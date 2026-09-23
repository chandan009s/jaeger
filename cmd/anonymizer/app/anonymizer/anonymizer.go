// Copyright (c) 2020 The Jaeger Authors.
// SPDX-License-Identifier: Apache-2.0

package anonymizer

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"sync"
	"time"

	"go.uber.org/zap"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

var allowedTags = map[string]bool{
	"error":            true,
	"http.method":      true,
	"http.status_code": true,
	"span.kind":        true,
	"sampler.type":     true,
	"sampler.param":    true,
}

const PermUserRW = 0o600 // Read-write for owner only

// mapping stores the mapping of service/operation names to their one-way hashes,
// so that we can do a reverse lookup should the researchers have questions.
type mapping struct {
	Services   map[string]string
	Operations map[string]string // key=[service]:operation
}

// Anonymizer transforms Jaeger span in the domain model by obfuscating site-specific strings,
// like service and operation names, and removes custom tags. It returns obfuscated span in the
// Jaeger UI format, to make it easy to visualize traces.
//
// The mapping from original to obfuscated strings is stored in a file and can be reused between runs.
type Anonymizer struct {
	mappingFile string
	logger      *zap.Logger
	lock        sync.Mutex
	mapping     mapping
	options     Options
	cancel      context.CancelFunc
	wg          sync.WaitGroup
}

// Options represents the various options with which the anonymizer can be configured.
type Options struct {
	HashStandardTags bool `yaml:"hash_standard_tags" name:"hash_standard_tags"`
	HashCustomTags   bool `yaml:"hash_custom_tags" name:"hash_custom_tags"`
	HashLogs         bool `yaml:"hash_logs" name:"hash_logs"`
	HashProcess      bool `yaml:"hash_process" name:"hash_process"`
}

// New creates new Anonymizer. The mappingFile stores the mapping from original to
// obfuscated strings, in case later investigations require looking at the original traces.
func New(mappingFile string, options Options, logger *zap.Logger) *Anonymizer {
	ctx, cancel := context.WithCancel(context.Background())
	a := &Anonymizer{
		mappingFile: mappingFile,
		logger:      logger,
		mapping: mapping{
			Services:   make(map[string]string),
			Operations: make(map[string]string),
		},
		options: options,
		cancel:  cancel,
	}
	if _, err := os.Stat(filepath.Clean(mappingFile)); err == nil {
		dat, err := os.ReadFile(filepath.Clean(mappingFile))
		if err != nil {
			logger.Fatal("Cannot load previous mapping", zap.Error(err))
		}
		if err := json.Unmarshal(dat, &a.mapping); err != nil {
			logger.Fatal("Cannot unmarshal previous mapping", zap.Error(err))
		}
	}
	a.wg.Go(func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				a.SaveMapping()
			case <-ctx.Done():
				return
			}
		}
	})
	return a
}

func (a *Anonymizer) Stop() {
	a.cancel()
	a.wg.Wait()
}

// SaveMapping writes the mapping from original to obfuscated strings to a file.
// It is called by the anonymizer itself periodically, and should be called at
// the end of the extraction run.
func (a *Anonymizer) SaveMapping() {
	a.lock.Lock()
	defer a.lock.Unlock()
	dat, err := json.Marshal(a.mapping)
	if err != nil {
		a.logger.Error("Failed to marshal mapping file", zap.Error(err))
		return
	}
	if err := os.WriteFile(filepath.Clean(a.mappingFile), dat, PermUserRW); err != nil {
		a.logger.Error("Failed to write mapping file", zap.Error(err))
		return
	}
	a.logger.Sugar().Infof("Saved mapping file %s: %s", a.mappingFile, string(dat))
}

func (a *Anonymizer) mapServiceName(service string) string {
	return a.mapString(service, a.mapping.Services)
}

func (a *Anonymizer) mapOperationName(service, operation string) string {
	v := fmt.Sprintf("[%s]:%s", service, operation)
	return a.mapString(v, a.mapping.Operations)
}

func (a *Anonymizer) mapString(v string, m map[string]string) string {
	a.lock.Lock()
	defer a.lock.Unlock()
	if s, ok := m[v]; ok {
		return s
	}
	s := hash(v)
	m[v] = s
	return s
}

func hash(value string) string {
	h := fnv.New64()
	_, _ = h.Write([]byte(value))
	return fmt.Sprintf("%016x", h.Sum64())
}

func (a *Anonymizer) AnonymizeTraces(traces ptrace.Traces) {
	for i := 0; i < traces.ResourceSpans().Len(); i++ {
		resourceSpans := traces.ResourceSpans().At(i)
		resource := resourceSpans.Resource()

		service := ""
		if value, ok := resource.Attributes().Get("service.name"); ok {
			service = value.Str()
		}

		resource.Attributes().PutStr("service.name", a.mapServiceName(service))

		if a.options.HashProcess {
			var processAttrs []attribute

			resource.Attributes().Range(func(key string, value pcommon.Value) bool {
				if key != "service.name" {
					processAttrs = append(processAttrs, attribute{
						key:   key,
						value: value,
					})
				}
				return true
			})

			resource.Attributes().Clear()
			resource.Attributes().PutStr("service.name", a.mapServiceName(service))

			for _, attr := range processAttrs {
				resource.Attributes().PutStr(
					hash(attr.key),
					hash(attr.value.AsString()),
				)
			}
		} else {
			resource.Attributes().RemoveIf(func(key string, _ pcommon.Value) bool {
				return key != "service.name"
			})
		}

		scopeSpans := resourceSpans.ScopeSpans()
		for j := 0; j < scopeSpans.Len(); j++ {
			spans := scopeSpans.At(j).Spans()

			for k := 0; k < spans.Len(); k++ {
				span := spans.At(k)

				span.SetName(a.mapOperationName(service, span.Name()))
				span.Attributes().Remove("@jaeger@warnings")
				a.anonymizeAttributes(span.Attributes())
				if a.options.HashLogs {
					for i := 0; i < span.Events().Len(); i++ {
						hashAttributes(span.Events().At(i).Attributes())
					}
				} else {
					span.Events().RemoveIf(func(ptrace.SpanEvent) bool {
						return true
					})
				}
			}
		}
	}
}

func (a *Anonymizer) anonymizeAttributes(attributes pcommon.Map) {
	var standard []attribute
	var custom []attribute

	attributes.Range(func(key string, value pcommon.Value) bool {
		attr := attribute{
			key:   key,
			value: value,
		}

		if allowedTags[key] {
			if key == "error" {
				switch value.Type() {
				case pcommon.ValueTypeBool:
					// Keep boolean error values as-is.
				case pcommon.ValueTypeStr:
					if value.Str() != "true" && value.Str() != "false" {
						value = pcommon.NewValueBool(true)
					}
				default:
					value = pcommon.NewValueBool(true)
				}
			}

			standard = append(standard, attribute{
				key:   key,
				value: value,
			})
		} else {
			custom = append(custom, attr)
		}
		return true
	})

	attributes.Clear()

	if a.options.HashStandardTags {
		for _, attr := range standard {
			attributes.PutStr(hash(attr.key), hash(attr.value.AsString()))
		}
	} else {
		for _, attr := range standard {
			attr.value.CopyTo(attributes.PutEmpty(attr.key))
		}
	}

	if a.options.HashCustomTags {
		for _, attr := range custom {
			attributes.PutStr(hash(attr.key), hash(attr.value.AsString()))
		}
	}
}

func hashAttributes(attributes pcommon.Map) {
	var attrs []attribute

	attributes.Range(func(key string, value pcommon.Value) bool {
		attrs = append(attrs, attribute{
			key:   key,
			value: value,
		})
		return true
	})

	attributes.Clear()

	for _, attr := range attrs {
		attributes.PutStr(hash(attr.key), hash(attr.value.AsString()))
	}
}

type attribute struct {
	key   string
	value pcommon.Value
}
