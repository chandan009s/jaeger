// Copyright (c) 2020 The Jaeger Authors.
// SPDX-License-Identifier: Apache-2.0

package writer

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"go.uber.org/zap"

	"github.com/jaegertracing/jaeger/cmd/anonymizer/app/anonymizer"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

// Config contains parameters to NewWriter.
type Config struct {
	CapturedFile   string             `yaml:"captured_file" name:"captured_file"`
	AnonymizedFile string             `yaml:"anonymized_file" name:"anonymized_file"`
	MappingFile    string             `yaml:"mapping_file" name:"mapping_file"`
	AnonymizerOpts anonymizer.Options `yaml:"anonymizer" name:"anonymizer"`
}

// Writer is a span Writer that obfuscates the span and writes it to a JSON file.
type Writer struct {
	config         Config
	lock           sync.Mutex
	logger         *zap.Logger
	capturedFile   *os.File
	anonymizedFile *os.File
	anonymizer     *anonymizer.Anonymizer
	spanCount      int
	closed         bool
}

// New creates an Writer
func New(config Config, logger *zap.Logger) (*Writer, error) {
	wd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	logger.Sugar().Infof("Current working dir is %s", wd)

	cf, err := os.OpenFile(config.CapturedFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.ModePerm)
	if err != nil {
		return nil, fmt.Errorf("cannot create output file: %w", err)
	}
	logger.Sugar().Infof("Writing captured spans to file %s", config.CapturedFile)

	af, err := os.OpenFile(config.AnonymizedFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.ModePerm)
	if err != nil {
		return nil, fmt.Errorf("cannot create output file: %w", err)
	}
	logger.Sugar().Infof("Writing anonymized spans to file %s", config.AnonymizedFile)

	options := anonymizer.Options{
		HashStandardTags: config.AnonymizerOpts.HashStandardTags,
		HashCustomTags:   config.AnonymizerOpts.HashCustomTags,
		HashLogs:         config.AnonymizerOpts.HashLogs,
		HashProcess:      config.AnonymizerOpts.HashProcess,
	}

	return &Writer{
		config:         config,
		logger:         logger,
		capturedFile:   cf,
		anonymizedFile: af,
		anonymizer:     anonymizer.New(config.MappingFile, options, logger),
	}, nil
}

// WriteTraces writes the original and anonymized traces as OTLP JSON.
func (w *Writer) WriteTraces(traces ptrace.Traces) error {
	w.lock.Lock()
	defer w.lock.Unlock()

	if w.closed {
		return errors.New("writer is closed")
	}

	marshaler := new(ptrace.JSONMarshaler)

	original, err := marshaler.MarshalTraces(traces)
	if err != nil {
		return err
	}

	if _, err := w.capturedFile.Write(original); err != nil {
		return err
	}

	anonymized := ptrace.NewTraces()
	traces.CopyTo(anonymized)
	w.anonymizer.AnonymizeTraces(anonymized)

	data, err := marshaler.MarshalTraces(anonymized)
	if err != nil {
		return err
	}

	if _, err := w.anonymizedFile.Write(data); err != nil {
		return err
	}

	if err := w.capturedFile.Sync(); err != nil {
		return err
	}
	if err := w.anonymizedFile.Sync(); err != nil {
		return err
	}

	w.spanCount += traces.SpanCount()

	if w.spanCount%100 == 0 {
		w.logger.Info("progress", zap.Int("numSpans", w.spanCount))
	}

	return nil
}

// Close closes the captured and anonymized files. It is safe to call multiple times.
func (w *Writer) Close() {
	w.lock.Lock()
	defer w.lock.Unlock()
	w.closeLocked()
}

func (w *Writer) closeLocked() {
	if w.closed {
		return
	}
	w.closed = true

	if w.capturedFile != nil {
		w.capturedFile.Close()
	}
	if w.anonymizedFile != nil {
		w.anonymizedFile.Close()
	}
	if w.anonymizer != nil {
		w.anonymizer.Stop()
		w.anonymizer.SaveMapping()
	}
}
