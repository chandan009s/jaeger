// Copyright (c) 2026 The Jaeger Authors.
// SPDX-License-Identifier: Apache-2.0

package anonymizer

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

func TestAnonymizer_AnonymizeTraces_AllFalse(t *testing.T) {
	traces := ptrace.NewTraces()

	rs := traces.ResourceSpans().AppendEmpty()
	rs.Resource().Attributes().PutStr("service.name", "serviceName")
	rs.Resource().Attributes().PutStr("process.foo", "processValue")

	span := rs.ScopeSpans().AppendEmpty().Spans().AppendEmpty()
	span.SetName("operationName")
	span.Attributes().PutBool("error", true)
	span.Attributes().PutStr("http.method", "POST")
	span.Attributes().PutStr("foobar", "customValue")

	event := span.Events().AppendEmpty()
	event.Attributes().PutStr("logKey", "logValue")

	anonymizer := &Anonymizer{
		mapping: mapping{
			Services:   make(map[string]string),
			Operations: make(map[string]string),
		},
		options: Options{},
	}

	anonymizer.AnonymizeTraces(traces)

	// Service and operation are always anonymized.
	assert.NotEqual(t, "serviceName", rs.Resource().Attributes().AsRaw()["service.name"])
	assert.NotEqual(t, "operationName", span.Name())

	errorValue, ok := span.Attributes().Get("error")
	assert.True(t, ok)
	assert.True(t, errorValue.Bool())

	httpMethod, ok := span.Attributes().Get("http.method")
	assert.True(t, ok)
	assert.Equal(t, "POST", httpMethod.Str())

	_, ok = span.Attributes().Get("foobar")
	assert.False(t, ok)

	_, ok = rs.Resource().Attributes().Get("process.foo")
	assert.False(t, ok)

	assert.Equal(t, 0, span.Events().Len())

	assert.Equal(t, 1, traces.SpanCount())
}

func TestAnonymizer_AnonymizeTraces_AllTrue(t *testing.T) {
	traces := ptrace.NewTraces()

	rs := traces.ResourceSpans().AppendEmpty()
	rs.Resource().Attributes().PutStr("service.name", "serviceName")
	rs.Resource().Attributes().PutStr("process.foo", "processValue")

	span := rs.ScopeSpans().AppendEmpty().Spans().AppendEmpty()
	span.SetName("operationName")
	span.Attributes().PutBool("error", true)
	span.Attributes().PutStr("http.method", "POST")
	span.Attributes().PutStr("foobar", "customValue")

	event := span.Events().AppendEmpty()
	event.Attributes().PutStr("logKey", "logValue")

	anonymizer := &Anonymizer{
		mapping: mapping{
			Services:   make(map[string]string),
			Operations: make(map[string]string),
		},
		options: Options{
			HashStandardTags: true,
			HashCustomTags:   true,
			HashLogs:         true,
			HashProcess:      true,
		},
	}

	anonymizer.AnonymizeTraces(traces)

	// Service and operation are always anonymized.
	assert.NotEqual(t, "serviceName", rs.Resource().Attributes().AsRaw()["service.name"])
	assert.NotEqual(t, "operationName", span.Name())

	// Standard attribute is hashed.
	hashedMethod, ok := span.Attributes().Get(hash("http.method"))
	assert.True(t, ok)
	assert.Equal(t, hash("POST"), hashedMethod.Str())

	// Custom attribute is hashed.
	hashedCustom, ok := span.Attributes().Get(hash("foobar"))
	assert.True(t, ok)
	assert.Equal(t, hash("customValue"), hashedCustom.Str())

	// Error attribute is normalized and hashed.
	hashedError, ok := span.Attributes().Get(hash("error"))
	assert.True(t, ok)
	assert.Equal(t, hash("true"), hashedError.Str())

	assert.Equal(t, 3, span.Attributes().Len())

	hashedProcess, ok := rs.Resource().Attributes().Get(hash("process.foo"))
	assert.True(t, ok)
	assert.Equal(t, hash("processValue"), hashedProcess.Str())
	assert.Greater(t, rs.Resource().Attributes().Len(), 1)

	assert.Equal(t, 1, span.Events().Len())

	hashedLog, ok := span.Events().At(0).Attributes().Get(hash("logKey"))
	assert.True(t, ok)
	assert.Equal(t, hash("logValue"), hashedLog.Str())

	assert.Equal(t, 1, traces.SpanCount())
}

func TestAnonymizer_AnonymizeTraces_ErrorNormalization(t *testing.T) {
	traces := ptrace.NewTraces()

	rs := traces.ResourceSpans().AppendEmpty()
	rs.Resource().Attributes().PutStr("service.name", "serviceName")

	span := rs.ScopeSpans().AppendEmpty().Spans().AppendEmpty()

	span.Attributes().PutStr("error", "something-else")

	anonymizer := &Anonymizer{
		mapping: mapping{
			Services:   make(map[string]string),
			Operations: make(map[string]string),
		},
		options: Options{},
	}

	anonymizer.AnonymizeTraces(traces)

	value, ok := span.Attributes().Get("error")
	assert.True(t, ok)
	assert.True(t, value.Bool())
}

func TestAnonymizer_AnonymizeTraces_ErrorStringValues(t *testing.T) {
	traces := ptrace.NewTraces()

	rs := traces.ResourceSpans().AppendEmpty()
	rs.Resource().Attributes().PutStr("service.name", "serviceName")

	span := rs.ScopeSpans().AppendEmpty().Spans().AppendEmpty()
	span.Attributes().PutStr("error", "true")

	anonymizer := &Anonymizer{
		mapping: mapping{
			Services:   make(map[string]string),
			Operations: make(map[string]string),
		},
		options: Options{},
	}

	anonymizer.AnonymizeTraces(traces)

	value, ok := span.Attributes().Get("error")
	assert.True(t, ok)
	assert.Equal(t, pcommon.ValueTypeStr, value.Type())
	assert.Equal(t, "true", value.Str())
}

func TestAnonymizer_AnonymizeTraces_HashLogsIndependently(t *testing.T) {
	traces := ptrace.NewTraces()

	rs := traces.ResourceSpans().AppendEmpty()
	rs.Resource().Attributes().PutStr("service.name", "serviceName")

	span := rs.ScopeSpans().AppendEmpty().Spans().AppendEmpty()
	span.SetName("operationName")

	event := span.Events().AppendEmpty()
	event.Attributes().PutStr("http.method", "POST")
	event.Attributes().PutStr("logKey", "logValue")

	anonymizer := &Anonymizer{
		mapping: mapping{
			Services:   make(map[string]string),
			Operations: make(map[string]string),
		},
		options: Options{
			HashLogs: true,
		},
	}

	anonymizer.AnonymizeTraces(traces)

	assert.Equal(t, 1, span.Events().Len())

	// Log attributes are hashed even when HashStandardTags and
	// HashCustomTags are disabled.
	hashedMethod, ok := span.Events().At(0).Attributes().Get(hash("http.method"))
	assert.True(t, ok)
	assert.Equal(t, hash("POST"), hashedMethod.Str())

	hashedLog, ok := span.Events().At(0).Attributes().Get(hash("logKey"))
	assert.True(t, ok)
	assert.Equal(t, hash("logValue"), hashedLog.Str())
}

func TestAnonymizer_AnonymizeTraces_RemovesWarnings(t *testing.T) {
	traces := ptrace.NewTraces()

	rs := traces.ResourceSpans().AppendEmpty()
	rs.Resource().Attributes().PutStr("service.name", "serviceName")

	span := rs.ScopeSpans().AppendEmpty().Spans().AppendEmpty()
	span.SetName("operationName")
	span.Attributes().PutStr("@jaeger@warnings", "trace was truncated")

	anonymizer := &Anonymizer{
		mapping: mapping{
			Services:   make(map[string]string),
			Operations: make(map[string]string),
		},
		options: Options{
			HashCustomTags: true,
		},
	}

	anonymizer.AnonymizeTraces(traces)

	_, ok := span.Attributes().Get("@jaeger@warnings")
	assert.False(t, ok)
}
