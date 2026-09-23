// Copyright (c) 2024 The Jaeger Authors.
// SPDX-License-Identifier: Apache-2.0

package writer

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

var testTraces = func() ptrace.Traces {
	traces := ptrace.NewTraces()

	resourceSpans := traces.ResourceSpans().AppendEmpty()
	resource := resourceSpans.Resource()
	resource.Attributes().PutStr("service.name", "serviceName")
	resource.Attributes().PutStr("process.foo", "processValue")

	scopeSpans := resourceSpans.ScopeSpans().AppendEmpty()
	span := scopeSpans.Spans().AppendEmpty()

	span.SetName("operationName")
	span.Attributes().PutBool("error", true)
	span.Attributes().PutStr("http.method", http.MethodPost)
	span.Attributes().PutBool("foobar", true)

	event := span.Events().AppendEmpty()
	event.SetName("test-event")
	event.Attributes().PutStr("logKey", "logValue")

	span.SetStartTimestamp(pcommon.Timestamp(time.Unix(300, 0).UnixNano()))
	span.SetEndTimestamp(pcommon.Timestamp(time.Unix(305, 0).UnixNano()))

	return traces
}()

func TestNew(t *testing.T) {
	nopLogger := zap.NewNop()
	tempDir := t.TempDir()

	t.Run("no error", func(t *testing.T) {
		config := Config{
			CapturedFile:   tempDir + "/captured.json",
			AnonymizedFile: tempDir + "/anonymized.json",
			MappingFile:    tempDir + "/mapping.json",
		}
		writer, err := New(config, nopLogger)
		require.NoError(t, err)
		defer writer.Close()
	})

	t.Run("CapturedFile does not exist", func(t *testing.T) {
		config := Config{
			CapturedFile:   tempDir + "/nonexistent_directory/captured.json",
			AnonymizedFile: tempDir + "/anonymized.json",
			MappingFile:    tempDir + "/mapping.json",
		}
		_, err := New(config, nopLogger)
		require.ErrorContains(t, err, "cannot create output file")
	})

	t.Run("AnonymizedFile does not exist", func(t *testing.T) {
		config := Config{
			CapturedFile:   tempDir + "/captured.json",
			AnonymizedFile: tempDir + "/nonexistent_directory/anonymized.json",
			MappingFile:    tempDir + "/mapping.json",
		}
		_, err := New(config, nopLogger)
		require.ErrorContains(t, err, "cannot create output file")
	})
}

// TestWriter_TruncatesExistingFile verifies that writer.New() truncates
// existing output files via O_TRUNC, preventing stale data.
func TestWriter_TruncatesExistingFile(t *testing.T) {
	tempDir := t.TempDir()
	capturedFile := filepath.Join(tempDir, "captured.json")
	anonymizedFile := filepath.Join(tempDir, "anonymized.json")
	mappingFile := filepath.Join(tempDir, "mapping.json")

	// Create files with old content that is clearly longer than what writer.New() will write
	oldContent := `{"old":"data","stale":true,"extra":"this_should_be_removed_completely"}`
	err := os.WriteFile(capturedFile, []byte(oldContent), 0o644)
	require.NoError(t, err)
	err = os.WriteFile(anonymizedFile, []byte(oldContent), 0o644)
	require.NoError(t, err)

	// Create writer with existing files - should truncate them
	config := Config{
		CapturedFile:   capturedFile,
		AnonymizedFile: anonymizedFile,
		MappingFile:    mappingFile,
	}
	writer, err := New(config, zap.NewNop())
	require.NoError(t, err)

	err = writer.WriteTraces(testTraces)
	require.NoError(t, err)

	writer.Close()

	// Verify old content is gone from captured file
	capturedData, err := os.ReadFile(capturedFile)
	require.NoError(t, err)
	require.NotContains(t, string(capturedData), "old")
	require.NotContains(t, string(capturedData), "stale")
	require.NotContains(t, string(capturedData), "extra") // proves no leftover tail
	// Ensure no partial/corrupted JSON remains
	var v any
	require.NoError(t, json.Unmarshal(capturedData, &v))

	// Verify old content is gone from anonymized file
	anonymizedData, err := os.ReadFile(anonymizedFile)
	require.NoError(t, err)
	require.NotContains(t, string(anonymizedData), "old")
	require.NotContains(t, string(anonymizedData), "stale")
	require.NotContains(t, string(anonymizedData), "extra") // proves no leftover tail
	// Ensure no partial/corrupted JSON remains
	require.NoError(t, json.Unmarshal(anonymizedData, &v))
}

func TestWriter_CloseIdempotent(t *testing.T) {
	tempDir := t.TempDir()
	capturedFile := filepath.Join(tempDir, "captured.json")
	anonymizedFile := filepath.Join(tempDir, "anonymized.json")
	mappingFile := filepath.Join(tempDir, "mapping.json")

	config := Config{
		CapturedFile:   capturedFile,
		AnonymizedFile: anonymizedFile,
		MappingFile:    mappingFile,
	}

	w, err := New(config, zap.NewNop())
	require.NoError(t, err)

	err = w.WriteTraces(testTraces)
	require.NoError(t, err)

	// Multiple calls to Close() should not error or corrupt files
	w.Close()
	w.Close()
	w.Close()

	capturedData, err := os.ReadFile(capturedFile)
	require.NoError(t, err)

	var captured map[string]any
	require.NoError(t, json.Unmarshal(capturedData, &captured))
	require.NotEmpty(t, captured)

	anonymizedData, err := os.ReadFile(anonymizedFile)
	require.NoError(t, err)

	var anonymized map[string]any
	require.NoError(t, json.Unmarshal(anonymizedData, &anonymized))
	require.NotEmpty(t, anonymized)
}

func TestWriter_WritesOTLPJSON(t *testing.T) {
	tempDir := t.TempDir()

	config := Config{
		CapturedFile:   filepath.Join(tempDir, "captured.json"),
		AnonymizedFile: filepath.Join(tempDir, "anonymized.json"),
		MappingFile:    filepath.Join(tempDir, "mapping.json"),
	}

	w, err := New(config, zap.NewNop())
	require.NoError(t, err)

	require.NoError(t, w.WriteTraces(testTraces))
	w.Close()

	capturedData, err := os.ReadFile(config.CapturedFile)
	require.NoError(t, err)

	captured, err := new(ptrace.JSONUnmarshaler).UnmarshalTraces(capturedData)
	require.NoError(t, err)
	require.Equal(t, 1, captured.SpanCount())

	anonymizedData, err := os.ReadFile(config.AnonymizedFile)
	require.NoError(t, err)

	anonymized, err := new(ptrace.JSONUnmarshaler).UnmarshalTraces(anonymizedData)
	require.NoError(t, err)
	require.Equal(t, 1, anonymized.SpanCount())
}
