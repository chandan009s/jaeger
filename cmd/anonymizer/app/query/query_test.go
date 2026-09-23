// Copyright (c) 2024 The Jaeger Authors.
// SPDX-License-Identifier: Apache-2.0

package query

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jaegertracing/jaeger/internal/jptrace"
	"github.com/jaegertracing/jaeger/internal/proto/api_v3"
	"github.com/jaegertracing/jaeger/internal/storage/v1/api/spanstore"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

var (
	mockInvalidTraceID = "xyz"
	mockTraceID        = "0000000000000000000000000001e240"

	mockTraceGRPC = func() ptrace.Traces {
		traces := ptrace.NewTraces()

		rs := traces.ResourceSpans().AppendEmpty()
		rs.Resource().Attributes().PutStr("service.name", "test-service")

		span := rs.ScopeSpans().AppendEmpty().Spans().AppendEmpty()
		span.SetName("test-operation")

		return traces
	}()
)

var errUninitializedTraceID = status.Error(codes.InvalidArgument, "uninitialized TraceID is not allowed")

// testGRPCHandler is a minimal implementation of api_v2.QueryServiceServer
// for testing purposes. It only implements GetTrace, using the embedded
// UnimplementedQueryServiceServer for other methods.
type testGRPCHandler struct {
	api_v3.UnimplementedQueryServiceServer
	returnTrace    ptrace.Traces
	returnError    error
	failDuringRecv bool
}

// GetTrace implements the gRPC GetTrace method by returning test data directly.
func (g *testGRPCHandler) GetTrace(
	r *api_v3.GetTraceRequest,
	stream api_v3.QueryService_GetTraceServer,
) error {
	if r.TraceId == "" {
		return errUninitializedTraceID
	}

	if g.returnError != nil {
		if errors.Is(g.returnError, spanstore.ErrTraceNotFound) {
			return status.Errorf(codes.NotFound, "trace not found: %v", g.returnError)
		}
		return status.Errorf(codes.Internal, "failed to fetch trace: %v", g.returnError)
	}

	if g.returnTrace.ResourceSpans().Len() == 0 {
		return status.Errorf(codes.NotFound, "trace not found")
	}

	if g.failDuringRecv {
		if err := stream.Send((*jptrace.TracesData)(&g.returnTrace)); err != nil {
			return err
		}
		return status.Errorf(codes.Internal, "failed during recv")
	}

	return stream.Send((*jptrace.TracesData)(&g.returnTrace))
}

type mockQueryClient struct {
	api_v3.QueryServiceClient
	getTraceErr error
}

func (m *mockQueryClient) GetTrace(
	ctx context.Context,
	in *api_v3.GetTraceRequest,
	opts ...grpc.CallOption,
) (api_v3.QueryService_GetTraceClient, error) {
	if m.getTraceErr != nil {
		return nil, m.getTraceErr
	}
	return m.QueryServiceClient.GetTrace(ctx, in, opts...)
}

type testServer struct {
	address net.Addr
	server  *grpc.Server
	handler *testGRPCHandler
}

func newTestServer(t *testing.T) *testServer {
	h := &testGRPCHandler{}

	server := grpc.NewServer()
	api_v3.RegisterQueryServiceServer(server, h)

	lis, err := net.Listen("tcp", ":0")
	require.NoError(t, err)

	var started, exited sync.WaitGroup
	started.Add(1)
	exited.Go(func() {
		started.Done()
		assert.NoError(t, server.Serve(lis))
	})
	started.Wait()
	t.Cleanup(func() {
		server.Stop()
		exited.Wait() // don't allow test to finish before server exits
	})

	return &testServer{
		server:  server,
		address: lis.Addr(),
		handler: h,
	}
}

func TestNew(t *testing.T) {
	server := newTestServer(t)

	query, err := New(server.address.String())
	require.NoError(t, err)
	defer query.Close()

	assert.NotNil(t, query)

	t.Run("invalid address", func(t *testing.T) {
		// Try a definitively invalid URI to trigger parser error in NewClient.
		q, err := New("invalid-scheme://%%")
		if err != nil {
			assert.Nil(t, q)
		} else if q != nil {
			q.Close()
		}
	})
}

func TestClose(t *testing.T) {
	s := newTestServer(t)
	q, err := New(s.address.String())
	require.NoError(t, err)
	assert.NoError(t, q.Close())
}

func TestQueryTrace(t *testing.T) {
	s := newTestServer(t)
	q, err := New(s.address.String())
	require.NoError(t, err)
	defer q.Close()

	traceID, err := ParseTraceID(mockTraceID)
	require.NoError(t, err)

	t.Run("No error", func(t *testing.T) {
		startTime := time.Date(1970, time.January, 1, 0, 0, 0, 1000, time.UTC)
		endTime := time.Date(1970, time.January, 1, 0, 0, 0, 2000, time.UTC)
		s.handler.returnTrace = mockTraceGRPC
		s.handler.returnError = nil

		tracesIter, err := q.QueryTrace(traceID, startTime, endTime)
		require.NoError(t, err)

		var traces []ptrace.Traces
		tracesIter(func(batch []ptrace.Traces, err error) bool {
			require.NoError(t, err)
			traces = append(traces, batch...)
			return true
		})

		require.Len(t, traces, 1)
		assert.Equal(t, mockTraceGRPC.SpanCount(), traces[0].SpanCount())
	})

	t.Run("General error from GetTrace", func(t *testing.T) {
		s.handler.returnTrace = ptrace.NewTraces()
		s.handler.returnError = errors.New("random error")

		tracesIter, err := q.QueryTrace(traceID, time.Time{}, time.Time{})
		require.NoError(t, err)

		var iterErr error
		tracesIter(func(_ []ptrace.Traces, err error) bool {
			iterErr = err
			return false
		})

		require.ErrorContains(t, iterErr, "random error")
	})

	t.Run("Trace not found", func(t *testing.T) {
		s.handler.returnTrace = ptrace.NewTraces()
		s.handler.returnError = spanstore.ErrTraceNotFound

		tracesIter, err := q.QueryTrace(traceID, time.Time{}, time.Time{})
		require.NoError(t, err)

		var iterErr error
		tracesIter(func(_ []ptrace.Traces, err error) bool {
			iterErr = err
			return false
		})

		require.ErrorIs(t, iterErr, spanstore.ErrTraceNotFound)
	})

	t.Run("Error from GetTrace (immediate)", func(t *testing.T) {
		originalClient := q.client
		mockClient := &mockQueryClient{
			QueryServiceClient: q.client,
			getTraceErr:        errors.New("immediate error"),
		}
		q.client = mockClient
		defer func() { q.client = originalClient }()

		spans, err := q.QueryTrace(traceID, time.Time{}, time.Time{})
		assert.Nil(t, spans)
		assert.ErrorContains(t, err, "immediate error")
	})

	t.Run("Error from stream.Recv", func(t *testing.T) {
		s.handler.returnTrace = mockTraceGRPC
		s.handler.returnError = nil
		s.handler.failDuringRecv = true
		defer func() { s.handler.failDuringRecv = false }()

		tracesIter, err := q.QueryTrace(traceID, time.Time{}, time.Time{})
		require.NoError(t, err)

		var iterErr error
		tracesIter(func(_ []ptrace.Traces, err error) bool {
			if err != nil {
				iterErr = err
				return false
			}
			return true
		})

		require.ErrorContains(t, iterErr, "failed during recv")
	})
}

func TestParseTraceID(t *testing.T) {
	t.Run("valid trace ID", func(t *testing.T) {
		traceID, err := ParseTraceID(mockTraceID)
		require.NoError(t, err)
		assert.Equal(t, mockTraceID, traceID.String())
	})

	t.Run("short trace ID", func(t *testing.T) {
		traceID, err := ParseTraceID("1e240")
		require.NoError(t, err)
		assert.Equal(t, "0000000000000000000000000001e240", traceID.String())
	})

	t.Run("invalid trace ID", func(t *testing.T) {
		_, err := ParseTraceID(mockInvalidTraceID)
		assert.ErrorContains(t, err, "invalid trace ID")
	})
}

func TestUnwrapNotFoundErr(t *testing.T) {
	t.Run("non-gRPC error", func(t *testing.T) {
		err := errors.New("standard error")
		assert.Equal(t, err, unwrapNotFoundErr(err))
	})

	t.Run("gRPC error with trace not found", func(t *testing.T) {
		err := status.Error(codes.NotFound, "trace not found")
		assert.Equal(t, spanstore.ErrTraceNotFound, unwrapNotFoundErr(err))
	})

	t.Run("gRPC error without trace not found", func(t *testing.T) {
		err := status.Error(codes.Internal, "internal error")
		assert.Equal(t, err, unwrapNotFoundErr(err))
	})

	t.Run("nil error", func(t *testing.T) {
		assert.NoError(t, unwrapNotFoundErr(nil))
	})
}
