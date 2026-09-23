// Copyright (c) 2020 The Jaeger Authors.
// SPDX-License-Identifier: Apache-2.0

package query

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"iter"
	"strings"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	_ "github.com/jaegertracing/jaeger/internal/gogocodec" // force gogo codec registration
	"github.com/jaegertracing/jaeger/internal/proto/api_v3"
	"github.com/jaegertracing/jaeger/internal/storage/v1/api/spanstore"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

// Query represents a jaeger-query's query for trace-id
type Query struct {
	client api_v3.QueryServiceClient
	conn   *grpc.ClientConn
}

// New creates a Query object
func New(addr string) (*Query, error) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to connect with the jaeger-query service: %w", err)
	}

	return &Query{
		client: api_v3.NewQueryServiceClient(conn),
		conn:   conn,
	}, nil
}

// unwrapNotFoundErr is a conversion function
func unwrapNotFoundErr(err error) error {
	if s, _ := status.FromError(err); s != nil {
		if strings.Contains(s.Message(), spanstore.ErrTraceNotFound.Error()) {
			return spanstore.ErrTraceNotFound
		}
	}
	return err
}

// QueryTrace queries for a trace and returns an iterator over OTLP trace batches.
func (q *Query) QueryTrace(
	traceID pcommon.TraceID,
	startTime time.Time,
	endTime time.Time,
) (iter.Seq2[[]ptrace.Traces, error], error) {
	request := api_v3.GetTraceRequest{
		TraceId:   traceID.String(),
		StartTime: startTime,
		EndTime:   endTime,
	}

	stream, err := q.client.GetTrace(context.Background(), &request)
	if err != nil {
		return nil, unwrapNotFoundErr(err)
	}

	return func(yield func([]ptrace.Traces, error) bool) {
		for {
			received, err := stream.Recv()
			if errors.Is(err, io.EOF) {
				return
			}
			if err != nil {
				yield(nil, unwrapNotFoundErr(err))
				return
			}
			if !yield([]ptrace.Traces{received.ToTraces()}, nil) {
				return
			}
		}
	}, nil
}

// Close closes the grpc client connection
func (q *Query) Close() error {
	return q.conn.Close()
}

func ParseTraceID(s string) (pcommon.TraceID, error) {
	if len(s) > 32 {
		return pcommon.TraceID{}, fmt.Errorf("TraceID cannot be longer than 32 hex characters: %s", s)
	}

	if s == "" {
		return pcommon.TraceID{}, fmt.Errorf("invalid trace ID %q", s)
	}

	// Jaeger accepts trace IDs shorter than 32 characters.
	// Pad them on the left to create the 16-byte OTLP TraceID.
	s = strings.Repeat("0", 32-len(s)) + s

	b, err := hex.DecodeString(s)
	if err != nil {
		return pcommon.TraceID{}, fmt.Errorf("invalid trace ID %q: %w", s, err)
	}

	return pcommon.TraceID(b), nil
}
