package telemetry

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel/trace/noop"
)

func TestInitTracer_NoopWhenEmpty(t *testing.T) {
	tracer, shutdown, err := InitTracer(context.Background(), "", "test", "v0.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer shutdown(context.Background()) //nolint:errcheck // test cleanup

	// Noop tracer should create noop spans
	_, span := tracer.Start(context.Background(), "test-span")
	if _, ok := span.(noop.Span); !ok {
		t.Error("expected noop span when endpoint is empty")
	}
	span.End()
}
