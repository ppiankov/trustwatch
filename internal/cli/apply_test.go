package cli

import (
	"bytes"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

func newCRDDynamicClient(objs ...runtime.Object) *dynamicfake.FakeDynamicClient {
	scheme := runtime.NewScheme()
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme,
		map[schema.GroupVersionResource]string{
			crdGVR: "CustomResourceDefinitionList",
		},
		objs...,
	)
}

func TestApplyCRD_Create(t *testing.T) {
	dynClient := newCRDDynamicClient()

	cmd := applyCmd
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)

	if err := applyCRD(cmd, dynClient); err != nil {
		t.Fatalf("applyCRD failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "created") {
		t.Errorf("expected 'created' in output, got %q", out)
	}
}

func TestApplyCRD_Update(t *testing.T) {
	dynClient := newCRDDynamicClient()
	cmd := applyCmd
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)

	if err := applyCRD(cmd, dynClient); err != nil {
		t.Fatalf("first applyCRD failed: %v", err)
	}

	buf.Reset()
	if err := applyCRD(cmd, dynClient); err != nil {
		t.Fatalf("second applyCRD failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "updated") {
		t.Errorf("expected 'updated' in output, got %q", out)
	}
}
