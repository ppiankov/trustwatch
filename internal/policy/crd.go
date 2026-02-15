package policy

import "embed"

//go:embed manifests/trustpolicy-crd.yaml
var crdFS embed.FS

// CRDManifest returns the raw YAML for the TrustPolicy CRD.
func CRDManifest() ([]byte, error) {
	return crdFS.ReadFile("manifests/trustpolicy-crd.yaml")
}
