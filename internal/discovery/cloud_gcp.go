//go:build gcp

package discovery

import (
	"context"
	"fmt"
	"time"

	certificatemanager "cloud.google.com/go/certificatemanager/apiv1"
	"cloud.google.com/go/certificatemanager/apiv1/certificatemanagerpb"
	"google.golang.org/api/iterator"

	"github.com/ppiankov/trustwatch/internal/store"
)

func init() {
	RegisterCloudDiscoverer(func() Discoverer {
		return &GCPCertDiscoverer{}
	})
}

// GCPCertDiscoverer lists certificates from GCP Certificate Manager.
type GCPCertDiscoverer struct {
	project string
}

// Name returns the discoverer label.
func (d *GCPCertDiscoverer) Name() string { return "cloud.gcp.cert" }

// Discover lists GCP managed certificates and returns findings for each.
func (d *GCPCertDiscoverer) Discover() ([]store.CertFinding, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client, err := certificatemanager.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("creating GCP certificate manager client: %w", err)
	}
	defer client.Close() //nolint:errcheck // best-effort cleanup

	parent := fmt.Sprintf("projects/%s/locations/-", d.project)
	it := client.ListCertificates(ctx, &certificatemanagerpb.ListCertificatesRequest{
		Parent: parent,
	})

	var findings []store.CertFinding
	for {
		cert, iterErr := it.Next()
		if iterErr == iterator.Done {
			break
		}
		if iterErr != nil {
			return nil, fmt.Errorf("listing GCP certificates: %w", iterErr)
		}
		f := store.CertFinding{
			Name:    cert.Name,
			Source:  store.SourceGCPManagedCert,
			ProbeOK: true,
		}
		if cert.ExpireTime != nil {
			f.NotAfter = cert.ExpireTime.AsTime()
		}
		findings = append(findings, f)
	}

	return findings, nil
}
