//go:build azure

package discovery

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"

	"github.com/ppiankov/trustwatch/internal/store"
)

func init() {
	RegisterCloudDiscoverer(func() Discoverer {
		return &AzureKeyVaultDiscoverer{}
	})
}

// AzureKeyVaultDiscoverer lists certificates from Azure Key Vault.
type AzureKeyVaultDiscoverer struct {
	vaultURL string
}

// Name returns the discoverer label.
func (d *AzureKeyVaultDiscoverer) Name() string { return "cloud.azure.keyvault" }

// Discover lists Azure Key Vault certificates and returns findings for each.
func (d *AzureKeyVaultDiscoverer) Discover() ([]store.CertFinding, error) {
	if d.vaultURL == "" {
		return nil, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("creating Azure credential: %w", err)
	}

	client, err := azcertificates.NewClient(d.vaultURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("creating Azure Key Vault client: %w", err)
	}

	pager := client.NewListCertificatesPager(nil)
	var findings []store.CertFinding
	for pager.More() {
		page, pageErr := pager.NextPage(ctx)
		if pageErr != nil {
			return nil, fmt.Errorf("listing Azure Key Vault certificates: %w", pageErr)
		}
		for _, item := range page.Value {
			f := store.CertFinding{
				Source:  store.SourceAzureKeyVault,
				ProbeOK: true,
			}
			if item.ID != nil {
				f.Name = string(*item.ID)
			}
			if item.Attributes != nil && item.Attributes.Expires != nil {
				f.NotAfter = *item.Attributes.Expires
			}
			findings = append(findings, f)
		}
	}

	return findings, nil
}
