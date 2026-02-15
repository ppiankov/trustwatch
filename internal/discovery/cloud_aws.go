//go:build aws

package discovery

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/acm"

	"github.com/ppiankov/trustwatch/internal/store"
)

func init() {
	RegisterCloudDiscoverer(func() Discoverer {
		return &AWSACMDiscoverer{}
	})
}

// AWSACMDiscoverer lists certificates from AWS Certificate Manager.
type AWSACMDiscoverer struct{}

// Name returns the discoverer label.
func (d *AWSACMDiscoverer) Name() string { return "cloud.aws.acm" }

// Discover lists ACM certificates and returns findings for each.
func (d *AWSACMDiscoverer) Discover() ([]store.CertFinding, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}

	client := acm.NewFromConfig(cfg)
	input := &acm.ListCertificatesInput{}
	var findings []store.CertFinding

	paginator := acm.NewListCertificatesPaginator(client, input)
	for paginator.HasMorePages() {
		page, pageErr := paginator.NextPage(ctx)
		if pageErr != nil {
			return nil, fmt.Errorf("listing ACM certificates: %w", pageErr)
		}
		for _, cs := range page.CertificateSummaryList {
			if cs.CertificateArn == nil {
				continue
			}
			desc, descErr := client.DescribeCertificate(ctx, &acm.DescribeCertificateInput{
				CertificateArn: cs.CertificateArn,
			})
			if descErr != nil {
				slog.Warn("describing ACM certificate", "arn", *cs.CertificateArn, "err", descErr)
				continue
			}
			cert := desc.Certificate
			f := store.CertFinding{
				Name:    *cs.CertificateArn,
				Source:  store.SourceAWSACM,
				ProbeOK: true,
			}
			if cert.NotAfter != nil {
				f.NotAfter = *cert.NotAfter
			}
			if cert.DomainName != nil {
				f.Target = *cert.DomainName
			}
			if cert.Issuer != nil {
				f.Issuer = *cert.Issuer
			}
			findings = append(findings, f)
		}
	}

	return findings, nil
}
