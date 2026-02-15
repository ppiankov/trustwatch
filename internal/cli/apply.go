package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/clientcmd"
	sigsyaml "sigs.k8s.io/yaml"

	"github.com/ppiankov/trustwatch/internal/policy"
)

var crdGVR = schema.GroupVersionResource{
	Group:    "apiextensions.k8s.io",
	Version:  "v1",
	Resource: "customresourcedefinitions",
}

var applyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Install TrustPolicy CRD into the cluster",
	Long:  `Install or update the trustwatch.dev/v1alpha1 TrustPolicy CRD. Idempotent.`,
	RunE:  runApply,
}

func init() {
	rootCmd.AddCommand(applyCmd)
	applyCmd.Flags().String("kubeconfig", "", "Path to kubeconfig")
	applyCmd.Flags().String("context", "", "Kubernetes context to use")
}

func runApply(cmd *cobra.Command, _ []string) error {
	kubeconfig, _ := cmd.Flags().GetString("kubeconfig") //nolint:errcheck // flag registered above
	kubeCtx, _ := cmd.Flags().GetString("context")       //nolint:errcheck // flag registered above

	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		loadingRules.ExplicitPath = kubeconfig
	}
	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		loadingRules,
		&clientcmd.ConfigOverrides{CurrentContext: kubeCtx},
	)

	restCfg, err := clientConfig.ClientConfig()
	if err != nil {
		return fmt.Errorf("building kubeconfig: %w", err)
	}

	dynClient, err := dynamic.NewForConfig(restCfg)
	if err != nil {
		return fmt.Errorf("creating dynamic client: %w", err)
	}

	return applyCRD(cmd, dynClient)
}

func applyCRD(cmd *cobra.Command, dynClient dynamic.Interface) error {
	raw, err := policy.CRDManifest()
	if err != nil {
		return fmt.Errorf("reading CRD manifest: %w", err)
	}

	var obj unstructured.Unstructured
	if err := sigsyaml.Unmarshal(raw, &obj.Object); err != nil {
		return fmt.Errorf("decoding CRD manifest: %w", err)
	}

	ctx := context.Background()
	existing, getErr := dynClient.Resource(crdGVR).Get(ctx, obj.GetName(), metav1.GetOptions{})
	if errors.IsNotFound(getErr) {
		_, createErr := dynClient.Resource(crdGVR).Create(ctx, &obj, metav1.CreateOptions{})
		if createErr != nil {
			return fmt.Errorf("creating CRD: %w", createErr)
		}
		fmt.Fprintln(cmd.OutOrStdout(), "TrustPolicy CRD created") //nolint:errcheck // best-effort output
		return nil
	}
	if getErr != nil {
		return fmt.Errorf("checking CRD: %w", getErr)
	}

	// Preserve resourceVersion for optimistic concurrency
	obj.SetResourceVersion(existing.GetResourceVersion())
	_, updateErr := dynClient.Resource(crdGVR).Update(ctx, &obj, metav1.UpdateOptions{})
	if updateErr != nil {
		return fmt.Errorf("updating CRD: %w", updateErr)
	}
	fmt.Fprintln(cmd.OutOrStdout(), "TrustPolicy CRD updated") //nolint:errcheck // best-effort output
	return nil
}
