package cli

import (
	"context"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/ppiankov/trustwatch/internal/policy"
)

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "List active TrustPolicy resources",
	Long:  `List all TrustPolicy custom resources in the cluster.`,
	RunE:  runPolicy,
}

func init() {
	rootCmd.AddCommand(policyCmd)
	policyCmd.Flags().String("kubeconfig", "", "Path to kubeconfig")
	policyCmd.Flags().String("context", "", "Kubernetes context to use")
}

func runPolicy(cmd *cobra.Command, _ []string) error {
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

	clientset, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return fmt.Errorf("creating kubernetes client: %w", err)
	}

	dynClient, err := dynamic.NewForConfig(restCfg)
	if err != nil {
		return fmt.Errorf("creating dynamic client: %w", err)
	}

	return listPolicies(cmd.OutOrStdout(), clientset.Discovery(), dynClient)
}

func listPolicies(w io.Writer, disc discovery.DiscoveryInterface, dynClient dynamic.Interface) error {
	policies, err := policy.LoadPolicies(context.Background(), disc, dynClient)
	if err != nil {
		return fmt.Errorf("loading policies: %w", err)
	}
	if policies == nil {
		fmt.Fprintln(w, "TrustPolicy CRD not installed. Run 'trustwatch apply' first.") //nolint:errcheck // best-effort output
		return nil
	}
	if len(policies) == 0 {
		fmt.Fprintln(w, "No TrustPolicy resources found.") //nolint:errcheck // best-effort output
		return nil
	}

	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAMESPACE\tNAME\tTARGETS\tRULES") //nolint:errcheck // best-effort output
	for i := range policies {
		fmt.Fprintf(tw, "%s\t%s\t%d\t%d\n", policies[i].Namespace, policies[i].Name, len(policies[i].Spec.Targets), len(policies[i].Spec.Rules)) //nolint:errcheck // best-effort output
	}
	return tw.Flush()
}
