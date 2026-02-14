package discovery

import (
	"context"
	"fmt"
	"log/slog"

	authv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// ResolveNamespaces returns the explicit list if non-empty, otherwise lists all
// namespaces in the cluster.
func ResolveNamespaces(ctx context.Context, client kubernetes.Interface, explicit []string) ([]string, error) {
	if len(explicit) > 0 {
		return explicit, nil
	}
	nsList, err := client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing namespaces: %w", err)
	}
	names := make([]string, len(nsList.Items))
	for i := range nsList.Items {
		names[i] = nsList.Items[i].Name
	}
	return names, nil
}

// FilterAccessible returns the subset of namespaces where the current identity
// can list the given resource type. Uses SelfSubjectAccessReview.
// If the access check itself fails (e.g. RBAC for SSAR is missing), the
// namespace is included to avoid silently dropping accessible namespaces.
func FilterAccessible(ctx context.Context, client kubernetes.Interface, namespaces []string, group, resource string) []string {
	var accessible []string
	for _, ns := range namespaces {
		review := &authv1.SelfSubjectAccessReview{
			Spec: authv1.SelfSubjectAccessReviewSpec{
				ResourceAttributes: &authv1.ResourceAttributes{
					Namespace: ns,
					Verb:      "list",
					Group:     group,
					Resource:  resource,
				},
			},
		}
		result, err := client.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, review, metav1.CreateOptions{})
		if err != nil {
			slog.Warn("access check failed, assuming allowed", "namespace", ns,
				"group", group, "resource", resource, "err", err)
			accessible = append(accessible, ns)
			continue
		}
		if result.Status.Allowed {
			accessible = append(accessible, ns)
		} else {
			slog.Debug("access denied, skipping namespace", "namespace", ns,
				"group", group, "resource", resource)
		}
	}
	return accessible
}

// namespacesOrAll returns the given namespaces, or a single empty-string entry
// to list across all namespaces.
func namespacesOrAll(ns []string) []string {
	if len(ns) == 0 {
		return []string{""}
	}
	return ns
}
