package discovery

import "sync"

// cloudDiscovererFactory is a function that creates a cloud discoverer.
type cloudDiscovererFactory func() Discoverer

var (
	cloudMu        sync.Mutex
	cloudFactories []cloudDiscovererFactory
)

// RegisterCloudDiscoverer registers a factory for a cloud provider discoverer.
// Called from init() in build-tagged files.
func RegisterCloudDiscoverer(f cloudDiscovererFactory) {
	cloudMu.Lock()
	defer cloudMu.Unlock()
	cloudFactories = append(cloudFactories, f)
}

// CloudDiscoverers returns all registered cloud provider discoverers.
func CloudDiscoverers() []Discoverer {
	cloudMu.Lock()
	defer cloudMu.Unlock()
	discoverers := make([]Discoverer, 0, len(cloudFactories))
	for _, f := range cloudFactories {
		discoverers = append(discoverers, f())
	}
	return discoverers
}
