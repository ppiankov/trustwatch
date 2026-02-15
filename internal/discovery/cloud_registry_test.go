package discovery

import "testing"

func TestCloudDiscoverers_DefaultEmpty(t *testing.T) {
	discoverers := CloudDiscoverers()
	if len(discoverers) != 0 {
		t.Errorf("expected 0 cloud discoverers without build tags, got %d", len(discoverers))
	}
}
