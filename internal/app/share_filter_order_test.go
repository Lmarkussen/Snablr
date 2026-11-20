package app

import (
	"reflect"
	"testing"

	"snablr/internal/config"
	"snablr/internal/smb"
)

type filteringClient struct {
	appFakeScanClient
	names       []string
	checked     []string
	listedPlain bool
	namedOnly   bool
}

func (c *filteringClient) ListShares() ([]smb.ShareInfo, error) {
	c.listedPlain = true
	out := make([]smb.ShareInfo, 0, len(c.names))
	for _, name := range c.names {
		c.checked = append(c.checked, name)
		out = append(out, smb.ShareInfo{Name: name})
	}
	return out, nil
}

func (c *filteringClient) ListSharesFiltered(opts smb.ShareListOptions) ([]smb.ShareInfo, []string, error) {
	var shares []smb.ShareInfo
	var rejected []string
	allow := opts.Allow
	names := c.names
	if len(opts.Names) > 0 {
		c.namedOnly = true
		names = opts.Names
	}
	for _, name := range names {
		if !allow(name) {
			rejected = append(rejected, name)
			continue
		}
		c.checked = append(c.checked, name)
		shares = append(shares, smb.ShareInfo{Name: name})
	}
	return shares, rejected, nil
}

// The share filters are applied before any share is connected to: an
// excluded ADMIN$ is never touched, and the rejected names are kept so the
// scan still reports them as skipped.
func TestShareFiltersApplyBeforeAccessCheck(t *testing.T) {
	names := []string{"ADMIN$", "C$", "Finance", "NETLOGON", "SYSVOL"}
	cases := []struct {
		name     string
		cfg      config.ScanConfig
		checked  []string
		rejected []string
	}{
		{"no filters", config.ScanConfig{}, names, nil},
		{"exclude admin shares", config.ScanConfig{ExcludeShare: []string{"admin$", "C$"}}, []string{"Finance", "NETLOGON", "SYSVOL"}, []string{"ADMIN$", "C$"}},
		{"one share", config.ScanConfig{Share: []string{"finance"}}, []string{"Finance"}, []string{"ADMIN$", "C$", "NETLOGON", "SYSVOL"}},
		{"only AD shares", config.ScanConfig{OnlyADShares: true}, []string{"NETLOGON", "SYSVOL"}, []string{"ADMIN$", "C$", "Finance"}},
	}
	for _, tc := range cases {
		client := &filteringClient{names: names}
		shares, rejected, err := listShareCandidates(client, tc.cfg)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if client.listedPlain {
			t.Errorf("%s: unfiltered listing used", tc.name)
		}
		if !reflect.DeepEqual(client.checked, tc.checked) {
			t.Errorf("%s: connected to %v, want %v", tc.name, client.checked, tc.checked)
		}
		if !reflect.DeepEqual(rejected, tc.rejected) {
			t.Errorf("%s: rejected %v, want %v", tc.name, rejected, tc.rejected)
		}
		if len(shares) != len(tc.checked) {
			t.Errorf("%s: %d shares returned", tc.name, len(shares))
		}
	}

	// A client without filtered listing keeps the previous behaviour.
	plain := &appFakeScanClient{}
	shares, rejected, err := listShareCandidates(plain, config.ScanConfig{ExcludeShare: []string{"share"}})
	if err != nil || len(shares) != 1 || rejected != nil {
		t.Errorf("fallback listing: %v %v %v", shares, rejected, err)
	}
}

// The real SMB client must take the filtered path.
var _ filteredShareLister = (*smb.Client)(nil)

// Stealth never connects to ADMIN$ or drive shares unless they are named,
// and with named shares it does not request the host's share list.
func TestStealthShareSelection(t *testing.T) {
	names := []string{"ADMIN$", "C$", "D$", "DeploymentShare$", "Finance", "SCCMContentLib$"}
	client := &filteringClient{names: names}
	_, rejected, err := listShareCandidates(client, config.ScanConfig{Stealth: true})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"DeploymentShare$", "Finance", "SCCMContentLib$"}; !reflect.DeepEqual(client.checked, want) {
		t.Errorf("connected to %v, want %v", client.checked, want)
	}
	if want := []string{"ADMIN$", "C$", "D$"}; !reflect.DeepEqual(rejected, want) {
		t.Errorf("rejected %v, want %v", rejected, want)
	}
	if client.namedOnly {
		t.Error("named-share path used without --share")
	}

	client = &filteringClient{names: names}
	_, _, err = listShareCandidates(client, config.ScanConfig{Stealth: true, Share: []string{"C$", "Finance"}})
	if err != nil {
		t.Fatal(err)
	}
	if !client.namedOnly {
		t.Error("stealth with named shares requested the host's share list")
	}
	if want := []string{"C$", "Finance"}; !reflect.DeepEqual(client.checked, want) {
		t.Errorf("connected to %v, want %v", client.checked, want)
	}

	// Without stealth, admin shares are tested as before.
	client = &filteringClient{names: names}
	if _, _, err := listShareCandidates(client, config.ScanConfig{}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(client.checked, names) || client.namedOnly {
		t.Errorf("default mode connected to %v (named=%v)", client.checked, client.namedOnly)
	}
	if opts := shareListOptions(config.ScanConfig{StealthMaxDeniedShares: 5}); opts.MaxConsecutiveDenied != 0 || opts.Names != nil {
		t.Errorf("stealth settings applied outside stealth: %+v", opts)
	}
}
