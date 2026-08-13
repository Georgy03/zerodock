package providers

import "sort"

// ProjectScope is the provider-neutral denominator for a SaaS provider. A
// provider must enumerate an organization before it may claim project scope;
// accepting a project-only credential would let a vendor hide projects.
type ProjectScope struct {
	Provider        string
	OrganizationIDs []string
	Projects        []string
}

func (s *ProjectScope) Normalize() {
	sort.Strings(s.OrganizationIDs)
	sort.Strings(s.Projects)
}
