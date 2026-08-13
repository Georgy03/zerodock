package transport

import (
	"context"
	"fmt"
	"net"
	"regexp"
)

// VsockPortSupabaseDataRelay is deliberately separate from the fixed AWS and
// Supabase Management API ports. The parent relay only accepts a canonical
// project Data API hostname then connects to one DNS answer it validated.
const VsockPortSupabaseDataRelay = 8400

var supabaseProjectHost = regexp.MustCompile(`^([a-z0-9]{20})\.supabase\.co$`)

// SupabaseDataDialer is a one-scan capability: it may dial only project refs
// that were independently enumerated through the Management API. It is not a
// general suffix proxy, even inside the enclave.
type SupabaseDataDialer struct {
	vsock    *VsockDialer
	projects map[string]struct{}
}

func NewSupabaseDataDialer(vsock *VsockDialer, projectRefs []string) *SupabaseDataDialer {
	projects := make(map[string]struct{}, len(projectRefs))
	for _, ref := range projectRefs {
		projects[ref] = struct{}{}
	}
	return &SupabaseDataDialer{vsock: vsock, projects: projects}
}

// DialContext speaks the relay's tiny pre-TLS protocol: one canonical
// hostname line, then opaque TLS bytes. http.Transport still performs TLS
// itself, preserving SNI and certificate validation inside the enclave.
func (d *SupabaseDataDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port != "443" {
		return nil, fmt.Errorf("supabase data dial: only HTTPS port 443 is allowed")
	}
	match := supabaseProjectHost.FindStringSubmatch(host)
	if match == nil {
		return nil, fmt.Errorf("supabase data dial: invalid project hostname %q", host)
	}
	if _, ok := d.projects[match[1]]; !ok {
		return nil, fmt.Errorf("supabase data dial: project %q was not enumerated for this scan", match[1])
	}
	conn, err := d.vsock.dialPort(ctx, VsockPortSupabaseDataRelay)
	if err != nil {
		return nil, err
	}
	if _, err := fmt.Fprintf(conn, "%s\n", host); err != nil {
		conn.Close()
		return nil, fmt.Errorf("supabase data dial: send validated hostname: %w", err)
	}
	return conn, nil
}
