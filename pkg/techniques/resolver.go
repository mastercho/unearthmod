package techniques

import (
	"context"
	"net"
	"net/netip"
	"strings"
)

// resolver is the DNS surface every passive technique that does name
// resolution depends on. It is unexported on purpose: techniques never need
// to expose it to callers, and tests replace the package-level default with
// a map-backed fake via SetResolver.
type resolver interface {
	LookupAddrs(ctx context.Context, host string) ([]netip.Addr, error)
	LookupTXT(ctx context.Context, host string) ([]string, error)
	LookupMX(ctx context.Context, host string) ([]string, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
	LookupNS(ctx context.Context, host string) ([]string, error)
}

// defaultResolver is a thin wrapper over net.DefaultResolver returning
// netip.Addr values so callers can stop juggling net.IP.
type defaultResolver struct{}

func (defaultResolver) LookupAddrs(ctx context.Context, host string) ([]netip.Addr, error) {
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if a, ok := netip.AddrFromSlice(ip.IP); ok {
			// Unmap so IPv4-mapped IPv6 addresses canonicalize to v4.
			out = append(out, a.Unmap())
		}
	}
	return out, nil
}

func (defaultResolver) LookupTXT(ctx context.Context, host string) ([]string, error) {
	return net.DefaultResolver.LookupTXT(ctx, host)
}

func (defaultResolver) LookupMX(ctx context.Context, host string) ([]string, error) {
	mxs, err := net.DefaultResolver.LookupMX(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(mxs))
	for _, mx := range mxs {
		out = append(out, strings.TrimSuffix(mx.Host, "."))
	}
	return out, nil
}

func (defaultResolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	c, err := net.DefaultResolver.LookupCNAME(ctx, host)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(c, "."), nil
}

func (defaultResolver) LookupNS(ctx context.Context, host string) ([]string, error) {
	nss, err := net.DefaultResolver.LookupNS(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(nss))
	for _, ns := range nss {
		out = append(out, strings.TrimSuffix(ns.Host, "."))
	}
	return out, nil
}

// activeResolver is the resolver used by all techniques. Tests swap it with
// SetResolver/RestoreResolver to inject deterministic answers.
var activeResolver resolver = defaultResolver{}

// SetResolver overrides the package-level DNS resolver and returns the
// previous one so the caller can restore it. Tests use this; production code
// never calls it.
func SetResolver(r resolver) (previous resolver) {
	previous = activeResolver
	activeResolver = r
	return previous
}
