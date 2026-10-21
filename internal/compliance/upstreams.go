package compliance

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/callerapi/falcon/internal/lists"
	"github.com/callerapi/falcon/internal/store"
)

// UpstreamIndex finds the upstream that owns a source address or a signer
// code. The longest matching prefix wins.
type UpstreamIndex struct {
	byLen map[int]map[netip.Prefix]store.Upstream
	bySPC map[string]store.Upstream
}

// NewUpstreamIndex indexes the addresses and signer codes of ups.
func NewUpstreamIndex(ups []store.Upstream) *UpstreamIndex {
	ix := &UpstreamIndex{byLen: map[int]map[netip.Prefix]store.Upstream{}, bySPC: map[string]store.Upstream{}}
	for _, u := range ups {
		for _, v := range u.IPs {
			p, err := netip.ParsePrefix(v)
			if err != nil {
				continue
			}
			if ix.byLen[p.Bits()] == nil {
				ix.byLen[p.Bits()] = map[netip.Prefix]store.Upstream{}
			}
			ix.byLen[p.Bits()][p] = u
		}
		for _, spc := range u.SPCs {
			ix.bySPC[strings.ToUpper(spc)] = u
		}
	}
	return ix
}

// Find returns the owner of ip, or of spc when no address matches.
func (ix *UpstreamIndex) Find(ip, spc string) (store.Upstream, bool) {
	if ix == nil {
		return store.Upstream{}, false
	}
	if addr, err := netip.ParseAddr(strings.TrimSpace(ip)); err == nil {
		addr = addr.Unmap()
		for bits := addr.BitLen(); bits >= 0; bits-- {
			rows := ix.byLen[bits]
			if len(rows) == 0 {
				continue
			}
			p, err := addr.Prefix(bits)
			if err != nil {
				continue
			}
			if u, ok := rows[p]; ok {
				return u, true
			}
		}
	}
	if u, ok := ix.bySPC[strings.ToUpper(strings.TrimSpace(spc))]; ok && spc != "" {
		return u, true
	}
	return store.Upstream{}, false
}

// NormalizeUpstream validates what an operator typed. Addresses become
// prefixes. RMD numbers, FRNs, and signer codes are put in one form.
func NormalizeUpstream(u store.Upstream) (store.Upstream, error) {
	u.Name = strings.TrimSpace(u.Name)
	if u.Name == "" || len(u.Name) > 200 {
		return u, errors.New("name is required, up to 200 characters")
	}
	if raw := strings.TrimSpace(u.RMD); raw != "" {
		if u.RMD = NormalizeRMD(raw); u.RMD == "" {
			return u, fmt.Errorf("RMD number %q is not RMD followed by up to seven digits", raw)
		}
	}
	if raw := strings.TrimSpace(u.FRN); raw != "" {
		if u.FRN = NormalizeFRN(raw); u.FRN == "" {
			return u, fmt.Errorf("FRN %q is not up to ten digits", raw)
		}
	}
	ips := make([]string, 0, len(u.IPs))
	seen := map[string]bool{}
	for _, v := range u.IPs {
		if v = strings.TrimSpace(v); v == "" {
			continue
		}
		r, err := lists.Normalize(lists.Rule{Kind: lists.Deny, Subject: lists.IP, Value: v})
		if err != nil {
			return u, fmt.Errorf("address %q: %v", v, err)
		}
		if !seen[r.Value] {
			seen[r.Value] = true
			ips = append(ips, r.Value)
		}
	}
	spcs := make([]string, 0, len(u.SPCs))
	for _, v := range u.SPCs {
		v = strings.ToUpper(strings.TrimSpace(v))
		if v == "" {
			continue
		}
		if len(v) > 10 || strings.Trim(v, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") != "" {
			return u, fmt.Errorf("signer code %q is not letters and digits", v)
		}
		if !seen["spc:"+v] {
			seen["spc:"+v] = true
			spcs = append(spcs, v)
		}
	}
	if len(ips) > 1000 || len(spcs) > 100 {
		return u, errors.New("at most 1000 addresses and 100 signer codes")
	}
	u.IPs, u.SPCs = ips, spcs
	u.Contact = strings.TrimSpace(u.Contact)
	u.Note = strings.TrimSpace(u.Note)
	if len(u.Contact) > 200 || len(u.Note) > 500 {
		return u, errors.New("contact is up to 200 characters and note up to 500")
	}
	return u, nil
}
