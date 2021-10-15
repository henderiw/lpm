package main

import (
	"sort"
	"strings"

	"github.com/pkg/errors"
	"inet.af/netaddr"
)

type IPPrefixes struct {
	prefixes []netaddr.IPPrefix
}

func NewIPPrefixes() *IPPrefixes {
	return &IPPrefixes{
		prefixes: make([]netaddr.IPPrefix, 0),
	}
}

func (p *IPPrefixes) GetPrefixes() []netaddr.IPPrefix {
	return p.prefixes
}

func (p *IPPrefixes) AddPrefixes(newpfxs []netaddr.IPPrefix) {
	for _, newpfx := range newpfxs {
		found := false
		for _, pfx := range p.prefixes {
			if pfx == newpfx {
				found = true
			}
		}
		if !found {
			p.prefixes = append(p.prefixes, newpfx)
		}
	}
}

func GetPrefixes(s string) (prefixes []netaddr.IPPrefix, err error) {
	if strings.Contains(s, "-") {
		// range
		if prefixes, err = getPrefixesForRange(s); err != nil {
			return nil, errors.Wrap(err, "cannot get prefixes from range")
		}
	} else {
		// prefix
		if p, err := netaddr.ParseIPPrefix(s); err != nil {
			return nil, errors.Wrap(err, "cannot parse prefix")
		} else {
			prefixes = append(prefixes, p)
		}
	}
	return prefixes, nil
}

func SortPrefixes(pfxs []netaddr.IPPrefix) []netaddr.IPPrefix {
	sort.SliceStable(pfxs, func(i, j int) bool {
		maski := pfxs[i].Bits()
		maskj := pfxs[j].Bits()
		return maski < maskj
	})

	return pfxs
}

func getPrefixesForRange(ra string) ([]netaddr.IPPrefix, error) {
	r, err := netaddr.ParseIPRange(ra)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing ip-range")
	}

	// expand range to individual prefixes
	var b netaddr.IPSetBuilder

	b.AddRange(r)
	s, err := b.IPSet()
	if err != nil {
		return nil, errors.Wrap(err, "error getting prefix set")
	}

	return s.Prefixes(), nil
}
