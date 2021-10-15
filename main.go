package main

import (
	"fmt"
	"math"
	"net"
	"strings"

	"github.com/k-sone/critbitgo"
	"github.com/pkg/errors"
	"inet.af/netaddr"
)

func callback(r *net.IPNet, v interface{}) bool {
	if c, ok := v.(Data); ok {
		fmt.Println("  Prefix", r, "Value", c.GetValue(), "ipPrefix", c.GetMeta().HasIpPrefix(), "ipRange", c.GetMeta().HasIpRange())
	} else {
		fmt.Println("  Prefix", r, "Value", v)
	}
	return true
}

type IpTree struct {
	t *critbitgo.Net
}

func New() *IpTree {
	return &IpTree{
		t: critbitgo.NewNet(),
	}
}

func (ipam *IpTree) GetTree() *critbitgo.Net {
	return ipam.t
}

func (ipam *IpTree) validateOverlap(s string) (bool, *net.IPNet, *Data, error) {
	var start, end netaddr.IP
	if strings.Contains(s, "-") {
		// range
		ra, err := netaddr.ParseIPRange(s)
		if err != nil {
			return false, nil, nil, errors.New("validation failed")
		}
		start, end, _, err = netValidateIpRange(&ra)
		if err != nil {
			return false, nil, nil, errors.New("validation failed")
		}
	} else {
		// prefix
		p, err := netaddr.ParseIPPrefix(s)
		if err != nil {
			return false, nil, nil, errors.New("validation failed")
		}
		start, end, _, err = netValidateIpNet(&p)
		if err != nil {
			return false, nil, nil, errors.New("validation failed")
		}
	}
	t := ipam.GetTree()
	keyStart, v, err := t.MatchIP(start.IPAddr().IP)
	if err != nil {
		return false, nil, nil, err
	}
	if c, ok := v.(Data); ok {
		fmt.Println("  ", start.IPAddr().IP, "Start", keyStart, "Value", c.GetValue(), "ipPrefix", c.GetMeta().HasIpPrefix(), "ipRange", c.GetMeta().HasIpRange())
	} else {
		fmt.Println("  ", start.IPAddr().IP, "Start", keyStart, "Value", v)
	}

	keyEnd, v, err := t.MatchIP(end.IPAddr().IP)
	if err != nil {
		return false, nil, nil, err
	}
	if c, ok := v.(Data); ok {
		fmt.Println("  ", end.IPAddr().IP, "End", keyEnd, "Value", c.GetValue(), "ipPrefix", c.GetMeta().HasIpPrefix(), "ipRange", c.GetMeta().HasIpRange())
	} else {
		fmt.Println("  ", end.IPAddr().IP, "End", keyEnd, "Value", v)
	}

	if keyStart == nil || keyEnd == nil {
		// not found
		fmt.Println("Overlap check passed, no result found")
		return false, nil, nil, nil
	}
	if keyStart.String() == keyEnd.String() {
		fmt.Println("Overlap check passed, key match")
		if c, ok := v.(Data); ok {
			return false, keyStart, &c, nil
		}

	}
	fmt.Println("Overlap check failed, key mismatch")
	return true, nil, nil, nil
}

// PreCheckAddition validates if the addition of a prefix/range results in
// a valid tree or not
func (ipam *IpTree) PreCheckAddition(s string) (bool, error) {
	fmt.Println("Pre Check adding prefix or range ...")
	// clear the ipam
	t := ipam.GetTree()
	t.Clear()

	prefixes, err := GetPrefixes(s)
	if err != nil {
		return false, err
	}

	pfxs := NewIPPrefixes()
	for _, p := range prefixes {
		// get the parent
		parent := ipam.Parent(p)
		pfxs.AddPrefixes(parent)
		if len(parent) > 0 {
			// get the children based on the parent of the new prefix
			pfxs.AddPrefixes(ipam.Children(parent[0]))
		}
		// add the new prefix to the list
		pfxs.AddPrefixes([]netaddr.IPPrefix{p})
	}

	fmt.Println(pfxs.GetPrefixes())

	return ipam.PreCheck(pfxs.GetPrefixes())
}

// PreCheckDeletion validates if the deletion of a prefix/range results in
// a valid tree or not
func (ipam *IpTree) PreCheckDeletion(s string) (bool, error) {
	fmt.Println("Pre Check delting prefix or range ...")
	// clear the ipam
	t := ipam.GetTree()
	t.Clear()

	prefixes, err := GetPrefixes(s)
	if err != nil {
		return false, err
	}

	pfxs := NewIPPrefixes()
	for _, p := range prefixes {
		pfxs.AddPrefixes(ipam.Parents(p))
		pfxs.AddPrefixes(ipam.Children(p))
	}

	return ipam.PreCheck(pfxs.GetPrefixes())
}

// Precheck validates if the insertion in the tree
func (ipam *IpTree) PreCheck(p []netaddr.IPPrefix) (bool, error) {
	fmt.Println("Check....")
	// sort the data such that we validate in order
	sortedPrefixes := SortPrefixes(p)
	// validate the result
	for _, p := range sortedPrefixes {
		fmt.Println("######### ", p, " ##########")

		success, err := ipam.PreCheckAddPrefix(p.String(), "dummy")
		if err != nil {
			return false, err
		}
		if !success {
			return false, nil
		}
	}
	return true, nil
}

// PreCheckAddPrefix adds a prefix to the dummy tree, to validate if the insertion would be successfull
func (ipam *IpTree) PreCheckAddPrefix(p string, value interface{}) (bool, error) {
	fmt.Println("PreCheckAddPrefix...")
	t := ipam.GetTree()
	overlap, _, d, err := ipam.validateOverlap(p)
	if err != nil {
		return false, errors.Wrap(err, "error validating overlap")
	}
	if overlap {
		// not successfull
		fmt.Println("PreCheckAddPrefix -> Overlap detetcted")
		return false, nil
	} else {
		fmt.Println("No Overlap")
		// successfull
		if d == nil || !d.GetMeta().HasIpRange() {
			// only add when the parent prefix is not a range
			v := Data{
				meta: &Metadata{
					ipPrefix: true,
				},
				value: map[string]interface{}{p: value},
			}
			if err := t.AddCIDR(p, v); err != nil {
				fmt.Println("error adding prefix")
				return false, nil
			}
			// success
			return true, nil
		} else {
			// inserting data in a object that has a range is not allowed
			return false, nil
		}
	}
}

// AddPrefix adds a prefix to the tree in a very open minded way
// overlap is not validated as this method, the method assumes validation
// was performed before calling it
func (ipam *IpTree) AddPrefix(p string, value interface{}) error {
	fmt.Println("AddPrefix...")
	// use the ipamtree
	t := ipam.GetTree()
	// execute this function to get the data since overlap validation occured already
	_, key, d, err := ipam.validateOverlap(p)
	if err != nil {
		return errors.Wrap(err, "error validating overlap")
	}
	if d != nil && key.String() == p {
		d.GetMeta().SetIpPrefix()
		d.AddValue(p, value)
		if err := t.AddCIDR(p, *d); err != nil {
			return errors.Wrap(err, "error adding prefix")
		}
	} else {
		v := Data{
			meta: &Metadata{
				ipPrefix: true,
			},
			value: map[string]interface{}{p: value},
		}
		if err := t.AddCIDR(p, v); err != nil {
			return errors.Wrap(err, "error adding prefix")
		}
	}
	return nil
}

// DeletePrefix deletes a prefix to the tree in a very open minded way
// overlap is not validated as this method, the method assumes validation
// was performed before calling it
func (ipam *IpTree) DeletePrefix(p string) error {
	// use the ipamtree
	t := ipam.GetTree()
	// execute this function to get the data since overlap validation occured already
	_, key, d, err := ipam.validateOverlap(p)
	if err != nil {
		return errors.Wrap(err, "error validating overlap")
	}

	if key != nil {
		d.DeleteValue(p)
		if d.GetMeta().HasIpRange() {
			d.GetMeta().ResetIpPrefix()
			// update the data in the tree
			if err := t.AddCIDR(p, *d); err != nil {
				return err
			}
		} else {
			if _, _, err := t.DeleteCIDR(p); err != nil {
				return err
			}
		}

	}
	return nil
}

func (ipam *IpTree) UpdatePrefix(p string) error {
	return nil
}

func (ipam *IpTree) GetPrefix(p string) error {
	return nil
}

// PreCheckAddRange adds a range to the dummy tree, to validate if the insertion would be successfull
func (ipam *IpTree) PreCheckAddRange(ra string, value interface{}) (bool, error) {
	t := ipam.GetTree()
	overlap, _, d, err := ipam.validateOverlap(ra)
	if err != nil {
		return false, errors.Wrap(err, "error validating overlap")
	}
	if overlap {
		// not successfull
		fmt.Println("ValidateAddRange -> Overlap detetcted")
		return false, nil
	}
	if d != nil && !d.GetMeta().HasIpRange() {
		// the higher level range does not overlap
		// a range should have a parent prefix

		prefixes, err := getPrefixesForRange(ra)
		if err != nil {
			return false, errors.Wrap(err, "cannot get prefixes from range")
		}

		// no overlap or errors, so we can insert the data to the tree
		for _, p := range prefixes {
			_, key, d, err := ipam.validateOverlap(p.String())
			if err != nil {
				fmt.Println("error validating overlap")
				break
			}
			if key != nil && key.String() == p.String() {
				// the range aggregate prefix matches with a parent prefix,
				// -> augment the data
				d.GetMeta().SetIpRange()
				d.AddValue(ra, value)
				if err := t.AddCIDR(p.String(), *d); err != nil {
					return false, errors.Wrap(err, "error adding prefix")
				}
			} else {
				// the range aggregate prefix does NOT match with a parent prefix
				// -> initialize as a new prefix with the range info
				v := Data{
					meta: &Metadata{
						ipRange: true,
					},
					value: map[string]interface{}{ra: value},
				}
				if err := t.AddCIDR(p.String(), v); err != nil {
					return false, errors.Wrap(err, "error adding prefix")
				}
			}
		}
		return true, nil
	}

	return false, nil
}

// AddRange adds a range to the tree in a very open minded way
// overlap is not validated as this method, the method assumes validation
// was performed before calling it
func (ipam *IpTree) AddRange(ra string, value interface{}) error {
	t := ipam.GetTree()
	_, _, d, err := ipam.validateOverlap(ra)
	if err != nil {
		fmt.Println("error validating overlap")
		panic(err)
	}
	if d != nil && !d.GetMeta().HasIpRange() {
		// the higher level range does not overlap
		// a range should have a parent prefix

		prefixes, err := getPrefixesForRange(ra)
		if err != nil {
			return errors.Wrap(err, "cannot get prefixes from range")
		}

		// no overlap or errors, so we can insert the data to the tree
		transaction := true
		var e error
		for _, p := range prefixes {
			_, key, d, err := ipam.validateOverlap(p.String())
			if err != nil {
				e = errors.Wrap(err, "error validating overlap")
				transaction = false
				break
			}
			if key != nil && key.String() == p.String() {
				// the range aggregate prefix matches with a parent prefix,
				// -> augment the data
				d.GetMeta().SetIpRange()
				d.AddValue(ra, value)
				if err := t.AddCIDR(p.String(), *d); err != nil {
					e = errors.Wrap(err, "error adding prefix")
					transaction = false
					break
				}
			} else {
				// the range aggregate prefix does NOT match with a parent prefix
				// -> initialize as a new prefix with the range info
				v := Data{
					meta: &Metadata{
						ipRange: true,
					},
					value: map[string]interface{}{ra: value},
				}
				if err := t.AddCIDR(p.String(), v); err != nil {
					e = errors.Wrap(err, "error adding prefix")
					transaction = false
					break
				}
			}
		}
		if !transaction {
			fmt.Println("Transation failed")
			return e
			// todo delete insertions
		}
	}
	return nil
}

// DeleteRange deletes a range from the tree in a very open minded way
// overlap is not validated as this method, the method assumes validation
// was performed before calling it
func (ipam *IpTree) DeleteRange(ra string) error {
	t := ipam.GetTree()

	prefixes, err := getPrefixesForRange(ra)
	if err != nil {
		return errors.Wrap(err, "cannot get prefixes from range")
	}

	// no overlap or errors, so we can insert the data to the tree
	transaction := true
	var e error
	for _, p := range prefixes {
		_, key, d, err := ipam.validateOverlap(p.String())
		if err != nil {
			e = errors.Wrap(err, "error validating overlap")
			transaction = false
			break
		}
		if key != nil {
			d.DeleteValue(ra)
			if d.GetMeta().HasIpAddress() || d.GetMeta().HasIpPrefix() {
				// the element is used for other information
				fmt.Println("delete range with other data")
				// check if other ranges still get mapped
				if !findOtherRanges(d.GetValue()) {
					d.GetMeta().ResetIpRange()
				}
				// update the data in the tree
				if err := t.AddCIDR(p.String(), *d); err != nil {
					e = errors.Wrap(err, "error updating prefix")
					transaction = false
					break
				}
			} else {
				fmt.Println("delete range no other rusage")
				// check if other ranges still get mapped
				if !findOtherRanges(d.GetValue()) {
					d.GetMeta().ResetIpRange()
					_, _, err := t.DeleteCIDR(p.String())
					if err != nil {
						e = errors.Wrap(err, "error deleting prefix")
						transaction = false
						break
					}
				} else {
					// update the data in the tree
					if err := t.AddCIDR(p.String(), *d); err != nil {
						e = errors.Wrap(err, "error updating prefix")
						transaction = false
						break
					}
				}

			}
		}
	}
	if !transaction {
		fmt.Println("Transation failed")
		return e
		// todo delete insertions
	}
	return nil
}

func (ipam *IpTree) Parent(r netaddr.IPPrefix) []netaddr.IPPrefix {
	t := ipam.GetTree()
	var result []netaddr.IPPrefix
	f := func(n *net.IPNet, _ interface{}) bool {
		pfx, _ := netaddr.FromStdIPNet(n)
		if pfx != r {
			result = append(result, pfx)
			return true
		}
		return true
	}
	result = []netaddr.IPPrefix{}
	t.WalkMatch(r.IPNet(), f)
	return result
}

func (ipam *IpTree) Parents(r netaddr.IPPrefix) []netaddr.IPPrefix {
	t := ipam.GetTree()
	var result []netaddr.IPPrefix
	f := func(n *net.IPNet, _ interface{}) bool {
		pfx, _ := netaddr.FromStdIPNet(n)
		if pfx != r {
			result = append(result, pfx)
		}
		return true
	}
	result = []netaddr.IPPrefix{}
	t.WalkMatch(r.IPNet(), f)
	return result
}

func (ipam *IpTree) Children(r netaddr.IPPrefix) []netaddr.IPPrefix {
	t := ipam.GetTree()
	var result []netaddr.IPPrefix
	f := func(n *net.IPNet, _ interface{}) bool {
		pfx, _ := netaddr.FromStdIPNet(n)
		if pfx.Bits() > r.Bits() {
			result = append(result, pfx)
		}
		return true
	}
	result = []netaddr.IPPrefix{}
	t.WalkPrefix(r.IPNet(), f)
	return result
}

func findOtherRanges(data map[string]interface{}) bool {
	//fmt.Println("findOtherRanges", data)
	found := false
	for k := range data {
		if strings.Contains(k, "-") {
			found = true
		}
	}
	return found
}

func main() {
	// Creating new Trie in memory
	ipam := New()
	// Printing the size of the Radix/Patricia tree
	fmt.Println("The ipam tree contains", ipam.GetTree().Size(), "prefixes")

	ipamDummy := New()
	// Printing the size of the Radix/Patricia tree
	fmt.Println("The dummy ipam tree tree contains", ipamDummy.GetTree().Size(), "prefixes")

	cidrs := []map[string]interface{}{
		{"10.0.0.0/8": "rfc1918"},
		{"10.0.0.0/24": "super1"},
		{"10.0.1.0/24": "super2"},
		{"10.0.0.0/16": "newsuper"}, // without sorting it fails on overlap check due to the fact it matches a /24 and a /8
		{"10.0.2.0/24": "super3"},
		{"10.0.255.0/24": "super4"},
		{"3000::/32": "ipv6"},
		{"10.0.0.0-10.0.0.255": "range1"},
		//{"10.0.0.3-10.0.0.178": "range1.1"},
		//{"10.0.0.179-10.0.0.200": "range1.2"},
		//{"10.0.0.0-10.0.1.178": "range2"},  // fails on overlap check since it matches a range
		//{"10.0.0.65-10.0.0.100": "range3"}, // fails on overlap check since it matches a range
		{"dead:beaf::000f-dead:beaf::ffff": "range4"},
		//{"10.0.0.0/25": "slimmy1"},
		//{"10.0.0.128/25": "slimmy2"},
	}

	for _, m := range cidrs {
		for ipitem, value := range m {
			fmt.Println("@@@@@@@@@@@@", ipitem, "@@@@@@@@@@@@")
			if strings.Contains(ipitem, "-") {
				ok, err := ipamDummy.PreCheckAddition(ipitem)
				if err != nil {
					fmt.Println(err)
					panic(err)
				}
				if ok {
					if err := ipam.AddRange(ipitem, value); err != nil {
						fmt.Println(err)
						panic(err)
					}
				} else {
					fmt.Println("cannot add range", ipitem)
				}

			} else {
				ok, err := ipamDummy.PreCheckAddition(ipitem)
				if err != nil {
					fmt.Println(err)
					panic(err)
				}
				if ok {
					if err := ipam.AddPrefix(ipitem, value); err != nil {
						fmt.Println(err)
						panic(err)
					}
				} else {
					fmt.Println("cannot add prefix", ipitem)
				}
			}
			fmt.Println("---------------------------------")
			fmt.Println("The tree contains", ipam.GetTree().Size(), "prefixes")
			ipam.GetTree().Walk(nil, callback)
			fmt.Println("---------------------------------")
		}
	}

	fmt.Println("---------------------------------")
	fmt.Println("The tree contains", ipam.GetTree().Size(), "prefixes")
	ipam.GetTree().Walk(nil, callback)
	fmt.Println("---------------------------------")

	r := "10.0.0.0-10.0.0.255"
	ok, err := ipamDummy.PreCheckDeletion(r)
	if err != nil {
		panic(err)
	}
	if ok {
		if err := ipam.DeleteRange(r); err != nil {
			fmt.Println(err)
			panic(err)
		}
	} else {
		fmt.Println("cannot delete")
	}

	fmt.Println("---------------------------------")
	fmt.Println("The tree contains", ipam.GetTree().Size(), "prefixes")
	ipam.GetTree().Walk(nil, callback)
	fmt.Println("---------------------------------")
	/*
		success, err := ipam.Validate(cidrs)
		if err != nil {
			fmt.Println(err)
			panic(err)
		}
		if success {
			for _, m := range cidrs {
				for ipinput, value := range m {
					if strings.Contains(ipinput, "-") {
						if err := ipam.AddRange(ipinput, value); err != nil {
							fmt.Println(err)
							panic(err)
						}
					} else {
						if err := ipam.AddPrefix(ipinput, value); err != nil {
							fmt.Println(err)
							panic(err)
						}
					}
				}
			}
			fmt.Println("The tree contains", ipam.GetIpamTree().Size(), "prefixes")
			ipam.GetIpamTree().Walk(nil, callback)

			fmt.Println("LPM Method 1 -- func (*Net) Match")

			ips := []string{"10.0.0.0", "10.0.0.200", "10.0.0.255", "10.255.255.255", "11.1.1.1"}

			for _, ip := range ips {
				if ipaddres, err := netaddr.ParseIP(ip); err == nil {
					key, v, err := ipam.GetIpamTree().MatchIP(ipaddres.IPAddr().IP)
					if err != nil {
						panic(err)
					}
					if key != nil {
						fmt.Println("LPM IP address Found", ip, "key", key, "Value", v)
					} else {
						fmt.Println("LPM IP address Not Found")
					}
				}
			}
			s := "10.0.0.0/24"
			p, _ := netaddr.ParseIPPrefix(s)
			fmt.Println(ipam.Parents(p))
			fmt.Println(ipam.Children(p))

			ok, err := ipam.ValidateDeletePrefix(s)
			if err != nil {
				panic(err)
			}
			if ok {
				if err := ipam.DeletePrefix(s); err != nil {
					fmt.Println(err)
					panic(err)
				}
			} else {
				fmt.Println("cannot delete")
			}

			r := "10.0.0.3-10.0.0.178"
			ok, err = ipam.ValidateDeleteRange(r)
			if err != nil {
				panic(err)
			}
			if ok {
				if err := ipam.DeleteRange(r); err != nil {
					fmt.Println(err)
					panic(err)
				}
			} else {
				fmt.Println("cannot delete")
			}

			r = "10.0.0.179-10.0.0.200"
			ok, err = ipam.ValidateDeleteRange(r)
			if err != nil {
				panic(err)
			}
			if ok {
				if err := ipam.DeleteRange(r); err != nil {
					fmt.Println(err)
					panic(err)
				}
			} else {
				fmt.Println("cannot delete")
			}


			fmt.Println("The tree contains", ipam.GetIpamTree().Size(), "prefixes")
			ipam.GetIpamTree().Walk(nil, callback)

		} else {
			fmt.Println("Validation not successfull")
		}
	*/

}

func netValidateIpNet(r *netaddr.IPPrefix) (start, end netaddr.IP, isV4 bool, err error) {
	if r == nil {
		err = errors.New("IP network is nil")
		return
	}
	return netValidatePrefix(r)
}

func netValidatePrefix(r *netaddr.IPPrefix) (start, end netaddr.IP, isV4 bool, err error) {
	if r.IP().Is4() {
		ra := r.Range()
		start = ra.From()
		end = ra.To()
		isV4 = true
	} else if r.IP().Is6() {
		ra := r.Range()
		start = ra.From()
		end = ra.To()
	} else {
		err = fmt.Errorf("invalid IP Prefix: %s", r.String())
	}
	return
}

func netValidateIpRange(r *netaddr.IPRange) (start, end netaddr.IP, isV4 bool, err error) {
	if r.From().Is4() && r.To().Is4() {
		start = r.From()
		end = r.To()
		isV4 = true
	} else if r.From().Is6() && r.To().Is6() {
		start = r.From()
		end = r.To()
	} else {
		err = fmt.Errorf("invalid IP Range: %s", r.String())
	}
	return
}

func AggregatePrefixFromRange(r *netaddr.IPRange) (*netaddr.IPPrefix, error) {
	start := r.From().IPAddr().IP
	end := r.To().IPAddr().IP
	// find the byte where there is a delta can be 0, 1, 2, 3
	idx := -1
	for i := 0; i < len(start); i++ {
		if start[i] != end[i] {
			idx = i
			break
		}
	}
	//fmt.Println("Byte", idx)
	// find the mask based on amount of addresses
	uppermask := idx * 8
	delta := end[idx] - start[idx]
	d := int(delta)
	//fmt.Println(d)
	idx2 := -1
	for i := 1; i <= 8; i++ {
		if d/int((math.Pow(2, float64(i)))) < 1 {
			idx2 = i
			break
		}
	}
	//fmt.Println(idx2)
	uppermask += 8 - idx2
	//fmt.Println("Mask", uppermask)

	startByte := int(int(start[idx])/int((math.Pow(2, float64(idx2))))) * int((math.Pow(2, float64(idx2))))
	//fmt.Println("StartByte", startByte)

	if r.From().Is4() {
		var ip [4]byte
		for i := 0; i < len(start); i++ {
			switch {
			case i < idx:
				ip[i] = start[i]
			case i == idx:
				ip[i] = byte(startByte)
			default:
				ip[i] = 0
			}
		}

		p := netaddr.IPPrefixFrom(netaddr.IPFrom4(ip), uint8(uppermask))
		return &p, nil
	}

	if r.From().Is6() {
		var ip [16]byte
		for i := 0; i < len(start); i++ {
			switch {
			case i < idx:
				ip[i] = start[i]
			case i == idx:
				ip[i] = byte(startByte)
			default:
				ip[i] = 0
			}
		}

		p := netaddr.IPPrefixFrom(netaddr.IPv6Raw(ip), uint8(uppermask))
		return &p, nil
	}
	return nil, errors.New("wrong ip version")
}
