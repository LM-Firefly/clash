package resolver

import (
	"errors"
	"net"

	"github.com/Dreamacro/clash/component/trie"
)

const (
	FlagResolveIPv4 ResolveFlag = 1 << 0
	FlagResolveIPv6             = 1 << 1
	FlagPreferIPv4              = 1 << 2
	FlagPreferIPv6              = 1 << 3
)

var (
	// DefaultResolver aim to resolve ip
	DefaultResolver Resolver

	// DisableIPv6 means don't resolve ipv6 host
	// default value is true
	DisableIPv6 = true

	// DefaultHosts aim to resolve hosts
	DefaultHosts = trie.New()
)

var (
	ErrIPNotFound = errors.New("couldn't find ip")
	ErrIPVersion  = errors.New("ip version error")
)

type ResolveFlag uint32

type Resolver interface {
	ResolveIPs(host string, flags ResolveFlag) (ip []net.IP, err error)
}

func ResolveIP(host string) (net.IP, error) {
	ips, err := ResolveIPs(host, FlagPreferIPv4|FlagPreferIPv6|FlagResolveIPv4)
	if err != nil {
		return nil, err
	}

	return ips[0], nil
}

func ResolveIPs(host string, flags ResolveFlag) ([]net.IP, error) {
	if DisableIPv6 {
		flags = flags & (FlagResolveIPv6 ^ 0xFFFFFFFF)
	}

	if resolver := DefaultResolver; resolver != nil {
		return resolver.ResolveIPs(host, flags)
	}

	var ips []net.IP
	var err error

	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else {
		ips, err = net.LookupIP(host)
	}
	if err != nil {
		return nil, err
	}

	filtered := make([]net.IP, 0, len(ips))

	if (flags&FlagPreferIPv4 != 0) == (flags&FlagPreferIPv6 != 0) {
		for _, ip := range ips {
			isV4 := ip.To4() != nil
			if isV4 && flags&FlagResolveIPv4 == 1 {
				filtered = append(filtered, ip.To4())
			} else if !isV4 && flags&FlagResolveIPv6 == 1 {
				filtered = append(filtered, ip.To16())
			}
		}
	} else if flags&FlagPreferIPv4 != 0 {
		for _, ip := range ips {
			isV4 := ip.To4() != nil
			if isV4 && flags&FlagResolveIPv4 == 1 {
				filtered = append(filtered, ip.To4())
			}
		}
		for _, ip := range ips {
			isV4 := ip.To4() != nil
			if !isV4 && flags&FlagResolveIPv6 == 1 {
				filtered = append(filtered, ip.To16())
			}
		}
	} else {
		for _, ip := range ips {
			isV4 := ip.To4() != nil
			if !isV4 && flags&FlagResolveIPv6 == 1 {
				filtered = append(filtered, ip.To16())
			}
		}
		for _, ip := range ips {
			isV4 := ip.To4() != nil
			if isV4 && flags&FlagResolveIPv4 == 1 {
				filtered = append(filtered, ip.To4())
			}
		}
	}

	if len(filtered) > 0 {
		return filtered, nil
	}

	return nil, ErrIPNotFound
}
