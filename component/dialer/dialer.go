package dialer

import (
	"context"
	"errors"
	"net"

	"github.com/Dreamacro/clash/common/picker"
	"github.com/Dreamacro/clash/component/resolver"
)

func Dialer() (*net.Dialer, error) {
	dialer := &net.Dialer{}
	if DialerHook != nil {
		if err := DialerHook(dialer); err != nil {
			return nil, err
		}
	}

	return dialer, nil
}

func Dial(network, address string) (net.Conn, error) {
	return DialContext(context.Background(), network, address)
}

func DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	var ips []net.IP

	switch network {
	case "tcp4", "udp4":
		ips, err = resolver.ResolveIPs(host, resolver.FlagResolveIPv4)
	case "tcp6", "udp6":
		ips, err = resolver.ResolveIPs(host, resolver.FlagResolveIPv6)
	case "tcp", "udp":
		ips, err = resolver.ResolveIPs(host, resolver.FlagResolveIPv4|resolver.FlagResolveIPv6)
	default:
		return nil, errors.New("network invalid")
	}
	if err != nil {
		return nil, err
	}

	return parallelDialContext(ctx, network, ips, port)
}

func ListenPacket(network, address string) (net.PacketConn, error) {
	cfg := &net.ListenConfig{}
	if ListenPacketHook != nil {
		var err error
		address, err = ListenPacketHook(cfg, address)
		if err != nil {
			return nil, err
		}
	}

	return cfg.ListenPacket(context.Background(), network, address)
}

func parallelDialContext(ctx context.Context, network string, ips []net.IP, port string) (net.Conn, error) {
	dialer, err := Dialer()
	if err != nil {
		return nil, err
	}

	fast, ctx := picker.WithContext(ctx)

	fast.Closer(func(conn interface{}) {
		conn.(net.Conn).Close()
	})

	for _, i := range ips {
		ip := i

		fast.Go(func() (interface{}, error) {
			if hook := DialHook; hook != nil {
				if err := hook(dialer, network, ip); err != nil {
					return nil, err
				}
			}

			return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		})
	}

	conn := fast.Wait()

	if conn != nil {
		return conn.(net.Conn), nil
	}

	if fast.Error() != nil {
		return nil, fast.Error()
	}

	return nil, ErrAddrNotFound
}
