//go:build !linux

package caddy_clienthello

import (
	"errors"
	"net"
)

func queryTcpInfo(_, _ *net.TCPAddr) ([]byte, error) {
	return nil, errors.New("sock_diag needs linux")
}
