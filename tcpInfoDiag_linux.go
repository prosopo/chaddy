//go:build linux

package caddy_clienthello

import (
	"encoding/binary"
	"errors"
	"net"
	"syscall"
)

const (
	netlinkSockDiag    = 4
	sockDiagByFamily   = 20
	inetDiagInfo       = 2
	nlmsgHeaderLen     = 16
	inetDiagMsgLen     = 72
	inetDiagReqLen     = 56
	netlinkAttrHeader  = 4
	tcpInfoReadBufSize = 4096
)

// queryTcpInfo asks the kernel for the stats of the socket with this exact
// address pair. Reading sock_diag needs no privilege, and the query always uses
// AF_INET6 because the kernel resolves v4-mapped addresses to the IPv4 socket.
func queryTcpInfo(local, remote *net.TCPAddr) ([]byte, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, netlinkSockDiag)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(fd)
	timeout := syscall.NsecToTimeval(v2Deadline.Nanoseconds())
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &timeout); err != nil {
		return nil, err
	}
	if err := syscall.Sendto(fd, tcpInfoRequest(local, remote), 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return nil, err
	}
	buf := make([]byte, tcpInfoReadBufSize)
	n, _, err := syscall.Recvfrom(fd, buf, 0)
	if err != nil {
		return nil, err
	}
	return parseTcpInfoReply(buf[:n])
}

func tcpInfoRequest(local, remote *net.TCPAddr) []byte {
	msg := make([]byte, nlmsgHeaderLen+inetDiagReqLen)
	binary.NativeEndian.PutUint32(msg[0:], uint32(len(msg)))
	binary.NativeEndian.PutUint16(msg[4:], sockDiagByFamily)
	binary.NativeEndian.PutUint16(msg[6:], syscall.NLM_F_REQUEST)
	req := msg[nlmsgHeaderLen:]
	req[0] = syscall.AF_INET6
	req[1] = syscall.IPPROTO_TCP
	req[2] = 1 << (inetDiagInfo - 1)
	binary.NativeEndian.PutUint32(req[4:], 0xffffffff)
	id := req[8:]
	binary.BigEndian.PutUint16(id[0:], uint16(local.Port))
	binary.BigEndian.PutUint16(id[2:], uint16(remote.Port))
	copy(id[4:], local.IP.To16())
	copy(id[20:], remote.IP.To16())
	binary.NativeEndian.PutUint64(id[40:], 0xffffffffffffffff)
	return msg
}

func parseTcpInfoReply(reply []byte) ([]byte, error) {
	if len(reply) < nlmsgHeaderLen+inetDiagMsgLen {
		return nil, errors.New("short sock_diag reply")
	}
	if binary.NativeEndian.Uint16(reply[4:]) != sockDiagByFamily {
		return nil, errors.New("no such socket")
	}
	attrs := reply[nlmsgHeaderLen+inetDiagMsgLen:]
	for len(attrs) >= netlinkAttrHeader {
		size := int(binary.NativeEndian.Uint16(attrs))
		if size < netlinkAttrHeader || size > len(attrs) {
			break
		}
		if binary.NativeEndian.Uint16(attrs[2:]) == inetDiagInfo {
			return attrs[netlinkAttrHeader:size], nil
		}
		attrs = attrs[min((size+3)&^3, len(attrs)):]
	}
	return nil, errors.New("no tcp_info in sock_diag reply")
}
