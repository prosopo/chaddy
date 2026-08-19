package caddy_clienthello

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// HandshakeRecord is the raw wire response returned by a co-located eBPF
// TCP handshake probe. Every field is a wire-observed primitive (RFC 793
// / RFC 9293) read straight from the client's SYN by the eBPF program —
// no derived fingerprints, no proprietary formulas, no third-party
// naming.
//
// The reference sidecar implementation is prosopo's private ja4l-probe
// binary, but any eBPF probe that speaks the same 12-byte request /
// 80-byte response protocol below works. Downstream services (providers,
// bumblebee, etc.) do their own math on these raw values.
//
// Layout mirrors a #[repr(C)] Rust struct on the sidecar side and is
// serialised in native byte order (little-endian on x86_64 hosts, which
// is the only architecture the sidecar is deployed on today).
type HandshakeRecord struct {
	// ObservedTtl is the TTL byte of the client's SYN as seen on the
	// server's WAN interface. Range 0..255.
	ObservedTtl uint8
	// SynNs, SynackNs, AckNs are kernel monotonic ns timestamps of the
	// TCP 3-way handshake, from bpf_ktime_get_ns() on the probe side.
	// Boot-relative; only meaningful in deltas within the same record.
	SynNs    uint64
	SynackNs uint64
	AckNs    uint64
	// TcpWindow is the TCP window field from the client's SYN.
	TcpWindow uint16
	// TcpMss is the TCP MSS option value from the client's SYN. Zero if
	// the option is absent or the probe's options parser is disabled.
	TcpMss uint16
	// TcpWscale is the TCP Window-Scale shift from the client's SYN.
	TcpWscale uint8
	// TcpOptsFlags is a bitfield indicating which TCP options are
	// present on the client's SYN. Bit assignment is defined by the
	// probe, not by this package — consumers should treat it as opaque
	// and use it only for equality / clustering.
	TcpOptsFlags uint8
	// TcpOptsOrder is a packed encoding of the order in which TCP
	// options appear on the client's SYN. Opaque like TcpOptsFlags —
	// same value on repeat handshakes from the same OS + kernel + NIC.
	TcpOptsOrder uint32
}

// ProbeLookupTimeout bounds every socket lookup. A slow or dead probe
// must never delay the response — we drop the extra headers and carry
// on if the lookup misses this budget.
const ProbeLookupTimeout = 50 * time.Millisecond

// Wire layout — 12-byte big-endian request, 80-byte native-endian
// response. Rust's #[repr(C)] pads u64 fields to their 8-byte
// alignment, so the response layout is:
//
//	src_ip[16]  0..16
//	dst_ip[16]  16..32
//	src_port    32..34
//	dst_port    34..36
//	is_v6       36
//	_pad0       37
//	syn_ttl     38          <-- ObservedTtl
//	_pad1       39
//	syn_ns      40..48      (u64, first 8-aligned offset)
//	synack_ns   48..56
//	ack_ns      56..64
//	tcp_window  64..66
//	tcp_mss     66..68
//	tcp_wscale  68
//	opts_flags  69
//	(2 bytes pad to align u32)
//	opts_order  72..76
//	(4 bytes trailing pad → total 80 for struct 8-alignment)
const (
	probeReqSize    = 12
	probeRespSize   = 80
	offSynTtl       = 38
	offSynNs        = 40
	offSynackNs     = 48
	offAckNs        = 56
	offTcpWindow    = 64
	offTcpMss       = 66
	offTcpWscale    = 68
	offTcpOptsFlags = 69
	offTcpOptsOrder = 72
)

// LookupHandshake asks the eBPF handshake probe for the raw TCP
// handshake record keyed by the client-side 4-tuple. Opens a fresh Unix
// connection per lookup — the reference probe accepts one request per
// connection and closes.
//
// Returns (nil, nil) on cache miss (probe returns a zeroed record).
// Returns (nil, err) on any dial / IO / timeout error — callers should
// log at debug and continue without injecting the extra headers.
func LookupHandshake(socketPath string, clientIP net.IP, clientPort uint16) (*HandshakeRecord, error) {
	v4 := clientIP.To4()
	if v4 == nil {
		// Reference eBPF probe covers IPv4 only. IPv6 lookups return
		// nothing useful; skip cleanly.
		return nil, nil
	}

	conn, err := net.DialTimeout("unix", socketPath, ProbeLookupTimeout)
	if err != nil {
		return nil, fmt.Errorf("dial probe socket: %w", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(ProbeLookupTimeout)); err != nil {
		return nil, fmt.Errorf("set deadline: %w", err)
	}

	// Request layout (12 bytes, big-endian):
	//   [0..4]   client_ip
	//   [4..6]   client_port
	//   [6..10]  server_ip   (ignored by the reference probe; keying is
	//                         client-side only so the same lookup works
	//                         through Docker DNAT)
	//   [10..12] server_port (ignored)
	var req [probeReqSize]byte
	copy(req[0:4], v4)
	binary.BigEndian.PutUint16(req[4:6], clientPort)
	// req[6..12] stays zero.

	if _, err := conn.Write(req[:]); err != nil {
		return nil, fmt.Errorf("write probe request: %w", err)
	}

	var resp [probeRespSize]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("short probe response: %w", err)
		}
		return nil, fmt.Errorf("read probe response: %w", err)
	}

	rec := HandshakeRecord{
		ObservedTtl:  resp[offSynTtl],
		SynNs:        binary.LittleEndian.Uint64(resp[offSynNs : offSynNs+8]),
		SynackNs:     binary.LittleEndian.Uint64(resp[offSynackNs : offSynackNs+8]),
		AckNs:        binary.LittleEndian.Uint64(resp[offAckNs : offAckNs+8]),
		TcpWindow:    binary.LittleEndian.Uint16(resp[offTcpWindow : offTcpWindow+2]),
		TcpMss:       binary.LittleEndian.Uint16(resp[offTcpMss : offTcpMss+2]),
		TcpWscale:    resp[offTcpWscale],
		TcpOptsFlags: resp[offTcpOptsFlags],
		TcpOptsOrder: binary.LittleEndian.Uint32(resp[offTcpOptsOrder : offTcpOptsOrder+4]),
	}

	// The probe returns an all-zero record on cache miss. A real hit
	// always has SynNs > 0 (from bpf_ktime_get_ns on a completed
	// handshake), so treating "SynNs == 0" as miss is safe.
	if rec.SynNs == 0 {
		return nil, nil
	}
	return &rec, nil
}
