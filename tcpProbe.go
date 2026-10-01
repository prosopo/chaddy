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
// The reference sidecar implementation is prosopo's private tcp-probe
// binary, but any eBPF probe that speaks the same 12-byte request /
// 104-byte response protocol below works. Downstream services
// (providers, bumblebee, etc.) do their own math on these raw values.
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

	// TcpWindow is the TCP window field from the client's SYN, before
	// any window scaling is applied.
	TcpWindow uint16
	// TcpMss is the TCP MSS option (kind 2) value from the client's SYN.
	// Zero if the option is absent or the probe's options parser is
	// disabled.
	TcpMss uint16
	// TcpWscale is the TCP Window-Scale option (kind 3) shift from the
	// client's SYN. 255 is the probe's absent-marker.
	TcpWscale uint8

	// TcpOptsKinds packs the IANA kind number of each TCP option on the
	// SYN, in wire order, one full byte per option, least-significant
	// byte first, for the first OptsKindsSlots options. Full kind values,
	// so MSS (2) is distinguishable from TCP Fast Open (34) and Window
	// Scale (3) from MD5 (19). This replaces the 4-bit-per-slot
	// TcpOptsOrder of the 80-byte record, which aliased exactly those
	// pairs together and could not name MPTCP at all.
	TcpOptsKinds uint64
	// TcpOptsPresent is a bitfield of which options were seen, using the
	// Opt* constants below. It covers options whose value is not
	// recorded, which is the only way to see MPTCP / Fast Open / MD5 at
	// all. This replaces the opaque 8-bit TcpOptsFlags of the 80-byte
	// record.
	TcpOptsPresent uint16
	// TcpOptsCount is the total number of options on the SYN, saturating
	// at 255. Larger than OptsKindsSlots means TcpOptsKinds is truncated,
	// which OptTruncated also reports.
	TcpOptsCount uint8

	// TcpTsval and TcpTsecr are the Timestamps option (kind 8) values.
	// TSval is a counter the sending kernel starts at boot and increments
	// at a fixed tick rate, so it identifies the sending stack rather
	// than the claimed client. TSecr should be 0 on a SYN; anything else
	// is anomalous. Both are only meaningful when OptTimestamps is set in
	// TcpOptsPresent — a TSval of exactly 0 is legal, so zero cannot mean
	// absent.
	TcpTsval uint32
	TcpTsecr uint32

	// TcpFlags is the raw TCP flag byte: CWR 0x80, ECE 0x40 … SYN 0x02,
	// FIN 0x01.
	TcpFlags uint8
	// TcpDataOffsetResv holds the data offset in the high nibble and the
	// reserved bits plus NS in the low nibble.
	TcpDataOffsetResv uint8
	// TcpUrgPtr is the TCP urgent pointer. Non-zero on a SYN is
	// malformed.
	TcpUrgPtr uint16

	// IpIdent is the IPv4 identification field: 0-with-DF on Linux,
	// incrementing on Windows.
	IpIdent uint16
	// IpTotalLen is the IPv4 total length, i.e. the size class of the
	// SYN.
	IpTotalLen uint16
	// IpFragFlags is the raw IPv4 flags plus fragment offset. DF is bit
	// 14 (IpFlagDf).
	IpFragFlags uint16
	// IpTos carries DSCP in the high 6 bits and the ECN codepoint in the
	// low 2 (IpTosEcnMask).
	IpTos uint8
}

// Bits for HandshakeRecord.TcpOptsPresent. Mirrors the OPT_* constants in
// the sidecar's wire crate; named for the option rather than the kind
// number so a reader never has to know the IANA table.
const (
	OptEol           uint16 = 1 << 0  // kind 0
	OptNop           uint16 = 1 << 1  // kind 1
	OptMss           uint16 = 1 << 2  // kind 2
	OptWscale        uint16 = 1 << 3  // kind 3
	OptSackPermitted uint16 = 1 << 4  // kind 4
	OptSack          uint16 = 1 << 5  // kind 5
	OptTimestamps    uint16 = 1 << 6  // kind 8
	OptMd5           uint16 = 1 << 7  // kind 19
	OptUserTimeout   uint16 = 1 << 8  // kind 28
	OptAuth          uint16 = 1 << 9  // kind 29 (TCP-AO)
	OptMptcp         uint16 = 1 << 10 // kind 30
	OptFastOpen      uint16 = 1 << 11 // kind 34
	OptExperimental  uint16 = 1 << 12 // kinds 253, 254
	OptUnknown       uint16 = 1 << 13 // any other kind
	OptTruncated     uint16 = 1 << 14 // more options than TcpOptsKinds slots
)

// OptsKindsSlots is how many option kinds TcpOptsKinds can hold.
const OptsKindsSlots = 8

// IpFlagDf and IpFlagMf are the IPv4 Don't Fragment and More Fragments
// bits within HandshakeRecord.IpFragFlags.
const (
	IpFlagDf uint16 = 0x4000
	IpFlagMf uint16 = 0x2000
)

// IpTosEcnMask is the ECN codepoint mask within HandshakeRecord.IpTos
// (00 not-ECT, 01 ECT(1), 10 ECT(0), 11 CE).
const IpTosEcnMask uint8 = 0x03

// WscaleAbsent is the sidecar's absent-marker for TcpWscale. A real shift
// of 255 is not expressible on the wire, so the marker is unambiguous.
const WscaleAbsent uint8 = 255

// ProbeLookupTimeout bounds every socket lookup. A slow or dead probe
// must never delay the response — we drop the extra headers and carry
// on if the lookup misses this budget.
const ProbeLookupTimeout = 50 * time.Millisecond

// ErrRecordSizeMismatch reports that the sidecar's record is not the size
// this build knows how to parse, which means the two are deployed at
// different versions. Callers must surface it as an error rather than
// folding it into the ordinary miss path: it is a deployment fault that
// needs a human, and the previous reader could not see it at all.
//
// That reader asked io.ReadFull for exactly 80 bytes, which SUCCEEDS
// against a 104-byte record — it gets the 80 bytes it asked for and the
// short-read branch never fires. It then parsed the old offsets out of
// the new layout, so TcpWindow read the low half of TcpOptsKinds and
// TcpOptsOrder read TcpTsval, and the result was plausible-looking wrong
// integers rather than an absence. Reading to EOF and comparing the
// length is what makes both directions of skew impossible to miss.
var ErrRecordSizeMismatch = errors.New("tcp probe handshake record size mismatch")

// Wire layout — 12-byte big-endian request, 104-byte native-endian
// response. Must stay in sync with the sidecar's
// tcp-probe/tcp-probe-common/src/lib.rs::HandshakeRecord.
//
// Rust's #[repr(C)] pads the u64 fields to their 8-byte alignment, so:
//
//	src_ip[16]            0..16
//	dst_ip[16]            16..32
//	src_port              32..34
//	dst_port              34..36
//	is_v6                 36
//	_pad0[3]              37..40
//	syn_ns                40..48   (u64, first 8-aligned offset)
//	synack_ns             48..56
//	ack_ns                56..64
//	tcp_opts_kinds        64..72
//	tcp_tsval             72..76
//	tcp_tsecr             76..80
//	tcp_opts_present      80..82
//	tcp_window            82..84
//	tcp_mss               84..86
//	tcp_urg_ptr           86..88
//	ip_ident              88..90
//	ip_total_len          90..92
//	ip_frag_flags         92..94
//	syn_ttl               94
//	ip_tos                95
//	tcp_flags             96
//	tcp_data_offset_resv  97
//	tcp_wscale            98
//	tcp_opts_count        99
//	_pad1[2]              100..102
//	(2-byte trailing pad → total 104 for struct 8-alignment)
const (
	probeReqSize  = 12
	probeRespSize = 104

	offSynNs             = 40
	offSynackNs          = 48
	offAckNs             = 56
	offTcpOptsKinds      = 64
	offTcpTsval          = 72
	offTcpTsecr          = 76
	offTcpOptsPresent    = 80
	offTcpWindow         = 82
	offTcpMss            = 84
	offTcpUrgPtr         = 86
	offIpIdent           = 88
	offIpTotalLen        = 90
	offIpFragFlags       = 92
	offSynTtl            = 94
	offIpTos             = 95
	offTcpFlags          = 96
	offTcpDataOffsetResv = 97
	offTcpWscale         = 98
	offTcpOptsCount      = 99
)

// probeRespReadCap bounds how much a misbehaving or newer sidecar can
// make us buffer, while still being large enough to measure any
// plausible record and report its real size in the mismatch error.
const probeRespReadCap = 1024

// LookupHandshake asks the eBPF handshake probe for the raw TCP
// handshake record keyed by the client-side 4-tuple. Opens a fresh Unix
// connection per lookup — the reference probe accepts one request per
// connection and closes.
//
// Returns (nil, nil) on cache miss (probe returns a zeroed record).
// Returns (nil, err) on any dial / IO / timeout error — callers should
// log at debug and continue without injecting the extra headers, except
// for ErrRecordSizeMismatch, which needs to be loud.
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

	// Read to EOF rather than asking for a fixed count, so that a record
	// of the wrong size is measurable instead of being silently truncated
	// to whatever this build expects. The probe closes after one
	// response, so EOF arrives on its own.
	resp, err := io.ReadAll(io.LimitReader(conn, probeRespReadCap))
	if err != nil {
		return nil, fmt.Errorf("read probe response: %w", err)
	}
	if len(resp) != probeRespSize {
		return nil, fmt.Errorf(
			"%w: sidecar sent %d bytes, this build parses %d",
			ErrRecordSizeMismatch, len(resp), probeRespSize,
		)
	}

	rec := HandshakeRecord{
		ObservedTtl:       resp[offSynTtl],
		SynNs:             binary.LittleEndian.Uint64(resp[offSynNs : offSynNs+8]),
		SynackNs:          binary.LittleEndian.Uint64(resp[offSynackNs : offSynackNs+8]),
		AckNs:             binary.LittleEndian.Uint64(resp[offAckNs : offAckNs+8]),
		TcpWindow:         binary.LittleEndian.Uint16(resp[offTcpWindow : offTcpWindow+2]),
		TcpMss:            binary.LittleEndian.Uint16(resp[offTcpMss : offTcpMss+2]),
		TcpWscale:         resp[offTcpWscale],
		TcpOptsKinds:      binary.LittleEndian.Uint64(resp[offTcpOptsKinds : offTcpOptsKinds+8]),
		TcpOptsPresent:    binary.LittleEndian.Uint16(resp[offTcpOptsPresent : offTcpOptsPresent+2]),
		TcpOptsCount:      resp[offTcpOptsCount],
		TcpTsval:          binary.LittleEndian.Uint32(resp[offTcpTsval : offTcpTsval+4]),
		TcpTsecr:          binary.LittleEndian.Uint32(resp[offTcpTsecr : offTcpTsecr+4]),
		TcpFlags:          resp[offTcpFlags],
		TcpDataOffsetResv: resp[offTcpDataOffsetResv],
		TcpUrgPtr:         binary.LittleEndian.Uint16(resp[offTcpUrgPtr : offTcpUrgPtr+2]),
		IpIdent:           binary.LittleEndian.Uint16(resp[offIpIdent : offIpIdent+2]),
		IpTotalLen:        binary.LittleEndian.Uint16(resp[offIpTotalLen : offIpTotalLen+2]),
		IpFragFlags:       binary.LittleEndian.Uint16(resp[offIpFragFlags : offIpFragFlags+2]),
		IpTos:             resp[offIpTos],
	}

	// The probe returns an all-zero record on cache miss. A real hit
	// always has SynNs > 0 (from bpf_ktime_get_ns on a completed
	// handshake), so treating "SynNs == 0" as miss is safe.
	if rec.SynNs == 0 {
		return nil, nil
	}
	return &rec, nil
}

// HasOption reports whether the SYN carried the option named by one of
// the Opt* bits.
func (r *HandshakeRecord) HasOption(bit uint16) bool {
	return r.TcpOptsPresent&bit != 0
}

// OptionKinds decodes TcpOptsKinds into the IANA kind numbers of the
// options on the SYN, in wire order. Stops at the first empty slot, so a
// trailing End-of-Option-List (kind 0) ends the list rather than
// appearing in it.
func (r *HandshakeRecord) OptionKinds() []uint8 {
	kinds := make([]uint8, 0, OptsKindsSlots)
	for slot := 0; slot < OptsKindsSlots; slot++ {
		kind := uint8(r.TcpOptsKinds >> (slot * 8))
		if kind == 0 {
			break
		}
		kinds = append(kinds, kind)
	}
	return kinds
}
