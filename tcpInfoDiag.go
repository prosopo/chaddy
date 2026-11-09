package caddy_clienthello

import (
	"encoding/binary"
	"encoding/json"
	"net"
)

// tcpInfoSize covers the last field read. A shorter reply from an older kernel
// reads as zeros, as it does in tcp-probe.
const tcpInfoSize = 232

// renderTcpInfo must match render_tcp_info in tcp-probe, so that a record has the
// same shape however it was looked up.
func renderTcpInfo(raw []byte) map[string]uint64 {
	b := make([]byte, tcpInfoSize)
	copy(b, raw)
	u32 := func(off int) uint64 { return uint64(binary.NativeEndian.Uint32(b[off:])) }
	u64 := func(off int) uint64 { return binary.NativeEndian.Uint64(b[off:]) }
	return map[string]uint64{
		"state": uint64(b[0]), "ca_state": uint64(b[1]), "options": uint64(b[5]),
		"snd_wscale": uint64(b[6] & 0xf), "rcv_wscale": uint64(b[6] >> 4),
		"rto": u32(8), "snd_mss": u32(16), "rcv_mss": u32(20),
		"lost": u32(32), "pmtu": u32(60), "rtt": u32(68), "rttvar": u32(72),
		"snd_cwnd": u32(80), "advmss": u32(84), "reordering": u32(88),
		"rcv_rtt": u32(92), "total_retrans": u32(100),
		"bytes_acked": u64(120), "bytes_received": u64(128),
		"segs_out": u32(136), "segs_in": u32(140), "min_rtt": u32(148),
		"delivery_rate": u64(160), "bytes_sent": u64(200), "snd_wnd": u32(228),
	}
}

// withTcpInfo adds tcp_info to a record found by client address. Behind the
// layer4 hop the client's socket has no fd here, but it is in this network
// namespace, so the kernel can report on it by address. A failure keeps the
// record as it was: the stats are extra and must not cost the rest of it.
func withTcpInfo(answer []byte, query func(local, remote *net.TCPAddr) ([]byte, error)) ([]byte, error) {
	var record map[string]json.RawMessage
	if err := json.Unmarshal(answer, &record); err != nil {
		return answer, err
	}
	var addrs struct {
		Hit        bool   `json:"hit"`
		LocalIP    string `json:"local_ip"`
		LocalPort  int    `json:"local_port"`
		RemoteIP   string `json:"remote_ip"`
		RemotePort int    `json:"remote_port"`
	}
	if err := json.Unmarshal(answer, &addrs); err != nil || !addrs.Hit {
		return answer, err
	}
	raw, err := query(
		&net.TCPAddr{IP: net.ParseIP(addrs.LocalIP), Port: addrs.LocalPort},
		&net.TCPAddr{IP: net.ParseIP(addrs.RemoteIP), Port: addrs.RemotePort},
	)
	if err != nil {
		return answer, err
	}
	info, err := json.Marshal(renderTcpInfo(raw))
	if err != nil {
		return answer, err
	}
	record["tcp_info"] = info
	merged, err := json.Marshal(record)
	if err != nil {
		return answer, err
	}
	return merged, nil
}
