package caddy_clienthello

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// fakeSidecar serves one fixed response per connection on a Unix socket,
// the way the real probe does, and returns the socket path.
func fakeSidecar(t *testing.T, response []byte) string {
	t.Helper()

	// Not t.TempDir(): it embeds the test name, and a Unix socket path is
	// capped near 100 bytes, so a descriptive subtest name is enough to make
	// bind() fail with EINVAL.
	dir, err := os.MkdirTemp("", "chaddy")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	path := filepath.Join(dir, "p.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen on %s: %v", path, err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			req := make([]byte, probeReqSize)
			_, _ = conn.Read(req)
			_, _ = conn.Write(response)
			_ = conn.Close()
		}
	}()

	return path
}

func lookup(t *testing.T, response []byte) (*HandshakeRecord, error) {
	t.Helper()
	return LookupHandshake(fakeSidecar(t, response), net.ParseIP("203.0.113.7"), 54321)
}

// currentRecord builds a 104-byte record with a distinct value in every
// field, so a misread picks up a neighbour's value rather than something
// that could pass for its own.
func currentRecord() []byte {
	rec := make([]byte, probeRespSize)
	binary.LittleEndian.PutUint64(rec[offSynNs:], 1_000_000_000)
	binary.LittleEndian.PutUint64(rec[offSynackNs:], 1_000_050_000)
	binary.LittleEndian.PutUint64(rec[offAckNs:], 1_000_120_000)
	// MSS(2), SACK-permitted(4), Timestamps(8), NOP(1), Window-Scale(3) —
	// the ordinary Linux SYN option order.
	binary.LittleEndian.PutUint64(rec[offTcpOptsKinds:], 0x00_00_00_03_01_08_04_02)
	binary.LittleEndian.PutUint32(rec[offTcpTsval:], 3_456_789)
	binary.LittleEndian.PutUint32(rec[offTcpTsecr:], 0)
	binary.LittleEndian.PutUint16(rec[offTcpOptsPresent:],
		OptMss|OptSackPermitted|OptTimestamps|OptNop|OptWscale)
	binary.LittleEndian.PutUint16(rec[offTcpWindow:], 64240)
	binary.LittleEndian.PutUint16(rec[offTcpMss:], 1460)
	binary.LittleEndian.PutUint16(rec[offTcpUrgPtr:], 0)
	binary.LittleEndian.PutUint16(rec[offIpIdent:], 0)
	binary.LittleEndian.PutUint16(rec[offIpTotalLen:], 60)
	binary.LittleEndian.PutUint16(rec[offIpFragFlags:], IpFlagDf)
	rec[offSynTtl] = 54
	rec[offIpTos] = 0
	rec[offTcpFlags] = 0x02
	rec[offTcpDataOffsetResv] = 0xA0
	rec[offTcpWscale] = 7
	rec[offTcpOptsCount] = 5
	return rec
}

func TestLookupHandshakeReadsEveryFieldOfTheCurrentRecord(t *testing.T) {
	rec, err := lookup(t, currentRecord())
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if rec == nil {
		t.Fatal("a record with syn_ns set is a hit, not a miss")
	}

	for _, c := range []struct {
		field string
		got   uint64
		want  uint64
	}{
		{"SynNs", rec.SynNs, 1_000_000_000},
		{"SynackNs", rec.SynackNs, 1_000_050_000},
		{"AckNs", rec.AckNs, 1_000_120_000},
		{"ObservedTtl", uint64(rec.ObservedTtl), 54},
		{"TcpWindow", uint64(rec.TcpWindow), 64240},
		{"TcpMss", uint64(rec.TcpMss), 1460},
		{"TcpWscale", uint64(rec.TcpWscale), 7},
		{"TcpOptsKinds", rec.TcpOptsKinds, 0x00_00_00_03_01_08_04_02},
		{"TcpOptsCount", uint64(rec.TcpOptsCount), 5},
		{"TcpTsval", uint64(rec.TcpTsval), 3_456_789},
		{"TcpTsecr", uint64(rec.TcpTsecr), 0},
		{"TcpFlags", uint64(rec.TcpFlags), 0x02},
		{"TcpDataOffsetResv", uint64(rec.TcpDataOffsetResv), 0xA0},
		{"TcpUrgPtr", uint64(rec.TcpUrgPtr), 0},
		{"IpIdent", uint64(rec.IpIdent), 0},
		{"IpTotalLen", uint64(rec.IpTotalLen), 60},
		{"IpFragFlags", uint64(rec.IpFragFlags), uint64(IpFlagDf)},
		{"IpTos", uint64(rec.IpTos), 0},
	} {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.field, c.got, c.want)
		}
	}
}

// The regression this file exists for. The previous reader asked
// io.ReadFull for 80 bytes, which SUCCEEDS against a 104-byte record, so
// it parsed the old offsets out of the new layout and wrote
// plausible-looking wrong integers with nothing logged. A record whose size
// matches no known layout must be refused rather than parsed.
func TestLookupHandshakeRefusesARecordOfTheWrongSize(t *testing.T) {
	for _, c := range []struct {
		name string
		size int
	}{
		{"a newer, longer sidecar", 128},
		{"a truncated record", 40},
		{"one byte short of the current layout", 103},
		{"one byte past the legacy layout", 81},
	} {
		t.Run(c.name, func(t *testing.T) {
			response := make([]byte, c.size)
			// Non-zero, so a mismatch cannot be mistaken for the
			// all-zeros cache miss. A record too short to even hold
			// syn_ns is left as-is.
			if c.size >= offSynNs+8 {
				binary.LittleEndian.PutUint64(response[offSynNs:], 1_000_000_000)
			}

			rec, err := lookup(t, response)

			if !errors.Is(err, ErrRecordSizeMismatch) {
				t.Fatalf("err = %v, want ErrRecordSizeMismatch", err)
			}
			if rec != nil {
				t.Error("a record of the wrong size must not be parsed at all")
			}
		})
	}
}

func TestLookupHandshakeReportsEverySizeInTheMismatchError(t *testing.T) {
	response := make([]byte, 128)
	binary.LittleEndian.PutUint64(response[offSynNs:], 1_000_000_000)

	_, err := lookup(t, response)
	if err == nil {
		t.Fatal("want an error")
	}
	// Whoever reads this log line needs the size that arrived and the sizes
	// this build understands, or they cannot tell which side is stale.
	for _, want := range []string{"128", "80", "104"} {
		if !contains(err.Error(), want) {
			t.Errorf("error %q does not report %s", err, want)
		}
	}
}

// legacyRecord builds the 80-byte record the published sidecar image still
// serves, with a distinct value in every field it carries.
func legacyRecord() []byte {
	rec := make([]byte, probeRespSizeLegacy)
	binary.LittleEndian.PutUint64(rec[offSynNs:], 2_000_000_000)
	binary.LittleEndian.PutUint64(rec[offSynackNs:], 2_000_060_000)
	binary.LittleEndian.PutUint64(rec[offAckNs:], 2_000_130_000)
	binary.LittleEndian.PutUint16(rec[offLegacyTcpWindow:], 65535)
	binary.LittleEndian.PutUint16(rec[offLegacyTcpMss:], 1452)
	rec[offLegacyTcpWscale] = 8
	rec[offLegacyTcpOptsFlags] = 0x1f
	binary.LittleEndian.PutUint32(rec[offLegacyTcpOptsOrder:], 123456)
	rec[offLegacySynTtl] = 118
	return rec
}

// Supported rather than refused: this is what the published sidecar image
// serves, and refusing it would drop every TCP signal on every pronode from
// the moment chaddy rolls out until a new image exists.
func TestLookupHandshakeStillReadsTheLegacy80ByteRecord(t *testing.T) {
	rec, err := lookup(t, legacyRecord())
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if rec == nil {
		t.Fatal("a legacy record with syn_ns set is a hit")
	}
	if !rec.Legacy {
		t.Error("Legacy must say which layout was read")
	}

	for _, c := range []struct {
		field string
		got   uint64
		want  uint64
	}{
		{"SynNs", rec.SynNs, 2_000_000_000},
		{"SynackNs", rec.SynackNs, 2_000_060_000},
		{"AckNs", rec.AckNs, 2_000_130_000},
		// 118 lives at offset 38 in this layout and 94 in the current one;
		// reading the wrong offset yields 0, so this pins the dispatch.
		{"ObservedTtl", uint64(rec.ObservedTtl), 118},
		{"TcpWindow", uint64(rec.TcpWindow), 65535},
		{"TcpMss", uint64(rec.TcpMss), 1452},
		{"TcpWscale", uint64(rec.TcpWscale), 8},
		{"TcpOptsFlags", uint64(rec.TcpOptsFlags), 0x1f},
		{"TcpOptsOrder", uint64(rec.TcpOptsOrder), 123456},
	} {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.field, c.got, c.want)
		}
	}
}

// The 80-byte record does not carry these at all. Leaving them zero is only
// safe because Legacy says so — otherwise a consumer reads "no options
// recorded" as "a SYN with no options".
func TestLegacyRecordLeavesTheFieldsItCannotCarryZero(t *testing.T) {
	rec, err := lookup(t, legacyRecord())
	if err != nil || rec == nil {
		t.Fatalf("lookup: %v", err)
	}

	for _, c := range []struct {
		field string
		got   uint64
	}{
		{"TcpOptsKinds", rec.TcpOptsKinds},
		{"TcpOptsPresent", uint64(rec.TcpOptsPresent)},
		{"TcpOptsCount", uint64(rec.TcpOptsCount)},
		{"TcpTsval", uint64(rec.TcpTsval)},
		{"TcpTsecr", uint64(rec.TcpTsecr)},
		{"TcpFlags", uint64(rec.TcpFlags)},
		{"TcpDataOffsetResv", uint64(rec.TcpDataOffsetResv)},
		{"TcpUrgPtr", uint64(rec.TcpUrgPtr)},
		{"IpIdent", uint64(rec.IpIdent)},
		{"IpTotalLen", uint64(rec.IpTotalLen)},
		{"IpFragFlags", uint64(rec.IpFragFlags)},
		{"IpTos", uint64(rec.IpTos)},
	} {
		if c.got != 0 {
			t.Errorf("%s = %d, want 0 — the 80-byte record has no such field", c.field, c.got)
		}
	}
}

func TestCurrentRecordIsNotMarkedLegacy(t *testing.T) {
	rec, err := lookup(t, currentRecord())
	if err != nil || rec == nil {
		t.Fatalf("lookup: %v", err)
	}
	if rec.Legacy {
		t.Error("a 104-byte record is not the legacy layout")
	}
}

func TestLookupHandshakeTreatsAnAllZeroLegacyRecordAsAMiss(t *testing.T) {
	rec, err := lookup(t, make([]byte, probeRespSizeLegacy))
	if err != nil {
		t.Fatalf("a miss is not an error: %v", err)
	}
	if rec != nil {
		t.Error("an all-zero legacy record is the probe's cache miss")
	}
}

func TestLookupHandshakeTreatsAnAllZeroRecordAsAMiss(t *testing.T) {
	rec, err := lookup(t, make([]byte, probeRespSize))
	if err != nil {
		t.Fatalf("a miss is not an error: %v", err)
	}
	if rec != nil {
		t.Error("an all-zero record is the probe's cache miss")
	}
}

func TestLookupHandshakeSkipsIPv6WithoutTouchingTheSocket(t *testing.T) {
	rec, err := LookupHandshake("/nonexistent/socket", net.ParseIP("2001:db8::1"), 443)
	if err != nil {
		t.Fatalf("an IPv6 client is skipped cleanly, not an error: %v", err)
	}
	if rec != nil {
		t.Error("the reference probe is IPv4-only")
	}
}

// tcp_opts_kinds carries full IANA kind numbers precisely so that the
// pairs its 4-bit predecessor aliased stay distinct.
func TestOptionKindsDecodesWireOrderAndStopsAtTheFirstEmptySlot(t *testing.T) {
	rec := &HandshakeRecord{TcpOptsKinds: 0x00_00_00_03_01_08_04_02}

	got := rec.OptionKinds()
	want := []uint8{2, 4, 8, 1, 3}
	if len(got) != len(want) {
		t.Fatalf("OptionKinds() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("OptionKinds() = %v, want %v", got, want)
		}
	}
}

func TestOptionKindsDistinguishesThePairsTheOldEncodingAliased(t *testing.T) {
	// MSS(2) vs Fast Open(34), and Window Scale(3) vs MD5(19). A
	// 4-bit-per-slot encoding could not tell either pair apart.
	rec := &HandshakeRecord{TcpOptsKinds: 0x00_00_00_00_13_22_03_02}

	got := rec.OptionKinds()
	want := []uint8{2, 3, 34, 19}
	for i := range want {
		if i >= len(got) || got[i] != want[i] {
			t.Fatalf("OptionKinds() = %v, want %v", got, want)
		}
	}
}

func TestHasOptionReadsThePresenceBitfield(t *testing.T) {
	rec := &HandshakeRecord{TcpOptsPresent: OptMss | OptTimestamps}

	if !rec.HasOption(OptTimestamps) {
		t.Error("Timestamps was set")
	}
	if !rec.HasOption(OptMss) {
		t.Error("MSS was set")
	}
	// The option the old 8-bit flags field could not represent at all.
	if rec.HasOption(OptMptcp) {
		t.Error("MPTCP was not set")
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
