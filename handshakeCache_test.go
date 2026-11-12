package caddy_clienthello

import (
	"net"
	"testing"

	"go.uber.org/zap"
)

const testAddr = "203.0.113.7:54321"

var testIP = net.ParseIP("203.0.113.7")

func openConnectionCache(t *testing.T) *Cache {
	t.Helper()
	c := &Cache{}
	c.init(zap.NewNop())
	c.SetClientHello(testAddr, "hello")
	return c
}

func missRecord() []byte { return make([]byte, probeRespSize) }

func TestLaterRequestsKeepTheRecordAfterTheProbeHasForgottenIt(t *testing.T) {
	cache := openConnectionCache(t)

	first, err := connectionHandshake(cache, fakeSidecar(t, currentRecord()), testAddr, testIP, 54321)
	if err != nil || first == nil {
		t.Fatalf("first lookup: rec=%v err=%v", first, err)
	}

	// The probe has pruned the record, as it does ten seconds after the handshake.
	later, err := connectionHandshake(cache, fakeSidecar(t, missRecord()), testAddr, testIP, 54321)
	if err != nil {
		t.Fatalf("later lookup: %v", err)
	}
	if later == nil || *later != *first {
		t.Fatalf("later request lost the record: got %+v, want %+v", later, first)
	}
}

func TestAMissIsAskedAgainRatherThanRemembered(t *testing.T) {
	cache := openConnectionCache(t)

	if rec, _ := connectionHandshake(cache, fakeSidecar(t, missRecord()), testAddr, testIP, 54321); rec != nil {
		t.Fatalf("expected a miss, got %+v", rec)
	}
	rec, err := connectionHandshake(cache, fakeSidecar(t, currentRecord()), testAddr, testIP, 54321)
	if err != nil || rec == nil {
		t.Fatalf("second lookup should reach the probe: rec=%v err=%v", rec, err)
	}
}

func TestClosingTheConnectionDropsItsRecord(t *testing.T) {
	cache := openConnectionCache(t)
	if _, err := connectionHandshake(cache, fakeSidecar(t, currentRecord()), testAddr, testIP, 54321); err != nil {
		t.Fatal(err)
	}

	cache.ClearClientHello(testAddr)

	if rec := cache.GetHandshake(testAddr); rec != nil {
		t.Fatalf("record outlived its connection: %+v", rec)
	}
}

func TestALookupFinishingAfterCloseLeavesNothingForTheNextConnection(t *testing.T) {
	cache := openConnectionCache(t)
	cache.ClearClientHello(testAddr)

	rec, err := connectionHandshake(cache, fakeSidecar(t, currentRecord()), testAddr, testIP, 54321)
	if err != nil || rec == nil {
		t.Fatalf("lookup itself should still answer: rec=%v err=%v", rec, err)
	}
	if kept := cache.GetHandshake(testAddr); kept != nil {
		t.Fatalf("closed connection's record was stored: %+v", kept)
	}
}

type remoteAddrConn struct {
	net.Conn
	addr net.Addr
}

func (c remoteAddrConn) RemoteAddr() net.Addr { return c.addr }

func TestTheRecordIsFetchedWhenTheClientHelloArrives(t *testing.T) {
	cache := openConnectionCache(t)
	conn := remoteAddrConn{addr: &net.TCPAddr{IP: testIP, Port: 54321}}
	wrapper := &ClientHelloConnWrapper{Conn: conn, cache: cache, log: zap.NewNop(), tcpProbeSocket: fakeSidecar(t, currentRecord())}

	wrapper.primeHandshake(testAddr)

	if rec := cache.GetHandshake(testAddr); rec == nil {
		t.Fatal("record was not kept at ClientHello time")
	}
}
