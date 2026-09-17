package caddy_clienthello

import (
	"bytes"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type testField struct {
	name  string
	value string
}

func encodeBlock(t *testing.T, encoder *hpack.Encoder, buf *bytes.Buffer, fields []testField) []byte {
	t.Helper()
	buf.Reset()
	for _, f := range fields {
		if err := encoder.WriteField(hpack.HeaderField{Name: f.name, Value: f.value}); err != nil {
			t.Fatal(err)
		}
	}
	return append([]byte(nil), buf.Bytes()...)
}

func names(fields []testField) []string {
	out := make([]string, len(fields))
	for i, f := range fields {
		out[i] = f.name
	}
	return out
}

func orderOf(fields []testField) string {
	return strings.Join(names(fields), ",")
}

// headerFor builds the Request.Header Go would parse from these fields.
func headerFor(fields []testField) http.Header {
	header := http.Header{}
	for _, f := range fields {
		if !strings.HasPrefix(f.name, ":") {
			header.Add(f.name, f.value)
		}
	}
	return header
}

func feedInChunks(recorder *headerOrderRecorder, data []byte, chunk int) {
	for len(data) > 0 {
		n := min(chunk, len(data))
		recorder.observe(data[:n])
		data = data[n:]
	}
}

var chromeFetch = []testField{
	{":method", "POST"},
	{":authority", "pronode.example"},
	{":scheme", "https"},
	{":path", "/v1/prosopo/provider/client/captcha/pow"},
	{"content-length", "120"},
	{"sec-ch-ua-platform", `"macOS"`},
	{"user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36"},
	{"sec-ch-ua", `"Chromium";v="152", "Not?A_Brand";v="24", "Google Chrome";v="152"`},
	{"content-type", "application/json"},
	{"sec-ch-ua-mobile", "?0"},
	{"accept", "*/*"},
	{"origin", "https://site.example"},
	{"sec-fetch-site", "cross-site"},
	{"sec-fetch-mode", "cors"},
	{"sec-fetch-dest", "empty"},
	{"referer", "https://site.example/"},
	{"accept-encoding", "gzip, deflate, br, zstd"},
	{"accept-language", "en-GB,en;q=0.9"},
	{"priority", "u=1, i"},
}

var reorderedGet = []testField{
	{":method", "GET"},
	{":authority", "pronode.example"},
	{":scheme", "https"},
	{":path", "/second"},
	{"sec-ch-ua", `"Chromium";v="152", "Not?A_Brand";v="24", "Google Chrome";v="152"`},
	{"user-agent", chromeFetch[6].value},
	{"accept", "*/*"},
	{"priority", "u=1, i"},
}

type h2Writer struct {
	t       *testing.T
	wire    bytes.Buffer
	framer  *http2.Framer
	block   bytes.Buffer
	encoder *hpack.Encoder
}

func newH2Writer(t *testing.T) *h2Writer {
	w := &h2Writer{t: t}
	w.wire.WriteString(http2.ClientPreface)
	w.framer = http2.NewFramer(&w.wire, nil)
	w.encoder = hpack.NewEncoder(&w.block)
	if err := w.framer.WriteSettings(http2.Setting{ID: http2.SettingHeaderTableSize, Val: 65536}); err != nil {
		t.Fatal(err)
	}
	if err := w.framer.WriteWindowUpdate(0, 15663105); err != nil {
		t.Fatal(err)
	}
	return w
}

func (w *h2Writer) headers(streamID uint32, fields []testField) {
	w.t.Helper()
	fragment := encodeBlock(w.t, w.encoder, &w.block, fields)
	if err := w.framer.WriteHeaders(http2.HeadersFrameParam{StreamID: streamID, BlockFragment: fragment, EndHeaders: true, EndStream: true}); err != nil {
		w.t.Fatal(err)
	}
}

func h2ClientStream(t *testing.T) []byte {
	t.Helper()
	w := newH2Writer(t)

	first := encodeBlock(t, w.encoder, &w.block, chromeFetch)
	split := len(first) / 3
	if err := w.framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: first[:split],
		PadLength:     7,
		Priority:      http2.PriorityParam{StreamDep: 0, Weight: 219, Exclusive: true},
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.framer.WriteContinuation(1, false, first[split:2*split]); err != nil {
		t.Fatal(err)
	}
	if err := w.framer.WriteContinuation(1, true, first[2*split:]); err != nil {
		t.Fatal(err)
	}
	if err := w.framer.WriteData(1, false, bytes.Repeat([]byte("x"), 120)); err != nil {
		t.Fatal(err)
	}
	w.headers(1, []testField{{"x-trailer", "1"}})
	w.headers(3, reorderedGet)
	return w.wire.Bytes()
}

func TestH2HeaderOrderSurvivesFramingAndDynamicTable(t *testing.T) {
	wire := h2ClientStream(t)
	for _, chunk := range []int{1, 7, 4096, len(wire)} {
		recorder := &headerOrderRecorder{}
		feedInChunks(recorder, wire, chunk)

		got, _ := recorder.take("GET", "/second", "pronode.example", headerFor(reorderedGet))
		if got != orderOf(reorderedGet) {
			t.Fatalf("chunk %d: second stream got %v", chunk, got)
		}
		got, _ = recorder.take("POST", "/v1/prosopo/provider/client/captcha/pow", "pronode.example", headerFor(chromeFetch))
		if got != orderOf(chromeFetch) {
			t.Fatalf("chunk %d: first stream got %v", chunk, got)
		}
		if len(recorder.pending) != 0 || recorder.failed {
			t.Fatalf("chunk %d: pending %v, failed %v", chunk, recorder.pending, recorder.failed)
		}
	}
}

func TestH2ConsecutiveLargeHeaderBlocksAreBothRecorded(t *testing.T) {
	w := newH2Writer(t)
	large := strings.Repeat("v", 600<<10)
	for i, path := range []string{"/a", "/b"} {
		w.headers(uint32(2*i+1), []testField{{":method", "GET"}, {":authority", "h"}, {":scheme", "https"}, {":path", path}, {"x-large", large}})
	}
	recorder := &headerOrderRecorder{}
	recorder.observe(w.wire.Bytes())
	header := http.Header{"X-Large": {large}}
	_, gotA := recorder.take("GET", "/a", "h", header)
	_, gotB := recorder.take("GET", "/b", "h", header)
	if !gotA || !gotB {
		t.Fatalf("both blocks should be recorded; failed=%v", recorder.failed)
	}
}

func TestH2HeaderOrderStopsOnMalformedFrames(t *testing.T) {
	var wire bytes.Buffer
	wire.WriteString(http2.ClientPreface)
	framer := http2.NewFramer(&wire, nil)
	if err := framer.WriteContinuation(1, true, []byte{0x82}); err != nil {
		t.Fatal(err)
	}
	recorder := &headerOrderRecorder{}
	recorder.observe(wire.Bytes())
	if !recorder.failed {
		t.Fatal("a CONTINUATION without HEADERS should stop recording")
	}
	recorder.observe([]byte("GET / HTTP/1.1\r\nHost: a\r\n\r\n"))
	if len(recorder.pending) != 0 {
		t.Fatal("a failed recorder must not queue entries")
	}
}

func TestTakeMatchesAuthorityAndHeaderSet(t *testing.T) {
	recorder := &headerOrderRecorder{}
	recorder.push(headerOrderEntry{method: "GET", target: "/", authority: "other", order: []byte(":method,a-first")})
	recorder.push(headerOrderEntry{method: "GET", target: "/", authority: "localhost", order: []byte(":method,x-left-behind")})
	recorder.push(headerOrderEntry{method: "GET", target: "/", authority: "localhost", order: []byte(":method,b-second")})

	got, _ := recorder.take("GET", "/", "localhost", http.Header{"B-Second": {"1"}})
	if got != ":method,b-second" {
		t.Fatalf("got %v", got)
	}
	if len(recorder.pending) != 2 {
		t.Fatalf("HTTP/2 must only remove the match, pending = %v", recorder.pending)
	}
	if _, ok := recorder.take("GET", "/", "localhost", http.Header{}); ok {
		t.Fatal("an entry whose headers aren't on the request must not match")
	}
}

func TestSequentialTakeDropsEntriesThatCanNoLongerMatch(t *testing.T) {
	recorder := &headerOrderRecorder{sequential: true}
	recorder.push(headerOrderEntry{method: "GET", target: "/robots.txt", authority: "a"})
	recorder.push(headerOrderEntry{method: "GET", target: "/", authority: "a", order: []byte("Host")})
	recorder.push(headerOrderEntry{method: "GET", target: "/next", authority: "a"})
	if _, ok := recorder.take("GET", "/", "a", http.Header{}); !ok {
		t.Fatal("expected a match")
	}
	if len(recorder.pending) != 1 || recorder.pending[0].target != "/next" {
		t.Fatalf("pending = %v", recorder.pending)
	}
}

func TestNamesPresentSkipsFieldsTheServerRemoves(t *testing.T) {
	recorded := []byte(":path,Host,Content-Length,Transfer-Encoding,Trailer,Connection,X-Header-Order,x_underscore,Accept")
	if !namesPresent(recorded, http.Header{"Accept": {"*/*"}}) {
		t.Fatal("fields Go or Caddy remove from Request.Header must be ignored")
	}
	if namesPresent([]byte("Accept,Origin"), http.Header{"Accept": {"*/*"}}) {
		t.Fatal("a missing field must fail the check")
	}
}

func TestH1HeaderOrderKeepsCasingDuplicatesAndPipelining(t *testing.T) {
	wire := "POST /first HTTP/1.1\r\n" +
		"Host: pronode.example\r\n" +
		"Connection: keep-alive\r\n" +
		"Content-Length: 7\r\n" +
		"sec-ch-ua-platform: \"Windows\"\r\n" +
		"User-Agent: Mozilla/5.0\r\n" +
		"Cookie: a=1\r\n" +
		"Cookie: b=2\r\n" +
		"\r\n" + `{"a":1}` +
		"\r\nGET /second?x=1 HTTP/1.1\n" +
		"Host: pronode.example\n" +
		"Accept: */*\n" +
		"\n"
	for _, chunk := range []int{1, 2, 3, 5, len(wire)} {
		recorder := &headerOrderRecorder{}
		feedInChunks(recorder, []byte(wire), chunk)

		header := http.Header{"Sec-Ch-Ua-Platform": {`"Windows"`}, "User-Agent": {"Mozilla/5.0"}, "Cookie": {"a=1", "b=2"}}
		got, _ := recorder.take("POST", "/first", "pronode.example", header)
		want := "Host,Connection,Content-Length,sec-ch-ua-platform,User-Agent,Cookie,Cookie"
		if got != want {
			t.Fatalf("chunk %d: first request got %v, want %v (failed=%v)", chunk, got, want, recorder.failed)
		}
		got, _ = recorder.take("GET", "/second?x=1", "pronode.example", http.Header{"Accept": {"*/*"}})
		if got != "Host,Accept" {
			t.Fatalf("chunk %d: bare-LF request got %v", chunk, got)
		}
	}
}

func TestH1HeaderOrderStopsAtChunkedBodies(t *testing.T) {
	smuggled := "GET /smuggled HTTP/1.1\r\nHost: a\r\n\r\n"
	wire := "POST /upload HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n" + smuggled +
		"GET /after HTTP/1.1\r\nHost: a\r\n\r\n"
	recorder := &headerOrderRecorder{}
	recorder.observe([]byte(wire))
	if len(recorder.pending) != 1 || recorder.pending[0].target != "/upload" || recorder.failed {
		t.Fatalf("only the chunked request's own head should be recorded, pending = %v", recorder.pending)
	}
}

func TestHeaderOrderMemoryIsBounded(t *testing.T) {
	recorder := &headerOrderRecorder{}
	var wire strings.Builder
	manyNames := strings.Repeat("X-"+strings.Repeat("n", 500)+": v\r\n", 20)
	for i := 0; i < maxPendingHeaderOrders+10; i++ {
		wire.WriteString("GET /r HTTP/1.1\r\nHost: a\r\n" + manyNames + "\r\n")
	}
	wire.WriteString("GET /" + strings.Repeat("p", maxMatchFieldBytes) + " HTTP/1.1\r\nHost: a\r\n\r\n")
	recorder.observe([]byte(wire.String()))

	if len(recorder.pending) != maxPendingHeaderOrders {
		t.Fatalf("pending = %d, want %d", len(recorder.pending), maxPendingHeaderOrders)
	}
	for _, entry := range recorder.pending {
		if len(entry.order) > maxHeaderOrderBytes || entry.target != "/r" {
			t.Fatalf("entry holds %d order bytes for %q", len(entry.order), entry.target)
		}
	}
}
