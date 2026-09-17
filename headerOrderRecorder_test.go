package caddy_clienthello

import (
	"bytes"
	"reflect"
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

func h2ClientStream(t *testing.T) []byte {
	t.Helper()
	var wire bytes.Buffer
	wire.WriteString(http2.ClientPreface)
	framer := http2.NewFramer(&wire, nil)
	if err := framer.WriteSettings(http2.Setting{ID: http2.SettingHeaderTableSize, Val: 65536}); err != nil {
		t.Fatal(err)
	}
	if err := framer.WriteWindowUpdate(0, 15663105); err != nil {
		t.Fatal(err)
	}

	var block bytes.Buffer
	encoder := hpack.NewEncoder(&block)

	first := encodeBlock(t, encoder, &block, chromeFetch)
	split := len(first) / 3
	if err := framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: first[:split],
		EndHeaders:    false,
		PadLength:     7,
		Priority:      http2.PriorityParam{StreamDep: 0, Weight: 219, Exclusive: true},
	}); err != nil {
		t.Fatal(err)
	}
	if err := framer.WriteContinuation(1, false, first[split:2*split]); err != nil {
		t.Fatal(err)
	}
	if err := framer.WriteContinuation(1, true, first[2*split:]); err != nil {
		t.Fatal(err)
	}
	if err := framer.WriteData(1, false, bytes.Repeat([]byte("x"), 120)); err != nil {
		t.Fatal(err)
	}

	trailer := encodeBlock(t, encoder, &block, []testField{{"x-trailer", "1"}})
	if err := framer.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: trailer, EndHeaders: true, EndStream: true}); err != nil {
		t.Fatal(err)
	}

	reordered := []testField{
		{":method", "GET"},
		{":authority", "pronode.example"},
		{":scheme", "https"},
		{":path", "/second"},
		{"sec-ch-ua", `"Chromium";v="152", "Not?A_Brand";v="24", "Google Chrome";v="152"`},
		{"user-agent", chromeFetch[6].value},
		{"accept", "*/*"},
		{"priority", "u=1, i"},
	}
	second := encodeBlock(t, encoder, &block, reordered)
	if err := framer.WriteHeaders(http2.HeadersFrameParam{StreamID: 3, BlockFragment: second, EndHeaders: true, EndStream: true}); err != nil {
		t.Fatal(err)
	}
	return wire.Bytes()
}

func TestH2HeaderOrderSurvivesFramingAndDynamicTable(t *testing.T) {
	wire := h2ClientStream(t)
	for _, chunk := range []int{1, 7, 4096, len(wire)} {
		recorder := newHeaderOrderRecorder()
		feedInChunks(recorder, wire, chunk)

		got, ok := recorder.take("GET", "/second")
		want := []string{":method", ":authority", ":scheme", ":path", "sec-ch-ua", "user-agent", "accept", "priority"}
		if !ok || !reflect.DeepEqual(got, want) {
			t.Fatalf("chunk %d: second stream got %v, want %v", chunk, got, want)
		}
		got, ok = recorder.take("POST", "/v1/prosopo/provider/client/captcha/pow")
		if !ok || !reflect.DeepEqual(got, names(chromeFetch)) {
			t.Fatalf("chunk %d: first stream got %v, want %v", chunk, got, names(chromeFetch))
		}
		if len(recorder.pending) != 0 {
			t.Fatalf("chunk %d: trailers or duplicates were recorded: %v", chunk, recorder.pending)
		}
		if recorder.failed {
			t.Fatalf("chunk %d: recorder failed", chunk)
		}
	}
}

func TestH2HeaderOrderStopsOnMalformedFrames(t *testing.T) {
	var wire bytes.Buffer
	wire.WriteString(http2.ClientPreface)
	framer := http2.NewFramer(&wire, nil)
	if err := framer.WriteContinuation(1, true, []byte{0x82}); err != nil {
		t.Fatal(err)
	}
	recorder := newHeaderOrderRecorder()
	recorder.observe(wire.Bytes())
	if !recorder.failed {
		t.Fatal("a CONTINUATION without HEADERS should stop recording")
	}
	recorder.observe([]byte("anything"))
	if len(recorder.pending) != 0 {
		t.Fatal("a failed recorder must not queue entries")
	}
}

func TestH1HeaderOrderKeepsCasingDuplicatesAndPipelining(t *testing.T) {
	body := `{"a":1}`
	wire := "POST /first HTTP/1.1\r\n" +
		"Host: pronode.example\r\n" +
		"Connection: keep-alive\r\n" +
		"Content-Length: " + "7" + "\r\n" +
		"sec-ch-ua-platform: \"Windows\"\r\n" +
		"User-Agent: Mozilla/5.0\r\n" +
		"Cookie: a=1\r\n" +
		"Cookie: b=2\r\n" +
		"\r\n" + body +
		"\r\nGET /second?x=1 HTTP/1.1\r\n" +
		"Host: pronode.example\r\n" +
		"Accept: */*\r\n" +
		"\r\n"
	for _, chunk := range []int{1, 5, len(wire)} {
		recorder := newHeaderOrderRecorder()
		feedInChunks(recorder, []byte(wire), chunk)

		got, ok := recorder.take("POST", "/first")
		want := []string{"Host", "Connection", "Content-Length", "sec-ch-ua-platform", "User-Agent", "Cookie", "Cookie"}
		if !ok || !reflect.DeepEqual(got, want) {
			t.Fatalf("chunk %d: first request got %v, want %v", chunk, got, want)
		}
		got, ok = recorder.take("GET", "/second?x=1")
		if !ok || !reflect.DeepEqual(got, []string{"Host", "Accept"}) {
			t.Fatalf("chunk %d: second request got %v", chunk, got)
		}
	}
}

func TestH1HeaderOrderStopsAtChunkedBodies(t *testing.T) {
	wire := "POST /upload HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nGET /\r\n0\r\n\r\n" +
		"GET /after HTTP/1.1\r\nHost: a\r\n\r\n"
	recorder := newHeaderOrderRecorder()
	recorder.observe([]byte(wire))
	if _, ok := recorder.take("POST", "/upload"); !ok {
		t.Fatal("the chunked request's own head should be recorded")
	}
	if _, ok := recorder.take("GET", "/after"); ok {
		t.Fatal("requests after a chunked body must not be recorded")
	}
	if _, ok := recorder.take("GET", "/"); ok {
		t.Fatal("chunked body bytes must not be read as a request")
	}
}

func TestPendingHeaderOrdersAreBounded(t *testing.T) {
	recorder := newHeaderOrderRecorder()
	var wire strings.Builder
	for i := 0; i < maxPendingHeaderOrders+10; i++ {
		wire.WriteString("GET /r HTTP/1.1\r\nHost: a\r\n\r\n")
	}
	recorder.observe([]byte(wire.String()))
	if len(recorder.pending) != maxPendingHeaderOrders {
		t.Fatalf("pending = %d, want %d", len(recorder.pending), maxPendingHeaderOrders)
	}
}
