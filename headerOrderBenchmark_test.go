package caddy_clienthello

import (
	"bytes"
	"testing"

	"golang.org/x/net/http2"
)

func BenchmarkHeaderOrderH2Request(b *testing.B) {
	w := newH2Writer(&testing.T{})
	w.wire.Reset()
	for i := 0; i < b.N; i++ {
		w.headers(uint32(2*i+1), chromeFetch)
	}
	wire := w.wire.Bytes()
	header := headerFor(chromeFetch)
	recorder := &headerOrderRecorder{}
	recorder.observe([]byte(http2.ClientPreface))
	b.ReportAllocs()
	b.ResetTimer()
	for len(wire) > 0 {
		n := min(4096, len(wire))
		recorder.observe(wire[:n])
		wire = wire[n:]
		for {
			if _, ok := recorder.take("POST", "/v1/prosopo/provider/client/captcha/pow", "pronode.example", header); !ok {
				break
			}
		}
	}
}

func BenchmarkHeaderOrderH1Request(b *testing.B) {
	head := []byte("POST /v1/prosopo/provider/client/captcha/pow HTTP/1.1\r\nHost: pronode.example\r\nConnection: keep-alive\r\nContent-Length: 2\r\nsec-ch-ua-platform: \"macOS\"\r\nUser-Agent: Mozilla/5.0\r\nsec-ch-ua: \"Chromium\";v=\"152\"\r\nContent-Type: application/json\r\nsec-ch-ua-mobile: ?0\r\nAccept: */*\r\nOrigin: https://site.example\r\nSec-Fetch-Site: cross-site\r\nSec-Fetch-Mode: cors\r\nSec-Fetch-Dest: empty\r\nReferer: https://site.example/\r\nAccept-Encoding: gzip, deflate, br, zstd\r\nAccept-Language: en-GB,en;q=0.9\r\n\r\n{}")
	recorder := &headerOrderRecorder{}
	header := headerFor([]testField{{"sec-ch-ua-platform", ""}, {"user-agent", ""}, {"sec-ch-ua", ""}, {"content-type", ""}, {"sec-ch-ua-mobile", ""}, {"accept", ""}, {"origin", ""}, {"sec-fetch-site", ""}, {"sec-fetch-mode", ""}, {"sec-fetch-dest", ""}, {"referer", ""}, {"accept-encoding", ""}, {"accept-language", ""}})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		recorder.observe(head)
		if _, ok := recorder.take("POST", "/v1/prosopo/provider/client/captcha/pow", "pronode.example", header); !ok {
			b.Fatal("no order recorded")
		}
	}
}

func BenchmarkHeaderOrderH2DataFrame(b *testing.B) {
	w := newH2Writer(&testing.T{})
	w.wire.Reset()
	if err := w.framer.WriteData(1, false, bytes.Repeat([]byte("x"), 16384)); err != nil {
		b.Fatal(err)
	}
	frame := append([]byte(nil), w.wire.Bytes()...)
	recorder := &headerOrderRecorder{}
	recorder.observe([]byte(http2.ClientPreface))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		recorder.observe(frame)
	}
}
