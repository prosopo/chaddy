package caddy_clienthello

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const (
	maxHeaderOrderNames    = 128
	maxPendingHeaderOrders = 128
	maxHeaderBlockBytes    = 1 << 20
	// Go's HTTP/2 server advertises no SETTINGS_HEADER_TABLE_SIZE, so the
	// client's encoder is bound by the protocol default.
	h2HeaderTableSize = 4096
)

var errHeaderOrderParse = errors.New("header order: unparseable stream")

type headerOrderEntry struct {
	method string
	target string
	names  []string
}

type headerOrderParser interface {
	feed(b []byte) error
}

// headerOrderRecorder watches the plaintext bytes a server reads from one
// connection and queues the header order of each request it sees. Parsing
// happens inside Read, before the HTTP server's own parser receives the
// bytes, so an entry is always queued before its handler runs. Any parse
// failure stops recording for the connection; it never affects the
// connection itself.
type headerOrderRecorder struct {
	parseMu sync.Mutex
	sniff   []byte
	parser  headerOrderParser
	failed  bool

	mu      sync.Mutex
	pending []headerOrderEntry
}

func newHeaderOrderRecorder() *headerOrderRecorder {
	return &headerOrderRecorder{}
}

func (r *headerOrderRecorder) observe(b []byte) {
	r.parseMu.Lock()
	defer r.parseMu.Unlock()
	if r.failed {
		return
	}
	if r.parser == nil {
		r.sniff = append(r.sniff, b...)
		prefixLen := min(len(r.sniff), len(http2.ClientPreface))
		if string(r.sniff[:prefixLen]) == http2.ClientPreface[:prefixLen] {
			if len(r.sniff) < len(http2.ClientPreface) {
				return
			}
			r.parser = newH2HeaderOrderParser(r.push)
			b = r.sniff[len(http2.ClientPreface):]
		} else {
			r.parser = newH1HeaderOrderParser(r.push)
			b = r.sniff
		}
		r.sniff = nil
	}
	if err := r.parser.feed(b); err != nil {
		r.failed = true
		r.parser = nil
	}
}

func (r *headerOrderRecorder) push(entry headerOrderEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.pending) == maxPendingHeaderOrders {
		r.pending = r.pending[1:]
	}
	r.pending = append(r.pending, entry)
}

// take returns the oldest queued order for a request with this method and
// target. HTTP/2 requests on one connection can reach handlers in any
// order, so entries are matched rather than popped.
func (r *headerOrderRecorder) take(method string, target string) ([]string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, entry := range r.pending {
		if entry.method == method && entry.target == target {
			r.pending = append(r.pending[:i], r.pending[i+1:]...)
			return entry.names, true
		}
	}
	return nil, false
}

const (
	h2FrameHeaderLen    = 9
	h2FrameHeaders      = 0x1
	h2FrameContinuation = 0x9
	h2FlagEndHeaders    = 0x4
	h2FlagPadded        = 0x8
	h2FlagPriority      = 0x20
)

type h2HeaderOrderParser struct {
	emit    func(headerOrderEntry)
	decoder *hpack.Decoder

	frame      []byte
	skip       int
	blockOpen  bool
	blockID    uint32
	blockBytes int
	recording  bool
	lastStream uint32
	current    headerOrderEntry
}

func newH2HeaderOrderParser(emit func(headerOrderEntry)) *h2HeaderOrderParser {
	p := &h2HeaderOrderParser{emit: emit}
	p.decoder = hpack.NewDecoder(h2HeaderTableSize, p.onField)
	p.decoder.SetMaxStringLength(maxHeaderBlockBytes)
	return p
}

func (p *h2HeaderOrderParser) onField(field hpack.HeaderField) {
	if !p.recording {
		return
	}
	if len(p.current.names) < maxHeaderOrderNames {
		p.current.names = append(p.current.names, field.Name)
	}
	switch field.Name {
	case ":method":
		p.current.method = field.Value
	case ":path":
		p.current.target = field.Value
	}
}

func (p *h2HeaderOrderParser) feed(b []byte) error {
	for len(b) > 0 {
		if p.skip > 0 {
			n := min(p.skip, len(b))
			p.skip -= n
			b = b[n:]
			continue
		}
		if len(p.frame) < h2FrameHeaderLen {
			n := min(h2FrameHeaderLen-len(p.frame), len(b))
			p.frame = append(p.frame, b[:n]...)
			b = b[n:]
			if len(p.frame) < h2FrameHeaderLen {
				return nil
			}
		}
		length := int(p.frame[0])<<16 | int(p.frame[1])<<8 | int(p.frame[2])
		frameType := p.frame[3]
		if frameType != h2FrameHeaders && frameType != h2FrameContinuation {
			if p.blockOpen {
				return errHeaderOrderParse
			}
			p.frame = p.frame[:0]
			p.skip = length
			continue
		}
		if p.blockBytes+length > maxHeaderBlockBytes {
			return errHeaderOrderParse
		}
		want := h2FrameHeaderLen + length
		n := min(want-len(p.frame), len(b))
		p.frame = append(p.frame, b[:n]...)
		b = b[n:]
		if len(p.frame) < want {
			return nil
		}
		if err := p.headerFrame(p.frame); err != nil {
			return err
		}
		p.frame = p.frame[:0]
	}
	return nil
}

func (p *h2HeaderOrderParser) headerFrame(frame []byte) error {
	frameType := frame[3]
	flags := frame[4]
	streamID := binary.BigEndian.Uint32(frame[5:9]) & 0x7fffffff
	payload := frame[h2FrameHeaderLen:]
	if streamID == 0 {
		return errHeaderOrderParse
	}

	if frameType == h2FrameContinuation {
		if !p.blockOpen || streamID != p.blockID {
			return errHeaderOrderParse
		}
	} else {
		if p.blockOpen {
			return errHeaderOrderParse
		}
		if flags&h2FlagPadded != 0 {
			if len(payload) < 1 || int(payload[0]) > len(payload)-1 {
				return errHeaderOrderParse
			}
			payload = payload[1 : len(payload)-int(payload[0])]
		}
		if flags&h2FlagPriority != 0 {
			if len(payload) < 5 {
				return errHeaderOrderParse
			}
			payload = payload[5:]
		}
		p.blockOpen = true
		p.blockID = streamID
		p.blockBytes = 0
		p.recording = streamID > p.lastStream
		if p.recording {
			p.lastStream = streamID
			p.current = headerOrderEntry{}
		}
	}

	p.blockBytes += len(payload)
	if _, err := p.decoder.Write(payload); err != nil {
		return err
	}
	if flags&h2FlagEndHeaders == 0 {
		return nil
	}
	p.blockOpen = false
	if err := p.decoder.Close(); err != nil {
		return err
	}
	if p.recording {
		p.emit(p.current)
		p.recording = false
	}
	return nil
}

type h1HeaderOrderParser struct {
	emit     func(headerOrderEntry)
	head     []byte
	bodyLeft int64
	stopped  bool
}

func newH1HeaderOrderParser(emit func(headerOrderEntry)) *h1HeaderOrderParser {
	return &h1HeaderOrderParser{emit: emit}
}

var h1HeadEnd = []byte("\r\n\r\n")

func (p *h1HeaderOrderParser) feed(b []byte) error {
	for len(b) > 0 && !p.stopped {
		if p.bodyLeft > 0 {
			n := min(p.bodyLeft, int64(len(b)))
			p.bodyLeft -= n
			b = b[n:]
			continue
		}
		searchFrom := max(0, len(p.head)-len(h1HeadEnd)+1)
		p.head = append(p.head, b...)
		end := bytes.Index(p.head[searchFrom:], h1HeadEnd)
		if end < 0 {
			if len(p.head) > maxHeaderBlockBytes {
				return errHeaderOrderParse
			}
			return nil
		}
		headLen := searchFrom + end + len(h1HeadEnd)
		head := p.head[:headLen]
		b = p.head[headLen:]
		p.head = nil
		if err := p.request(head); err != nil {
			return err
		}
	}
	return nil
}

// request records one request head and works out how many body bytes
// follow it. Bodies it cannot frame without decoding (chunked transfer
// coding, protocol upgrades, CONNECT) end recording for the connection.
func (p *h1HeaderOrderParser) request(head []byte) error {
	lines := strings.Split(strings.TrimLeft(string(head), "\r\n"), "\r\n")
	requestLine := strings.SplitN(lines[0], " ", 3)
	if len(requestLine) != 3 || !strings.HasPrefix(requestLine[2], "HTTP/1.") {
		return errHeaderOrderParse
	}
	entry := headerOrderEntry{method: requestLine[0], target: requestLine[1]}
	contentLength := int64(0)
	for _, line := range lines[1:] {
		if line == "" || line[0] == ' ' || line[0] == '\t' {
			continue
		}
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			return errHeaderOrderParse
		}
		name := line[:colon]
		if len(entry.names) < maxHeaderOrderNames {
			entry.names = append(entry.names, name)
		}
		value := strings.TrimSpace(line[colon+1:])
		switch {
		case strings.EqualFold(name, "Content-Length"):
			parsed, err := strconv.ParseInt(value, 10, 64)
			if err != nil || parsed < 0 {
				return errHeaderOrderParse
			}
			contentLength = parsed
		case strings.EqualFold(name, "Transfer-Encoding"), strings.EqualFold(name, "Upgrade"):
			p.stopped = true
		}
	}
	if entry.method == "CONNECT" {
		p.stopped = true
	}
	p.emit(entry)
	p.bodyLeft = contentLength
	return nil
}
