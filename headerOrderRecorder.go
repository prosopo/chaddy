package caddy_clienthello

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const (
	maxHeaderOrderNames = 128
	maxHeaderOrderBytes = 4096
	// Requests whose target or authority exceed this aren't queued, which
	// bounds what a stale entry can hold.
	maxMatchFieldBytes     = 8192
	maxPendingHeaderOrders = 32
	maxHeaderBlockBytes    = 1 << 20
	// Go's HTTP/2 server advertises SETTINGS_HEADER_TABLE_SIZE from
	// MaxDecoderHeaderTableSize, which Caddy leaves at the protocol default.
	// A client that sends a larger table size update is rejected by Go and
	// stops recording here.
	h2HeaderTableSize = 4096
	// Retained frame buffers above this are released once a frame is
	// handled, so one large header block doesn't pin memory for the life
	// of the connection.
	maxRetainedFrameBuffer = 64 << 10
)

var errHeaderOrderParse = errors.New("header order: unparseable stream")

type headerOrderEntry struct {
	method    string
	target    string
	authority string
	// order is the comma-joined names, built as they're parsed so the
	// handler forwards it without joining and no name references the
	// buffer it was parsed from.
	order []byte
	names int
}

func (e *headerOrderEntry) addName(name string) {
	if e.names == maxHeaderOrderNames || len(e.order)+len(name)+1 > maxHeaderOrderBytes {
		return
	}
	if e.names > 0 {
		e.order = append(e.order, ',')
	}
	e.order = append(e.order, name...)
	e.names++
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

	mu         sync.Mutex
	pending    []headerOrderEntry
	sequential bool
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
			r.parser = &h1HeaderOrderParser{emit: r.push}
			r.mu.Lock()
			r.sequential = true
			r.mu.Unlock()
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
	if len(entry.target) > maxMatchFieldBytes || len(entry.authority) > maxMatchFieldBytes {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.pending) == maxPendingHeaderOrders {
		r.pending = r.pending[1:]
	}
	r.pending = append(r.pending, entry)
}

// take returns the order recorded for the request with this method, target
// and authority whose recorded names the parsed header map still contains,
// or nil. The name check stops an entry left behind by a request that
// never reached the handler from being attached to a later request to the
// same URL. HTTP/1.x requests are served in order, so entries queued before
// the match can never be taken and are dropped; HTTP/2 handlers run
// concurrently, so only the match is removed.
func (r *headerOrderRecorder) take(method string, target string, authority string, header http.Header) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.pending {
		entry := &r.pending[i]
		if entry.method != method || entry.target != target || !strings.EqualFold(entry.authority, authority) || !namesPresent(entry.order, header) {
			continue
		}
		order := string(entry.order)
		if r.sequential {
			r.pending = r.pending[i+1:]
		} else {
			r.pending = append(r.pending[:i], r.pending[i+1:]...)
		}
		return order, true
	}
	return "", false
}

// namesPresent reports whether every recorded field the server keeps in
// Request.Header is there. Pseudo-headers and the fields Go moves onto
// Request are skipped, as are names Caddy deletes for containing an
// underscore and the order header itself, which is replaced.
func namesPresent(order []byte, header http.Header) bool {
	for len(order) > 0 {
		var field []byte
		field, order, _ = bytes.Cut(order, []byte{','})
		if len(field) == 0 || field[0] == ':' || bytes.IndexByte(field, '_') >= 0 {
			continue
		}
		key := http.CanonicalHeaderKey(string(field))
		switch key {
		case "Host", "Content-Length", "Transfer-Encoding", "Trailer", "Connection", HeaderOrderHeader:
			continue
		}
		if _, ok := header[key]; !ok {
			return false
		}
	}
	return true
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
	p.current.addName(field.Name)
	switch field.Name {
	case ":method":
		p.current.method = field.Value
	case ":path":
		p.current.target = field.Value
	case ":authority":
		p.current.authority = field.Value
	case "host":
		if p.current.authority == "" {
			p.current.authority = field.Value
		}
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
		if cap(p.frame) > maxRetainedFrameBuffer {
			p.frame = nil
		} else {
			p.frame = p.frame[:0]
		}
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
	p.blockBytes = 0
	if err := p.decoder.Close(); err != nil {
		return err
	}
	if p.recording && p.current.target != "" {
		p.emit(p.current)
	}
	p.recording = false
	return nil
}

type h1HeaderOrderParser struct {
	emit     func(headerOrderEntry)
	head     []byte
	bodyLeft int64
	stopped  bool
}

func (p *h1HeaderOrderParser) feed(b []byte) error {
	for len(b) > 0 && !p.stopped {
		if p.bodyLeft > 0 {
			n := min(p.bodyLeft, int64(len(b)))
			p.bodyLeft -= n
			b = b[n:]
			continue
		}
		if len(p.head) == 0 {
			if end := headEnd(b, 0); end >= 0 {
				if err := p.request(b[:end]); err != nil {
					return err
				}
				b = b[end:]
				continue
			}
		}
		searchFrom := max(0, len(p.head)-2)
		p.head = append(p.head, b...)
		end := headEnd(p.head, searchFrom)
		if end < 0 {
			if len(p.head) > maxHeaderBlockBytes {
				return errHeaderOrderParse
			}
			return nil
		}
		head := p.head[:end]
		b = p.head[end:]
		p.head = nil
		if err := p.request(head); err != nil {
			return err
		}
	}
	return nil
}

// headEnd returns the index just past the empty line ending a request head,
// or -1. Go's server accepts bare LF line endings, so both "\n\n" and
// "\n\r\n" end a head. Blank lines before a request line are not an end.
func headEnd(buf []byte, from int) int {
	start := 0
	for start < len(buf) && (buf[start] == '\r' || buf[start] == '\n') {
		start++
	}
	for i := max(from, start); i < len(buf); {
		nl := bytes.IndexByte(buf[i:], '\n')
		if nl < 0 {
			return -1
		}
		j := i + nl + 1
		if j < len(buf) && buf[j] == '\n' {
			return j + 1
		}
		if j+1 < len(buf) && buf[j] == '\r' && buf[j+1] == '\n' {
			return j + 2
		}
		if j == len(buf) || (j+1 == len(buf) && buf[j] == '\r') {
			return -1
		}
		i = j
	}
	return -1
}

// request records one request head and works out how many body bytes
// follow it. Bodies it cannot frame without decoding (chunked transfer
// coding, CONNECT tunnels) end recording for the connection. Upgraded
// connections need no special case: the bytes that follow don't parse as
// a request head, which stops recording.
func (p *h1HeaderOrderParser) request(head []byte) error {
	text := strings.TrimLeft(string(head), "\r\n")
	lines := strings.Split(strings.TrimRight(text, "\r\n"), "\n")
	requestLine := strings.SplitN(strings.TrimSuffix(lines[0], "\r"), " ", 3)
	if len(requestLine) != 3 || !strings.HasPrefix(requestLine[2], "HTTP/1.") {
		return errHeaderOrderParse
	}
	entry := headerOrderEntry{method: strings.Clone(requestLine[0]), target: strings.Clone(requestLine[1])}
	contentLength := int64(0)
	for _, line := range lines[1:] {
		line = strings.TrimSuffix(line, "\r")
		if line == "" || line[0] == ' ' || line[0] == '\t' {
			continue
		}
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			return errHeaderOrderParse
		}
		name := line[:colon]
		entry.addName(name)
		value := strings.TrimSpace(line[colon+1:])
		switch {
		case strings.EqualFold(name, "Host"):
			if entry.authority == "" {
				entry.authority = strings.Clone(value)
			}
		case strings.EqualFold(name, "Content-Length"):
			parsed, err := strconv.ParseInt(value, 10, 64)
			if err != nil || parsed < 0 {
				return errHeaderOrderParse
			}
			contentLength = parsed
		case strings.EqualFold(name, "Transfer-Encoding"):
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
