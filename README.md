# caddy-clienthello

[![ci](https://github.com/prosopo/chaddy/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/prosopo/chaddy/actions/workflows/ci.yml) [![license](https://img.shields.io/github/license/prosopo/chaddy)](LICENSE)

A caddy plugin to forward TLS `ClientHello` packets on requests as a header.

## Building locally
```bash
CGO_ENABLED=1 xcaddy build \
    --with github.com/mholt/caddy-ratelimit \
    --with github.com/prosopo/chaddy=/path/to/chaddy/repo \
```
to build caddy, which will output a bin file in your cwd. Then
```bash
./caddy run --config ./path/to/the/Caddyfile
```

## Building with xcaddy

```shell
xcaddy build \
  --with github.com/prosopo/chaddy
```

## Sample Caddyfile

Note that this enforces HTTPS (TLS).\
You can add a http_redirect to automatically redirect `http` -> `https` like shown below.

TLS `ClientHello`s do not exist on HTTP/3 connections.
No `X-TLS-ClientHello` header will be present on such requests.
I recommended to disable HTTP/3.

```caddyfile
{
    order ja3 before reverse_proxy
    client_hello {
        # Configure the maximum allowed ClientHello packet size in bytes (1-16384)
        max_client_hello_size 16384

        # Optional: path to a co-located eBPF TCP handshake probe's Unix
        # socket. When set, each request is enriched with X-TLS-* headers
        # carrying the raw wire signals from the client's SYN.
        # See "TCP probe socket" section below.
        tcp_probe_socket /var/run/ja4l/lookup.sock
    }
    servers {
        # Disable HTTP/3
        protocols h1 h2

        listener_wrappers {
            http_redirect
            client_hello
            tls
        }
    }
}

localhost {
    client_hello

    # ClientHello will be available as the `X-TLS-ClientHello` header 
    reverse_proxy http://other.service
}
```

## Details

The `X-TLS-ClientHello` header will be present on all requests that use an underlying TLS connection.
It contains the raw `ClientHello` bytes as a base64 encoded string.

If the `ClientHello` exceeds the configured `max_client_hello_size` in bytes, then the `X-TLS-ClientHello`
header will instead be set to the value `EXCEEDS_MAXIMUM_SIZE`. The maximum allowed size value should be
carefully selected as I have observed sizes ranging anywhere from `200` to `2500` bytes and possibly more.

In the case of an internal error and a missing `X-TLS-ClientHello` header, this is not representative of
a suspicious client and should not be factored in to a bot score.

This module also disables TLS session resumption globally to always retrieve a full `ClientHello`.
This is done through the usage of
[caddytls's `session_tickets/disabled`](https://caddyserver.com/docs/modules/tls#session_tickets/disabled)
config option automatically.

## TLS handshake round trip

`X-TLS-Handshake-Rtt-Us` is the time, in microseconds, from the server's handshake flight leaving Caddy to
the client's reply to it arriving: one round trip to whatever terminates TLS on the client side. It sits
alongside the TCP probe's `X-TLS-Synack-Ns` → `X-TLS-Ack-Ns`, which is one round trip to whatever opened the
TCP connection, and includes the client's handshake crypto.

The header is absent when the client's reply was already buffered before the flight was sent, since it
cannot then be timed.

## TCP probe socket

When `tcp_probe_socket` is set, chaddy performs a per-request Unix-socket
lookup against a co-located eBPF TCP handshake probe and forwards the raw
wire values from the client's SYN as HTTP headers. Every field is an
RFC 793 / RFC 9293 primitive; no fingerprints or derived metrics are
computed here.

Headers added when the probe is reachable and has a cache hit for the
current connection:

| Header | Type | Meaning |
| --- | --- | --- |
| `X-TLS-Syn-Ns` | uint64 | Kernel monotonic ns when the client SYN arrived on the WAN interface |
| `X-TLS-Synack-Ns` | uint64 | Kernel monotonic ns when the server SYN-ACK left |
| `X-TLS-Ack-Ns` | uint64 | Kernel monotonic ns when the client ACK arrived |
| `X-TLS-Observed-Ttl` | uint8 | TTL byte of the client's SYN |
| `X-TLS-Tcp-Mss` | uint16 | TCP MSS option value from the client's SYN |
| `X-TLS-Tcp-Wscale` | uint8 | TCP Window-Scale shift from the client's SYN |
| `X-TLS-Tcp-Window` | uint16 | TCP window field from the client's SYN, before scaling |
| `X-TLS-Tcp-Opts-Kinds` | uint64 | IANA kind number of each TCP option on the SYN, in wire order, one byte per option, least-significant byte first, for the first 8 options |
| `X-TLS-Tcp-Opts-Present` | uint16 | Bitfield of which TCP options were seen, including ones whose value is not recorded (MPTCP, Fast Open, MD5) |
| `X-TLS-Tcp-Opts-Count` | uint8 | Total options on the SYN, saturating at 255. More than 8 means `Opts-Kinds` is truncated |
| `X-TLS-Tcp-Tsval` | uint32 | Timestamps option TSval. Sent only when the Timestamps option was present |
| `X-TLS-Tcp-Tsecr` | uint32 | Timestamps option TSecr. Sent only when the Timestamps option was present |
| `X-TLS-Tcp-Flags` | uint8 | Raw TCP flag byte (CWR 0x80, ECE 0x40 … SYN 0x02, FIN 0x01) |
| `X-TLS-Tcp-Data-Offset-Resv` | uint8 | Data offset in the high nibble, reserved bits plus NS in the low |
| `X-TLS-Tcp-Urg-Ptr` | uint16 | TCP urgent pointer. Non-zero on a SYN is malformed |
| `X-TLS-Ip-Ident` | uint16 | IPv4 identification field |
| `X-TLS-Ip-Total-Len` | uint16 | IPv4 total length, i.e. the size class of the SYN |
| `X-TLS-Ip-Frag-Flags` | uint16 | Raw IPv4 flags plus fragment offset; DF is bit 14 |
| `X-TLS-Ip-Tos` | uint8 | DSCP in the high 6 bits, ECN codepoint in the low 2 |

`X-TLS-Tcp-Opts-Kinds` and `X-TLS-Tcp-Opts-Present` supersede the
`X-TLS-Tcp-Opts-Order` and `X-TLS-Tcp-Opts-Flags` headers of the 80-byte
record. The old order field packed 4 bits per option, which aliased MSS
onto Fast Open and Window Scale onto MD5 and could not name MPTCP at all;
the new one carries full kind numbers. They are new header names rather
than the old ones carrying new meanings, so no consumer can keep reading a
column whose contents changed underneath it.

Exactly one of the two pairs is sent, never both: the new names when the
probe served a 104-byte record, the old pair when it served an 80-byte one.
Which headers arrive is therefore also the statement of which layout the
values came from.

Kernel ns timestamps are boot-relative on the probe host, so only their
deltas within a single connection are meaningful.

Lookups have a 50 ms bounded timeout and are best-effort — a slow or
unreachable probe never delays the request; the extra headers are just
omitted for that request.

**Wire protocol** expected on the socket: a 12-byte big-endian request
(`client_ip[4] client_port[2] server_ip[4] server_port[2]`, server side
is ignored / for future use), and a 104-byte fixed-size response (or the
80-byte predecessor) — see `tcpProbe.go` for both layouts. Prosopo's `tcp-probe` binary is
the reference implementation, but any probe that speaks the same
protocol works.

Both the current 104-byte record and its 80-byte predecessor are read;
the length tells them apart with no ambiguity, so there is no need to
deploy chaddy and the probe as a pair. On the 80-byte record the fields
it does not carry are simply not sent, rather than sent as zero.

A response of any **other** size is refused, not parsed, and logged at
error with the size that arrived and the sizes this build understands.
The record carries no length or version of its own, so that comparison is
the only thing standing between a future field addition and a column full
of plausible-looking wrong integers.

## Header order

Go's HTTP server stores request headers in a map, so the order a client sent
them in is gone before any handler runs, and `reverse_proxy` re-writes them
upstream in its own sorted order. The `header_order` listener wrapper reads
the header names off the decrypted connection first and the `client_hello`
handler forwards them as `X-Header-Order`, comma-joined in arrival order:

- HTTP/2: lowercase names including pseudo-headers, e.g.
  `:method,:authority,:scheme,:path,content-length,user-agent,...`
- HTTP/1.x: names with the client's casing, e.g. `Host,Connection,User-Agent,...`
- Duplicates are kept. At most 128 names and 4 KB are recorded per request.

A client-supplied `X-Header-Order` is always removed, whether or not an order
was recorded. A recorded order is only attached to a request with the same
method, target (before any rewrite) and authority whose headers are all still
present, so an order is omitted rather than guessed when it can't be matched.
It is also omitted for HTTP/3, connections without TLS, requests after a
chunked request body on HTTP/1.1, and connections whose framing could not be
followed.

Requires Caddy v2.11+. Place the wrapper after `tls`:

```caddyfile
{
    servers {
        protocols h1 h2
        listener_wrappers {
            client_hello
            tls
            header_order {
                # Close connections that haven't finished the TLS handshake
                # and sent request bytes within this time. Default 10s.
                timeout 10s
            }
        }
    }
}

localhost {
    client_hello
    reverse_proxy http://other.service
}
```

`timeout` exists because Go's HTTP server only applies its TLS handshake and
HTTP/2 preface timeouts to an unwrapped `*tls.Conn`. Every wrapper placed after
`tls` loses them; without this option a client that connects and sends nothing
would be held open indefinitely.
