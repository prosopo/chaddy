# caddy-clienthello

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
| `X-TLS-Tcp-Opts-Flags` | uint8 | Bitfield of TCP option presence (opaque; probe-defined) |
| `X-TLS-Tcp-Opts-Order` | uint32 | Packed encoding of TCP option order (opaque; probe-defined) |
| `X-TLS-Tcp-Window` | uint16 | TCP window field from the client's SYN |

Kernel ns timestamps are boot-relative on the probe host, so only their
deltas within a single connection are meaningful.

Lookups have a 50 ms bounded timeout and are best-effort — a slow or
unreachable probe never delays the request; the extra headers are just
omitted for that request.

**Wire protocol** expected on the socket: a 12-byte big-endian request
(`client_ip[4] client_port[2] server_ip[4] server_port[2]`, server side
is ignored / for future use), and an 80-byte fixed-size response — see
`tcpProbe.go` for the exact layout. Prosopo's `ja4l-probe` binary is
the reference implementation, but any probe that speaks the same
protocol works.
