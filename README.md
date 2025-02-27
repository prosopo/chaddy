# caddy-clienthello

A caddy plugin to forward TLS `ClientHello` packets on requests as a header.

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
