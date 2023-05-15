# Range Header Testing Tools

These tools are for testing http `Range` headers in environments where those
headers may be removed by middleware during the http request lifecycle.

The server is `/server/main.go`, and the client is `/client/main.go`. `/gen_self_signed_cert/main.go` is a
tool used to generate a self-signed TLS certificate used for serving over https.

## Generate Self-Signed Certificates

Args:

`--host` Comma-separated hostnames and IPs to generate a certificate for. Required.
`--start-date` Creation date formatted as Jan 1 15:04:05 2011. Default now.
`--duration` Duration that certificate is valid for. Default 365 days.
`--ca` whether this cert should be its own Certificate Authority.
`--rsa-bits`  Size of RSA key to generate. Ignored if --ecdsa-curve is set. Default 2048.
`--ecdsa-curve` ECDSA curve to use to generate a key. Valid values are P224, P256 (recommended), P384, P521.
`--ed25519` Generate an Ed25519 key.

Basic Usage:

```bash
./gen_self_signed_cert --host "127.0.0.1"
2023/02/06 08:30:56 wrote cert.pem
2023/02/06 08:30:56 wrote key.pem
```

## Server

Args:

`--port` specifies the http port. Default `1709`. Required.
`--secure-port` specifies the https port. Default `443`. Required.
`--tls-cert-file` path to TLS certificate pem. Required.
`--tls-key-file` path to TLS key pem. Required.
`--verbose` logs the response body as base64 encoded string.

To use, first run the server:

```bash
./server --tls-cert-file cert.pem --tls-key-file key.pem
Serving https on : 443
Serving http on : 1709

```

When a valid request hit's the server on either port, it will log something like:

```bash
received request
query param: 'range'
responding:
content-range: bytes 2500-2599/4000
content-length: 100
status-code: 206
```

After the server is running, you can use the client to send valid range requests to the server over `http`, `https` and `http2`.

## Client

Args:

`--host` is the host running the server, required.
`--port` is the server port, required.
`--header` used to specify the request header, ie `'Range bytes=0-100'`. Only `Range`, `X-Dolt-Range` headers supported.
`--params` used to specify url encoded query params, ie `'range=bytes%3D0%2D100'`.
`--all` makes a request without range headers requesting all content from server.
`--verbose` logs the response body as base64 encoded string.
`--http2` uses http2 protocol.
`--tls-skip-verify` skips TLS verfication.
`--tls-cert-file` specifies the path to the TLS certificate pem file used with the server.
`--tls-key-file` specifies the path to the TLS key pem file used with the server.

Running client with only `--host` and `--port` arguments sends a series of `http` requests to the server&mdash;three `range` requests,
three `x-dolt-range` requests, three requests using the `range` query param, and a single request for all contents.

Client output will look something like the following on successful requests

```bash
./client --host 127.0.0.1 --port 1709
...
request:
with url query param: 'range=[bytes=2500-2599]'
response:
status: 206 Partial Content
with header: 'Accept-Ranges: bytes'
with header: 'Content-Length: 100'
with header: 'Content-Range: bytes 2500-2599/4000'
with header: 'Date: Thu, 02 Feb 2023 16:34:35 GMT'
with header: 'Content-Type: text/plain; charset=utf-8'

request:

response:
status: 200 OK
with header: 'Date: Thu, 02 Feb 2023 16:34:35 GMT'
with header: 'Content-Type: text/plain; charset=utf-8'
with header: 'Accept-Ranges: bytes'
with header: 'Content-Length: 4000'
```
