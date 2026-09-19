---
'@platform-sec/sensitive-string-http': minor
'@platform-sec/sensitive-string-axios': minor
---

Tag the proxy a request goes through, so a host-bound credential refuses one its binding does not
name.

A proxy setting changes the machine that receives the bytes and leaves the URL untouched, so the
host check alone passed it; the corpus recorded that shape against axios, and noted that the only
place this row mentioned a proxy was an instruction for turning off the check that incidentally
covered it. `OutgoingRequest` gains `proxy`, a URL or a `host[:port]`, and the attempt context tags
it as `tags.proxy`, which core's destination binding reads as a second machine the bytes reach.

`sensitive-axios` resolves the effective proxy the way axios itself does: `config.proxy`, an agent
on `httpAgent` or `httpsAgent` that exposes its `proxy` as `https-proxy-agent` does, or the
`<scheme>_proxy` and `all_proxy` environment under `no_proxy`, with `proxy-from-env` 2.1.0's rules
restated rather than imported, since that package is axios's dependency and not this one's. An
opaque agent reads as no proxy and the README says so. got, ky, undici and fetch honour no proxy
option of their own and pass none.
