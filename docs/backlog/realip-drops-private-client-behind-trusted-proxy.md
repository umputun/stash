---
worth: maybe
where: app/server/server.go:224
added: 2026-09-07
---
# private client addresses are dropped even behind a trusted proxy

`--server.trusted-proxies` decides whether forwarded headers reach `rest.RealIP`, but the
vendored `realip.Get` (`vendor/github.com/go-pkgz/rest/realip/real.go:47`) only accepts a
public address from those headers. A client on a private network behind a trusted proxy is
therefore still attributed to the proxy address in the rate limiter and the audit log, while the
README says the flag makes the real client IP visible.

Either document the public-only rule next to the flag, or replace `rest.RealIP` with a resolver
that accepts any parseable address once the peer is a trusted proxy. The second changes how
the rate limiter keys clients on private networks, so it is a design call rather than a fix.
Filed by revmux round 1 on the `security-fixes` branch as pre-existing; lowest of the deferred
items in codex's ranking.
