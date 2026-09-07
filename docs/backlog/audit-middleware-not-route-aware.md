---
worth: later
where: app/server/audit/logger.go:37
added: 2026-09-07
---
# audit middleware derives the key from the raw path instead of the matched route

Two consequences of the same mechanism. A read of `/kv/history/app/config` is recorded with key
`history/app/config`, so the audited key and the ACL key (now derived from the matched route in
`app/server/auth/middleware.go`) no longer agree and an audit query by key misses history reads.
And the middleware skips every method under `/kv/subscribe/`, meant for the long-lived GET stream,
so a PUT or DELETE of an ordinary key named `subscribe/...` is never audited at all.

Fix is the same move the token middleware made in `c1fe4be`: take the key from `r.PathValue("key")`
and decide by `r.Pattern` which route it is, skipping only the GET subscribe route. The audit
middleware is mounted on the kv group so the pattern is available. Filed by revmux round 1 on the
`security-fixes` branch; codex added the subscribe half.
