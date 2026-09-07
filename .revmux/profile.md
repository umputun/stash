# stash review profile

## What this software is

Stash is a single-binary key-value configuration service: an HTTP API and an HTMX web UI over
SQLite or PostgreSQL, with optional prefix-based auth (users with sessions, API tokens, a public
token), an encrypted secrets vault keyed by path segment, client-side zero-knowledge values the
server never decrypts, git-backed history with a restore command, SSE change notifications, an
audit log, and client SDKs in Go, Python, TypeScript, Java and Rust. It is run by one operator for
a team, usually behind a reverse proxy, often on a small container. It is not a distributed store
and does not try to be one.

## What a real failure looks like here

- A principal reads, writes, lists, subscribes to or learns the name of a key its ACL does not
  grant. Secrets paths need an explicit grant; a wildcard never covers them.
- A secret value leaves the server in plaintext by any path other than an authorized read:
  git history, a remote, an SSE event, a log line, an error message, a conflict view.
- Data loss on `restore`: anything that clears the database and then fails to put a key back.
- A request from one caller that blocks or exhausts the server for everyone: a lock held across
  crypto or I/O, unbounded concurrent argon2 derivations, a stalled SSE subscriber.
- Stored content executing in a browser on the stash origin.
- A change that silently alters what an existing deployment does: an ACL contract, a default,
  a header the proxy relied on. Deliberate contract changes are listed in the round's scope.

## Blast radius

The database is the source of truth; git, cache and SSE are secondary and log warnings on failure.
Auth is enforced server-side in the token middleware for `/kv/*` and in each web handler for the
UI; the list, history and subscribe handlers filter per key themselves. Group middleware in
routegroup runs after mux matching, so `r.Pattern` and path values are available there. SQLite
runs with a single connection and an application mutex; PostgreSQL relies on MVCC. The SDKs
share the `$ZK$` envelope format and argon2 parameters with `lib/stash/zk.go`; a change to either
side breaks the other four.

## Reporting bar

Major or above is reserved for the failures above in executable code, with a concrete input and
the line that mishandles it. Style, naming, comment volume and test organisation are minor at
most and usually not worth a finding: the linter roster in `.golangci.yml` (gocritic, gosec,
revive, testifylint, wrapcheck and forty others) already enforces them and CI runs it. A doc or
comment finding is major only when following the text would make a later run wrong. Finding
nothing is a valid answer; do not manufacture a finding to fill a report.

## Deliberate conventions

- Consumer-side interfaces, concrete return types, moq-generated mocks in a `mocks` subpackage
  (in-package when a cycle forces it). Hand-written mocks are a defect.
- One test file per source file, table-driven with testify; test names state the behavior.
- Lowercase comments that state a constraint or a non-obvious reason, never what the code shows.
- Errors wrapped with `fmt.Errorf("context: %w", err)`; `log.Printf` with a level prefix.
- Write permission implies read. The trusted-proxies list defaults to empty. SSE events are
  filtered per subscriber. Keys with `secrets` as a path segment are secrets by construction.
- Secrets are committed to the git history encrypted under a `$ENC$` envelope; older plaintext
  commits are left as they are and are not a finding.
- Private helpers by default; export only for an out-of-package caller.
