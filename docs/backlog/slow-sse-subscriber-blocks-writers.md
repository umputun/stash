---
worth: yes
where: app/server/sse/sse.go:208
added: 2026-09-07
---
# one slow SSE subscriber blocks every PUT and DELETE handler

`Service.Publish` calls `provider.Publish` synchronously from the request handler
(`app/server/api/handler.go:268`), and go-sse's `Joe` delivers to subscribers synchronously
in its dispatcher loop (`vendor/github.com/tmaxmax/go-sse/joe.go:244`): `Send` then `Flush`
on each session in turn. The SSE handler disables the write deadline for long-lived streams,
so a subscriber that stops reading makes `Flush` block on a full socket buffer, the dispatcher
stalls, every later `Publish` queues behind it, and the API handlers that publish wait at that
line indefinitely.

Options: a per-subscriber buffered channel with a drop-or-disconnect policy on overflow, a write
deadline per event rather than none, or publishing from a goroutine with a bounded queue so a
stalled dispatcher never holds an API request. Filed as pre-existing by revmux round 1 on the
`security-fixes` branch and confirmed statically by codex; ranked second of the deferred items.
