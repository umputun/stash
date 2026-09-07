---
worth: yes
where: app/main.go:308
added: 2026-09-07
---
# restore clears the database and then skips malformed ZK secrets

`runRestore` reads the repository, refuses on an undecryptable or keyless secret, clears the
database, and inserts every key. A secret-path value that starts with `$ZK$` but is not a valid
envelope passes `ReadAll` (nothing decodes it) and is then rejected by `Store.Set` with
`ErrInvalidZKPayload` at `app/store/db.go:431`, which the restore loop only logs and skips. The
command exits zero with that key missing from the restored database.

Same shape as the keyless-restore refusal added in `4b3c538`: validate `kvPairs` for ZK envelopes
with `stash.IsValidZKPayload` before clearing, and refuse the restore naming the key. Surfaced by
revmux rounds 1 and 2 on the `security-fixes` branch, filed as pre-existing; codex ranked it first
of the deferred items.
