# Remote Git as Durable History Home

## Overview
- make a git remote the durable home for key history, so the local checkout at `--git.path` can be lost (container without a volume) and rebuilt from the remote
- the database (external PostgreSQL, or SQLite on a kept volume) stays the store of record for values; git stays a history log
- exactly one stash instance writes to a remote branch; no multi-instance protocol, no merge strategy
- new mode is enabled by `--git.url`; without it the current `--git.remote` / `--git.push` behavior is unchanged
- two existing defects are fixed in both modes because the new mode depends on them:
  - DB write and git commit happen under different locks, so concurrent writes can land in opposite order in DB and git, and restore brings back the older value
  - a format-only change (same value, new format) cannot be committed: format lives only in the commit message and go-git refuses an empty commit
- two cleanups folded in: Store-only helpers become methods, and `validateKey` rejects keys under the top-level `.git` directory and keys with control characters (needed once history trusts the `key:` line)

## Context (from discovery)
- `app/git/git.go` - Store: repo init (`initRepo`, `ensureBranch`, `createNewRepo`), Commit/Delete, Push/Pull, History/GetRevision, ReadAll (walks working files), `getFileFormat` and `rawHistory` use `LogOptions.FileName`
- `app/git/service.go` - Service wraps Storer: Commit/Delete then inline pull+push when `pushSync`
- `app/server/server.go:61`, `app/server/api/handler.go:35`, `app/server/web/handler.go:85` - three GitService interfaces with Commit/Delete/History/GetRevision; server passes one `deps.Git` to both api and web
- write paths calling DB then git: `api/handler.go` set (234, 257) and delete (~287-303); `web/keys.go` create, update (SetWithVersion), delete (439), revision restore (568-576)
- `app/main.go` - flags (`Git` group, line 29), `initGitService`, `gitConfig`, `runRestore` (Checkout + ReadAll + clear + insert), `rawStore` (uncached) at line 157
- go-git v5.19.2: `Repository.Merge` supports fast-forward only; `LogOptions.PathFilter` available
- mocks via moq in `app/git/mocks`, `app/server/mocks`, `app/server/api/mocks`, `app/server/web/mocks`

## Development Approach
- **testing approach**: TDD - write the failing test first, run it to confirm it fails, then implement
- complete each task fully before moving to the next
- make small, focused changes
- **CRITICAL: every task MUST include new/updated tests** for code changes in that task
  - tests are not optional - they are a required part of the checklist
  - write unit tests for new functions/methods
  - write unit tests for modified functions/methods
  - add new test cases for new code paths
  - update existing test cases if behavior changes
  - tests cover both success and error scenarios
- **CRITICAL: all tests must pass before starting next task** - no exceptions
- **CRITICAL: update this plan file when scope changes during implementation**
- run tests after each change
- maintain backward compatibility: no `--git.url` means today's behavior, existing repositories keep working, existing flags keep their meaning

## Code-Quality Rules (HARD — verify against every task before marking complete)

These rules supplement project CLAUDE.md and are NOT optional. They are the gate for marking any task complete. If a rule is violated, the task is not done — refactor, re-test, then mark complete.

**Signatures (hard limits):**
- No function or method has 4+ parameters. `ctx context.Context` does not count toward the budget. If you need 4+, use an option struct (e.g., `type fooOpts struct { ... }`).
- No function or method has 4+ return values. Split the function into two single-purpose ones, or return a struct.
- Multiple adjacent same-type parameters (`oldLine, newLine int`) are a swap hazard — review whether they belong on a struct.

**Methods vs standalone helpers (project rule, hard):**
- If a function is called only from methods of a single struct, it MUST be a method on that struct. Calling pattern decides, not field access.
- Standalone helpers are reserved for: (a) constructors and entry points (`Parse...`, `New...`, `Decorate...`), (b) utilities shared by multiple unrelated types or by both standalone functions AND methods, (c) tiny cross-cutting helpers.
- Before adding any standalone helper, mentally walk its callers. If every caller is a method of one type, make the helper a method on that type.

**Visibility (private by default, hard):**
- Lowercase identifiers by default. Only export when an out-of-package caller exists.
- Exception (per CLAUDE.md): methods called by other structs in the same package CAN be exported for inter-component API clarity. This is the only exception. It does not extend to types, functions, constants, or variables.
- Before exporting any new identifier, grep for cross-package callers. If none, lowercase it.

**Comments (default: none, hard):**
- Default to writing no comments. Add one only when the WHY is non-obvious (a hidden invariant, a workaround, behavior that would surprise a reader).
- Exported items get godoc comments starting with the name. Unexported items get lowercase non-godoc comments — or no comment at all.
- Never describe WHAT the code does when the code itself is self-evident. Never write multi-paragraph comments on routine helpers.

**Per-task gate (before marking ANY checkbox complete):**
1. Formatter runs clean (`~/.claude/format.sh` or `gofmt -s -w` + `goimports -w`).
2. `golangci-lint run --max-issues-per-linter=0 --max-same-issues=0` reports zero issues.
3. `go test ./... -race` passes.
4. Scan the new code for the four rule classes above. Specifically:
   - Grep new function signatures: `grep -nE '^func.*\(.*,.*,.*,.*\)' app/<path>/*.go` — any hit with 4+ comma-separated params (excluding `ctx`) is a violation. Same for the return-value side.
   - For every new standalone helper, `grep -rn 'helperName(' --include='*.go'` and confirm at least one caller is NOT a method of a single type. If all callers are methods of one type, convert.
   - For every new exported identifier, grep cross-package. If no out-of-package hit, lowercase it.
5. Only after 1–4 pass: mark the task complete.

If a previous task shipped a violation (spotted later by user, reviewer, or yourself): fix it in the next commit BEFORE starting the next task. Do not let violations accumulate.

## Testing Strategy
- **unit tests**: required for every task; git tests use a local bare repository as the remote (`git.PlainInit(dir, true)`, file path URL), no network
- **e2e tests**: no UI changes; run `make e2e` in the acceptance task to confirm history, revision view and restore in the UI still work
- concurrency: the ordering fix gets a `-race` test that runs concurrent writes to one key and asserts DB value equals the git HEAD value

## Progress Tracking
- mark completed items with `[x]` immediately when done
- add newly discovered tasks with ➕ prefix
- document issues/blockers with ⚠️ prefix
- update plan if implementation deviates from original scope
- keep plan in sync with actual work done

## Solution Overview

**Contract of `--git.url` mode** (goes into README as written):
- values live in the database; a DB write succeeds even when the git commit or push fails
- the local checkout can be deleted; on start stash clones it back from `--git.url`
- on start, before serving, stash compares the database with the last local commit and commits the differences as sync commits authored by stash, then pushes; once that push succeeds the remote matches every database key git can represent (keys inside the top-level `.git` directory stay database-only)
- pushes run in the background: once when the server starts, after each commit, on a fixed interval while commits are pending, and once on shutdown after in-flight requests finish; a failed push is retried, a rejected push (remote moved) is logged as an error and never forced, because only one stash instance may write to the branch
- an in-flight push holds up writes for up to 10s per attempt, so during a remote outage writes slow down; this is a bound per push attempt, not a total latency ceiling for a write
- the remote branch must exist or the remote must be empty; a remote holding other branches only (a repository created with a README on `main` while stash uses `master`) is refused at startup with an error naming the branch
- commits that never reached the remote before the checkout was lost are gone; the next startup sync restores the current values but not those intermediate history steps
- a lost database must be restored before starting stash; started against an empty database, the sync commits deletion of every key (earlier commits still hold the data)
- the secrets key must be kept outside the instance; secrets in git are encrypted with it, and stash refuses to start in this mode when the database holds secrets it cannot decrypt

**Key decisions:**
- ordering: `git.Service.Record` runs the DB write callback and the local commit under one mutex owned by Service. Server already passes one Service to api and web, so one lock covers all handlers. Push runs outside that lock
- format: stays in the commit message only, no new files (a sidecar file would collide with existing keys: key `a` needs `a.fmt`, key `a.fmt/b` needs a directory `a.fmt`). A format-only change becomes an empty commit (`AllowEmptyCommits`). Readers find a key's commits by the `key:` line every stash commit message carries since the git feature was added, instead of filtering by file path, so empty commits are seen. Old repos read correctly; an old binary reading a repo written by the new version may show the previous format for a key whose last change was format-only
- startup sync is a `git.Store` method that takes the wanted state as `map[string]KeyValue`; `main.go` builds that map from the uncached store, so the git package does not depend on `store`
- in url mode the remote name defaults to `origin`; `--git.remote`, when set, overrides the name. The default is written to `opts.Git.Remote` right after flag parsing when `--git.url` is set, so both `gitConfig` and `runRestore`'s existing `opts.Git.Remote != ""` pull check see it
- history now trusts the `key:` line, so `validateKey` rejects control characters in keys (a key with a newline could forge a `key:` or `format:` line for another key); such keys stay database-only like keys inside `.git`. This guards new writes only; commits already written by earlier versions are not rewritten

## Technical Details

**Flags** (`app/main.go` Git group):
- `--git.url` / `STASH_GIT_URL` - remote repository URL; enables remote-history mode; `stash server` fails if it is set without `--git.enabled` (the check lives in `runServer` only; `stash restore` never required `--git.enabled` and keeps working with `--git.url`)
- unchanged: `--git.path`, `--git.branch`, `--git.remote`, `--git.push`, `--git.ssh-key`
- `--git.push` together with `--git.url` is accepted and has no extra effect (url mode always pushes, in the background)

**git.Config** gains `URL string`.

**SSH remotes** (`git@host:repo.git`, `ssh://user@host/repo.git`; https and file paths also work):
- `--git.ssh-key` loads the key for clone, push and pull; without it go-git falls back to ssh-agent
- the SSH user comes from the URL; the hard-coded `"git"` user in `NewPublicKeysFromFile` is used only when the URL has none
- host keys are verified against `SSH_KNOWN_HOSTS`, `~/.ssh/known_hosts` or `/etc/ssh/ssh_known_hosts`; a container needs one of them (documented, no flag to disable verification)
- passphrase-protected keys stay unsupported

**Repository open in url mode** (`initRepo`):
1. path has a repo: verify the remote named `Remote` points to `URL` (create it if missing, error on a different URL); check out the branch ref with `Force` (restore leaves HEAD detached, and a non-forced checkout fails on a dirty worktree), then hard-reset worktree and index to the local branch head (keeps unpushed commits, clears an interrupted commit)
2. path has no repo: `PlainClone` with branch and auth; an empty remote (`transport.ErrEmptyRemoteRepository`) falls back to `createNewRepo` plus adding the remote; a non-empty remote without the branch fails with an error naming the branch and the URL
- the SSH auth builder is a `Store` method (`(s *Store) auth() (transport.AuthMethod, error)`) shared by clone, push and pull

**Format-only changes** (both modes):
- Commit sets `AllowEmptyCommits` only when the value file is unchanged and the format differs from the key's current format; when both are unchanged Commit returns nil without committing (today go-git returns `ErrEmptyCommit`, which handlers log as a spurious WARN)
- `rawHistory` and `getFileFormat` walk the log without `FileName` and select commits whose message `key:` line equals the key (new `(s *Store) parseKeyFromCommit`); the value at each selected commit is read from that commit's tree
- `getFileFormat` takes the key instead of the file path
- bulk readers (ReadAll, Sync) build a key-to-format map in one newest-first log walk, first hit per key, instead of one walk per key
- commits without a `key:` line (hand edits on the remote) do not appear in History; documented
- `getFileContentAtCommit(commit, filePath, key, hash)` shrinks to `(commit, filePath)`: `key` and `hash` only feed two debug logs, which use `filePath` and `commit.Hash` instead
- GetRevision at a format-only commit returns the unchanged value with the new format
- no repository layout change

**Tree-based ReadAll** (both modes): reads blobs from the HEAD commit tree instead of the working directory, skipping symlinks and non-`.val` entries as today. A `(s *Store) headTree()` reader returns raw blobs keyed by key; ReadAll decodes all of them, Sync decodes only keys present on both sides. `runRestore` keeps Checkout + ReadAll, so restore results are unchanged.

**Ordering** (`app/git/service.go`):
```go
// Record runs write, which applies a change to the database and returns the matching commit
// request, then commits it to git, all under one lock. Returns write's error; git failures are logged.
func (s *Service) Record(write func() (CommitRequest, error)) error
```
- `CommitRequest.Operation == "delete"` routes to `Storer.Delete`
- `Record` returns the callback's error unchanged, so the web update path still finds `*store.ConflictError` with `errors.AsType`
- web `commitToGit` (5 parameters) is removed; its three call sites build the `CommitRequest` inside the `write` callback
- GitService interfaces in server, api and web: `Commit` and `Delete` replaced by `Record`
- api and web handlers each get a `write(fn)` method that calls `Git.Record` or, with git disabled, `fn` directly

**Wiring** (`app/main.go`):
- `initGitService` becomes `initGitStore` and returns the concrete `*git.Store` (nil when git is disabled)
- `runServer` builds the Service from it, in url mode runs Sync, starts `Service.Run` with its own worker context, and only then sets `server.Deps.Git`; `Deps.Git` is assigned only for a non-nil Service, because a nil `*git.Service` stored in the interface field is not nil and the handlers' `h.Git != nil` checks would pass
- shutdown order in url mode: server ctx cancelled, `Server.Run` returns only after the HTTP drain finishes, then `runServer` cancels the worker context and waits for `Service.Run` to return after its bounded final push

**Server shutdown** (`app/server/server.go`, both modes): `Server.Run` derives a local cancellable context, and waits for its shutdown goroutine (SSE and HTTP drain, bounded by `ShutdownTimeout`) before returning. Today it returns when `ListenAndServe` stops, while handlers may still be running. When `ListenAndServe` fails on its own (port in use), Run cancels the local context first so the goroutine exits, then returns the bind error promptly. Waiting for the bounded drain is the only change in non-url mode
- `runServer` cancels and waits for the worker on every return path, the bind-error path included

**Background push** (url mode, `app/git/service.go`):
- `NewService(st Storer, opts ServiceOpts)` replaces the `pushSync bool` parameter:
```go
// ServiceOpts configures when Service pushes to the remote.
type ServiceOpts struct {
	PushSync     bool          // pull and push inline after each commit (--git.push)
	PushInterval time.Duration // when > 0, push in the background on each commit and on this interval; PushSync is ignored
}
```
- url mode sets `PushInterval` to 1 minute and never `PushSync`, so `--git.push` with `--git.url` does not bring back the inline pull
- `Store.PushContext(ctx)` and the matching `Storer` method; regenerate `app/git/mocks`
- after a commit in async mode Service signals a buffered channel (size 1, non-blocking send)
- `(s *Service) Run(ctx context.Context)` makes one push attempt at start (covers startup sync commits and commits left unpushed by an earlier process; a failure leaves the push pending), then pushes on signal, and on `PushInterval` ticks only while a push is pending (a commit since the last successful push, or the last push failed); returns immediately when `PushInterval` is not positive; on ctx done it makes one final push with a fresh 10s context and returns after it; started from `runServer`
- every new exported type, field and method gets a short godoc
- url mode pushes with a fixed 10s timeout set by the Service worker; `Store.mu` is held for the push, so writes can wait up to that long during an outage (stated in the contract); legacy `Store.Push` keeps no deadline
- go-git has no sentinel for non-fast-forward (`remote.go` returns `fmt.Errorf("non-fast-forward update: ...")`), so `(s *Service) isRejected(err) bool` matches that text; a rejection logs `[ERROR] remote branch moved, another writer on <branch>?`, other failures log `[WARN]`

**Startup sync** (`app/git/git.go`):
```go
// SyncResult describes what Sync changed.
type SyncResult struct {
	Updated int // keys committed with a new value or format
	Deleted int // keys removed because the database no longer has them
}

// Sync commits the differences between want (every git-representable database key) and the HEAD tree,
// one commit per key, authored by DefaultAuthor.
func (s *Store) Sync(want map[string]KeyValue) (SyncResult, error)
```
- `main.go` builds `want` from `rawStore.List` + `rawStore.GetWithFormat` (decrypted secrets, opaque ZK)
- any DB read error aborts startup, including a secret that cannot be decrypted because `--secrets.key` is missing; a partial `want` would make the sync incomplete, so stash refuses to start instead
- deletion decisions use key presence only: a key in HEAD but absent from `want` is deleted without decoding its value, so stale encrypted secrets are removed too
- for keys present on both sides, the HEAD value is decoded and compared with `want`; a decode failure aborts startup
- Sync itself drops keys that `validateKey` rejects, from `want` and from the HEAD deletion candidates alike (old repos can hold keys written by earlier versions that the stricter check now refuses; Sync leaves those files alone; rejected means `.git` or `.` path parts or control characters, see Task 2) and logs one warning listing them; they can never be stored in git, stay DB-only and cannot be recovered from it. This differs from an unreadable supported key, which still aborts startup because it is unknown data, not a known exclusion
- so the guarantee is: once a push succeeds, the remote matches every database key git can represent
- the unreadable-secret abort applies to url mode only; without `--git.url` there is no startup sync
- Sync runs before the HTTP listener starts; it does not push itself, the worker's initial attempt does, so an unreachable remote never blocks startup

## What Goes Where
- **Implementation Steps**: code, tests, README/CLAUDE.md/site docs in this repo
- **Post-Completion**: deployment wiring outside this repo

## Implementation Steps

### Task 1: Convert Store-only helpers to methods (no behavior change)

**Files:**
- Modify: `app/git/git.go`, `app/git/git_test.go`

- [x] confirm by grep that `keyToPath`, `pathToKey`, `parseFormatFromCommit` and `parseOperationFromCommit` have only `Store` methods as production callers; a helper with any other production caller stays standalone
- [x] convert the confirmed ones to `Store` methods; their tests call them through a `Store` value
- [x] run tests - must pass before next task

### Task 2: Reject keys git cannot store safely (both modes)

**Files:**
- Modify: `app/git/git.go`, `app/git/git_test.go`

- [x] write failing tests: `validateKey` rejects `.git/x`, `.git/hooks/x`, `./.git/x` (web create accepts it, `NormalizeKey` keeps `./`), `.GIT/x`, nested `a/.git/x`, `.` parts (`a/./b` aliased key `a/b`), and keys with `\n`, `\r`, NUL, tab or DEL; still accepts bare `.git` and `a/.git` (stored as `.git.val`, an ordinary file), `.github/x`, `.gitignore`
- [x] in `validateKey`, reject control characters, then reject any non-final part of `keyToPath(key)` equal to `.` or to `.git` case-insensitively; this mirrors go-git's own worktree rules (`worktree_fs.go` `validPath`), which today refuse these keys only at staging, after the value file is written
- [x] the database still accepts such keys (no API change); git commit for them fails with the validation error and is logged as today
- [x] run tests - must pass before next task
- ⚠️ the plan first said nested `a/.git/x` stays allowed; go-git already refuses it at staging, so it is rejected up front. go-git's HFS/NTFS look-alikes of `.git` (internal package, not importable) are not mirrored and still fail at staging

### Task 3: Record format-only changes (both modes)

**Files:**
- Modify: `app/git/git.go`
- Modify: `app/git/git_test.go`

- [x] write failing tests: format-only change produces a commit; History shows the new format at that entry; GetRevision and ReadAll return it; an unchanged value and format returns nil with no commit; a repo built with the oldest message shape (`git_test.go` fixtures) reads the same history and formats
- [x] Commit allows an empty commit when only the format changed and returns nil when nothing changed
- [x] `rawHistory` and `getFileFormat` (now taking the key) select commits by the message `key:` line via `(s *Store) parseKeyFromCommit` instead of `FileName`; ReadAll uses a key-to-format map from one log walk
- [x] shrink `getFileContentAtCommit` to `(commit, filePath)`
- [x] run tests - must pass before next task
- ➕ review fix: one storage identity `(s *Store) storedKey` (clean `keyToPath(key)`, strip `.val`) used by history, `getFileFormat` and `keyFormats`, since go-git stages the cleaned path (`a//b` and `a/b` share a file; `a/.` is stored as `a/..val`, not `a`); `validateKey` also rejects empty path parts
- ⚠️ compatibility exception: History for a DB key with `//` now returns an invalid-key error; before it returned an empty list because the file-path filter never matched the cleaned path, so no usable history is lost and the DB still accepts such keys

### Task 4: One lock over DB write and git commit (both modes)

**Files:**
- Modify: `app/git/service.go`, `app/git/service_test.go`
- Modify: `app/server/server.go`, `app/server/api/handler.go`, `app/server/web/handler.go`, `app/server/web/keys.go`
- Modify: their `_test.go` files; regenerate the GitService mocks in `app/server/api/mocks` and `app/server/web/mocks`

- [ ] write failing deterministic regression test: with a moq `Storer` whose `Commit` blocks writer A on a channel, writer B's `Record` callback does not run until A's commit returns (fails today because nothing orders them)
- [ ] add `Service.Record`; delete routes to `Storer.Delete`; git failures logged inside Record
- [ ] replace `Commit`/`Delete` with `Record` in the three GitService interfaces; add `write(fn)` to api and web handlers; convert api set/delete and web create/update/delete/revision restore; remove web `commitToGit`
- [ ] update handler tests for the new interface (success, DB error returns error and no commit, git error still returns success, web update conflict still renders the conflict form)
- [ ] run tests - must pass before next task

### Task 5: Clone from `--git.url`, tree-based ReadAll, reset to local head

**Files:**
- Modify: `app/git/git.go`, `app/git/git_test.go`
- Modify: `app/main.go`, `app/main_test.go`

- [ ] write failing tests against a local bare remote: missing path clones; empty remote initializes and adds the remote; non-empty remote without the branch errors naming the branch; existing repo with matching remote opens; different remote URL errors; dirty worktree after a simulated interrupted commit is reset while unpushed commits stay; detached HEAD after restore is back on the branch
- [ ] add `Config.URL`, url-mode branch in `initRepo`
- [ ] write failing tests for SSH user selection: scp-style, `ssh://` with and without a user
- [ ] `(s *Store) auth()` takes the user from the URL (falls back to `git`), used by clone, push and pull
- [ ] write failing tests for ReadAll: uncommitted worktree changes are ignored, symlinks and non-`.val` entries skipped
- [ ] `(s *Store) headTree()` and ReadAll on top of it; restore tests still pass unchanged
- [ ] write failing tests: `stash server` with `--git.url` and without `--git.enabled` fails; `stash restore --git.url` with a missing path clones, then restores
- [ ] add `--git.url` flag, the server-only validation, and the `origin` default written to `opts.Git.Remote` after flag parsing
- [ ] run tests - must pass before next task

### Task 6: Startup sync from the database

**Files:**
- Modify: `app/git/git.go`, `app/git/git_test.go`
- Modify: `app/main.go`, `app/main_test.go`

- [ ] write failing tests for `Store.Sync`: changed value, new key, deleted key, deleted secret without decoding, format-only change, secret and ZK compared by plaintext/opaque bytes, undecodable present key returns an error, keys rejected by `validateKey` are skipped with a warning and not deleted from git, no-op when equal
- [ ] implement `Store.Sync` and `SyncResult` on top of `headTree` and the key-to-format map
- [ ] `initGitService` becomes `initGitStore` returning `*git.Store`; `runServer` builds the Service and assigns `Deps.Git` only when non-nil
- [ ] in `runServer` url mode: build `want` from `rawStore`, run Sync, then start serving; log the result
- [ ] integration tests in `main_test.go`: populated DB and stale local repo, local HEAD matches DB after startup; DB secret without `--secrets.key`, url-mode startup fails with a clear error while non-url startup is unaffected
- [ ] run tests - must pass before next task

### Task 7: Background push in url mode

**Files:**
- Modify: `app/git/service.go`, `app/git/service_test.go`
- Modify: `app/git/git.go`, `app/git/git_test.go`; regenerate `app/git/mocks`
- Modify: `app/server/server.go`, `app/server/server_test.go`
- Modify: `app/main.go`, `app/main_test.go`

- [ ] write failing tests for `Store.PushContext`: pushes to the bare remote; respects a cancelled context
- [ ] add `Store.PushContext` and the `Storer` method; regenerate `app/git/mocks`
- [ ] write failing tests: `Run` makes an initial push at start; startup push fails with zero later writes, the next tick succeeds and the remote catches up; async mode pushes after a commit without inline pull; an idle tick with nothing pending does not push; non-fast-forward rejection is logged as an error and not forced; legacy `PushSync` keeps inline pull+push; `PushSync` with `PushInterval` set stays async; `Run` with zero interval returns at once; cancelling ctx makes one final push and `Run` returns only after it
- [ ] `ServiceOpts`, signal channel, pending tracking, `Service.Run(ctx)` with the initial attempt, the 10s push timeout and the final push, `(s *Service) isRejected`; legacy push path unchanged
- [ ] write failing tests for `Server.Run`: it returns only after an in-flight request finishes (bounded by `ShutdownTimeout`); with the port already taken it returns the bind error promptly
- [ ] `Server.Run` uses a local cancellable context and waits for its shutdown goroutine before returning
- [ ] `runServer` url mode: start `Run` with a worker context; on every return from `Server.Run`, including the bind error, cancel it and wait for `Run` to return; test the occupied-port path in `main_test.go`
- [ ] integration tests in `main_test.go`: populated DB and stale remote, remote head matches DB after startup; unreachable remote with an existing local repo, server still starts; a key written through the API after startup reaches the bare remote; a write in flight at shutdown is committed and pushed before the process exits
- [ ] run tests - must pass before next task

### Task 8: Verify acceptance criteria
- [ ] verify all requirements from Overview are implemented
- [ ] verify backward compatibility: no `--git.url` behaves as before (existing tests unchanged in intent), repos written before this change read the same history and formats
- [ ] run full test suite: `make test`
- [ ] run e2e tests: `make e2e`
- [ ] verify test coverage meets project standard (80%)

### Task 9: [Final] Update documentation
- [ ] README.md: `--git.url` flag row, "Remote Sync" section rewritten with the contract from Solution Overview; fix the "manual resolution instructions" sentence, which the code never produced
- [ ] README: SSH remote setup (key, ssh-agent fallback, known_hosts requirement in containers), the branch requirement for a non-empty remote, and that hand edits on the remote without a `key:` line do not show in History
- [ ] site/ docs mirror of the README git section, if present
- [ ] CLAUDE.md: git storage notes (format-only empty commits and key-line history selection, Record lock, url mode)
- [ ] move this plan to `docs/plans/completed/`

## Post-Completion
*Items requiring manual intervention or external systems - no checkboxes, informational only*

**Manual verification:**
- run stash with `--git.url` against a real remote (GitHub or Gitea over SSH), delete `--git.path`, restart, confirm history in the UI is intact
- simulate a remote outage, write keys, restore the remote, confirm the background push catches up

**Deployment:**
- container deployments set `STASH_GIT_URL` and an SSH key; `--git.path` may live on ephemeral storage

---
Smells pre-check: 6 items fixed before save (initGitService returns the concrete store and Deps.Git is set only when non-nil; web commitToGit removed; ServiceOpts single async switch with interval guard; getFileContentAtCommit shrunk to two parameters; Sync author parameter dropped; godoc and mock list corrected)
