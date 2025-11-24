# Git Support

## Overview

Add optional git versioning for all KV changes. Every set/delete operation commits to a local git repository, with optional push to remote. Includes a restore command to recover the database from any git revision.

This provides:
- Full audit trail of all configuration changes
- Ability to restore to any point in history
- Optional remote backup via git push
- Config-as-code workflow (changes tracked in git)

## Key Features

- **Storage format**: Path-based with `.val` suffix (`app/config/db` → `.history/app/config/db.val`)
- **Git method**: Pure Go implementation using go-git library (no external git binary required)
- **CLI structure**: Subcommands (`stash server`, `stash restore`)
- **Remote**: Optional - works with local-only repos

## Configuration

### Shared Options (same env for both commands)

| Flag | Env | Default | Description |
|------|-----|---------|-------------|
| `--db` | `STASH_DB` | `stash.db` | database URL |
| `--git.path` | `STASH_GIT_PATH` | `.history` | local git repo path |
| `--git.branch` | `STASH_GIT_BRANCH` | `master` | git branch |
| `--git.remote` | `STASH_GIT_REMOTE` | | remote name (optional) |

### Server-Only Options

| Flag | Env | Default | Description |
|------|-----|---------|-------------|
| `--git.enabled` | `STASH_GIT_ENABLED` | `false` | enable git tracking |
| `--git.push` | `STASH_GIT_PUSH` | `false` | auto-push after commits |
| `--server.*` | `STASH_SERVER_*` | | server options |
| `--auth.*` | `STASH_AUTH_*` | | auth options |

### Restore-Only Options

| Flag | Env | Default | Description |
|------|-----|---------|-------------|
| `--rev` | | (required) | revision to restore (commit/tag/branch) |

### Docker Usage

```yaml
# docker-compose.yml
services:
  stash:
    image: stash
    environment:
      - STASH_DB=/data/stash.db
      - STASH_GIT_PATH=/data/.history
      - STASH_GIT_ENABLED=true
    volumes:
      - stash-data:/data

# Restore works with same env vars:
# docker exec stash stash restore --rev=abc123
```

---

## Implementation Plan

### Iteration 1: CLI Restructure [COMPLETED]

- [x] Restructure main.go to use go-flags subcommands
- [x] Create ServerCmd with all options (db, git.*, server.*, auth.*)
- [x] Create RestoreCmd stub with restore-specific options
- [x] Move existing run() logic to server command Execute()
- [x] Verify existing main_test.go passes
- [x] Add tests for ServerCmd and RestoreCmd

### Iteration 2: Git Package Foundation [COMPLETED]

- [x] Create `app/git/git.go` with Git struct and Config
- [x] Implement Init/Open repository
- [x] Implement Commit (write file, stage, commit with metadata)
- [x] Implement Push (with error handling)
- [x] Implement Pull
- [x] Implement Checkout
- [x] Implement ReadAll (walk repo, read .val files)
- [x] Add `app/git/git_test.go` with unit tests for all operations

### Iteration 3: Server Integration [COMPLETED]

- [x] Define GitStore interface in server package
- [x] Add git config to server.Config
- [x] Wire git into server startup (optional, based on --git.enabled)
- [x] Call git.Commit() after successful Set operations
- [x] Call git.Delete() after successful Delete operations
- [x] Generate mocks with moq
- [x] Manual integration test verified working

### Iteration 4: Restore Command [COMPLETED]

- [x] Implement restore command Execute()
- [x] Pull from remote if configured
- [x] Checkout specified revision
- [x] Clear all keys from database
- [x] Walk repo, read all .val files, insert into DB
- [x] Print summary message and exit
- [x] Add integration tests for restore flow

### Iteration 5: Documentation [COMPLETED]

- [x] Update README.md with git configuration section
- [x] Update CLAUDE.md with new CLI structure
- [x] Add usage examples

---

## Technical Details

### File Structure

```
app/
├── main.go              # CLI with subcommands
├── main_test.go         # Integration tests
├── git/
│   ├── git.go           # Git operations
│   └── git_test.go      # Unit tests
├── server/
│   ├── server.go        # + GitStore interface
│   ├── handlers.go      # + git calls after DB ops
│   └── mocks/
│       └── gitstore.go  # Generated mock
└── store/
    └── ...              # Unchanged
```

### Git Repository Structure

```
.history/
├── .git/
├── app/
│   └── config/
│       ├── db.val       # content: "postgres://..."
│       └── redis.val    # content: "redis://..."
└── service/
    └── timeout.val      # content: "30s"
```

### Commit Message Format

```
set app/config/db

timestamp: 2024-01-15T10:30:00Z
operation: set
key: app/config/db
```

### Error Handling

- **Push failures**: Log WARN, continue (don't fail API request)
- **Commit failures**: Log ERROR, continue (DB is source of truth)
- **Restore failures**: Exit with error code and message

---

## Files to Create/Modify

**New files:**
- `app/git/git.go` - Git operations using go-git
- `app/git/git_test.go` - Unit tests

**Modified files:**
- `app/main.go` - Subcommand restructure
- `app/main_test.go` - Update for subcommands
- `app/server/server.go` - GitStore interface, wiring
- `app/server/handlers.go` - Git calls after DB operations
- `README.md` - Git configuration docs
- `CLAUDE.md` - Updated structure

---

## Out of Scope

- Bidirectional sync (git → DB on pull)
- Web UI for git history viewing
- Conflict resolution for concurrent changes
- Git authentication configuration (relies on system git config)
