# pi-cryptex

A pi extension inspired by `fastlane-plugin-cryptex`.

It now has two independent vaults with separate passwords.

## Vaults

### 1) Project vault (per project)

- File: `.cryptex/vault.v1.enc` inside your project
- Password env var: `PI_CRYPTEX_PROJECT_PASSWORD` (legacy fallback: `PI_CRYPTEX_PASSWORD`)
- Keychain service: `pi-cryptex-project`
- Use with: `cryptex_vault`, `cryptex_git_sync`

### 2) Account vault (global)

- File: `~/.pi/agent/cryptex-account.v1.enc`
- Password env var: `PI_CRYPTEX_ACCOUNT_PASSWORD`
- Keychain service: `pi-cryptex-account`
- Use with: `cryptex_pi_state`, `cryptex_account_git_sync`

## Install

### Option A: run directly

```bash
pi -e ./extensions/pi-cryptex.ts
```

### Option B: install package

```bash
pi install .
```

## Commands

- `/cryptex-password` - set project password (legacy alias)
- `/cryptex-project-password` - set/rotate project vault password
- `/cryptex-account-password` - set/rotate account vault password
- `/cryptex-info` - show vault file locations
- `/cryptex-backup-pi [profile]` - backup `~/.pi/agent` auth/login state into account vault
- `/cryptex-restore-pi [profile]` - restore auth/login state from account vault

## Tools (all prefixed)

### `cryptex_vault`

Per-project secret storage.

Actions:

- `set`
- `set_many`
- `get`
- `get_many`
- `delete`
- `list`
- `nuke`
- `rotate_password`

### `cryptex_git_sync`

Project vault git sync.

Actions:

- `push`
- `pull`

Notes:

- `push` can use current repo when `repoUrl` is omitted.
- `pull` requires `repoUrl`.

### `cryptex_pi_state`

Backup and restore selected `~/.pi/agent` files into the account vault.

Actions:

- `backup`
- `restore`

Default backup paths:

- `auth.json`
- `multi-pass.json` (for `pi-multi-pass` subscriptions, pools, chains)
- `settings.json`

Default restore paths:

- `auth.json`
- `multi-pass.json`

### `cryptex_account_git_sync`

Account vault git sync (dedicated repo).

Actions:

- `push`
- `pull`

Notes:

- `repoUrl` is required for both actions.

## Security notes

- Vault format: `aes-256-gcm` + `scrypt`.
- If `reveal=true` is used, plaintext enters model context/session history.
- Account backup includes sensitive files like `auth.json`; keep account vault password strong.
