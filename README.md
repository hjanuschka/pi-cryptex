# pi-cryptex

Encrypted secrets management for pi.

`pi-cryptex` gives you a clean split between:

- project secrets (live with each repo)
- portable account state (live in your `~/.pi/agent` area)

## Vaults

### Project vault

- Path: `.cryptex/vault.v1.enc`
- Purpose: API keys, tokens, project-specific secrets
- Main tools: `cryptex_vault`, `cryptex_git_sync`
- Password env var: `PI_CRYPTEX_PROJECT_PASSWORD`

### Account vault

- Path: `~/.pi/agent/cryptex-account.v1.enc`
- Purpose: carry pi auth and multi-pass state across machines
- Main tools: `cryptex_pi_state`, `cryptex_account_git_sync`
- Password env var: `PI_CRYPTEX_ACCOUNT_PASSWORD`

## Install

### Run directly

```bash
pi -e ./extensions/pi-cryptex.ts
```

### Install as package

```bash
pi install .
```

## Recommended commands

- `/cryptex-project-password` - set or rotate project vault password
- `/cryptex-account-password` - set or rotate account vault password
- `/cryptex-info` - show vault locations
- `/cryptex-backup-pi [profile]` - backup selected `~/.pi/agent` files into account vault
- `/cryptex-restore-pi [profile]` - restore selected `~/.pi/agent` files from account vault

## Tools

### `cryptex_vault`

Manage project secrets.

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

Sync project vault with git.

Actions:

- `push`
- `pull`

Notes:

- `push` can use current repo if `repoUrl` is omitted.
- `pull` requires `repoUrl`.

### `cryptex_pi_state`

Backup and restore pi account files in the account vault.

Actions:

- `backup`
- `restore`

Default backup paths:

- `auth.json`
- `multi-pass.json`
- `settings.json`

Default restore paths:

- `auth.json`
- `multi-pass.json`

### `cryptex_account_git_sync`

Sync account vault to a dedicated private git repo.

Actions:

- `push`
- `pull`

Notes:

- `repoUrl` is required for both actions.

## Demo in this repository

This repo includes an encrypted project vault at:

- `.cryptex/vault.v1.enc`

It contains a demo key named `testkey`.

Example prompt:

```text
Show me testkey from project vault
```

## Security

- Vault encryption: `aes-256-gcm`
- Key derivation: `scrypt`
- `reveal=true` returns plaintext to model context and session history. Use only when needed.
- Account vault may contain highly sensitive auth material (`auth.json`). Use a strong account password and private git repo.
