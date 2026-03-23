# pi-cryptex

Encrypted secrets and account portability for pi.

`pi-cryptex` gives you two vaults with separate passwords:

- a **per-project vault** for app/repo secrets
- an **account vault** for your pi login state and multi-pass config

This keeps project secrets in the project, and your personal pi identity portable across machines.

## Why two vaults?

### Project vault (`.cryptex/vault.v1.enc`)

Use this for things that belong to one codebase:

- API keys for that project
- deployment tokens for that repo
- environment-specific secrets used by that team

Typical behavior:

- committed with the project repo (encrypted only)
- shared with teammates who know the project vault password
- rotated independently from your personal pi account credentials

### Account vault (`~/.pi/agent/cryptex-account.v1.enc`)

Use this for things that belong to **you**, not one repo:

- `auth.json` (pi provider logins)
- `multi-pass.json` (pi-multi-pass subscriptions/pools/chains)
- optional account-level settings backup

Typical behavior:

- synced to a separate private repo (for example `hjanuschka/pi-accounts`)
- restored when setting up a new machine
- protected with a separate account vault password

## Install

### Run directly from this repo

```bash
pi -e ./extensions/pi-cryptex.ts
```

### Install as package

```bash
pi install npm:pi-cryptex
```

## Passwords

Project vault password:

- env var: `PI_CRYPTEX_PROJECT_PASSWORD`
- legacy fallback: `PI_CRYPTEX_PASSWORD`

Account vault password:

- env var: `PI_CRYPTEX_ACCOUNT_PASSWORD`

On macOS, passwords are stored in Keychain when entered interactively.

## Commands

- `/cryptex-project-password` - set/rotate project vault password
- `/cryptex-account-password` - set/rotate account vault password
- `/cryptex-info` - show both vault locations
- `/cryptex-backup-pi [profile]` - backup selected `~/.pi/agent` files into account vault
- `/cryptex-restore-pi [profile]` - restore selected `~/.pi/agent` files from account vault

## Tools

### `cryptex_vault`

Per-project secret manager.

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

- `push` can use current repo if `repoUrl` is omitted.
- `pull` requires `repoUrl`.

### `cryptex_pi_state`

Backup/restore account state in the account vault.

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

Sync account vault with a dedicated private git repo.

Actions:

- `push`
- `pull`

Note: `repoUrl` is required for both actions.

## Sample workflows

## 1) Project secret workflow

### Save secret

Prompt:

```text
Store STRIPE_SECRET in project vault
```

Explicit tool call shape:

```json
{
  "action": "set",
  "key": "STRIPE_SECRET",
  "value": "sk_live_..."
}
```

### Read secret (masked)

```json
{
  "action": "get",
  "key": "STRIPE_SECRET"
}
```

### Read secret (plaintext)

```json
{
  "action": "get",
  "key": "STRIPE_SECRET",
  "reveal": true
}
```

### Push encrypted project vault

```json
{
  "action": "push"
}
```

(or with dedicated repo)

```json
{
  "action": "push",
  "repoUrl": "git@github.com:your-org/your-project-secrets.git",
  "branch": "main"
}
```

## 2) Account migration workflow

### Backup current machine state

```json
{
  "action": "backup",
  "profile": "laptop"
}
```

### Push account vault to private repo

```json
{
  "action": "push",
  "repoUrl": "git@github.com:hjanuschka/pi-accounts.git",
  "branch": "main"
}
```

### On a new machine: pull + restore

Pull:

```json
{
  "action": "pull",
  "repoUrl": "git@github.com:hjanuschka/pi-accounts.git",
  "branch": "main"
}
```

Restore:

```json
{
  "action": "restore",
  "profile": "laptop",
  "overwrite": true
}
```

## Demo in this repository

This repo includes an encrypted project vault:

- `.cryptex/vault.v1.enc`

It contains a demo key `testkey`.

Try:

```text
Show me testkey from project vault
```

## Security notes

- Encryption: `aes-256-gcm`
- Key derivation: `scrypt`
- `reveal=true` sends plaintext into model context/session history. Use only when necessary.
- Account vault includes sensitive auth material (`auth.json`). Use a strong password and a private git repo.
