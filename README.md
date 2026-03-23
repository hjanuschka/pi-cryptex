# pi-cryptex

A pi extension inspired by `fastlane-plugin-cryptex`.

It stores project credentials in an encrypted file:

- `.cryptex/vault.v1.enc`

## Password resolution

Master password lookup order:

1. `PI_CRYPTEX_PASSWORD`
2. macOS Keychain (`service=pi-cryptex`, account derived from project path)
3. interactive prompt (then saved to Keychain on macOS)

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

- `/cryptex-password` - create or rotate master password
- `/cryptex-info` - show vault file location
- `/cryptex-backup-pi [profile]` - backup `~/.pi/agent` auth/login state into cryptex
- `/cryptex-restore-pi [profile]` - restore auth/login state from cryptex

## Tools (all prefixed)

### `cryptex_vault`

Actions:

- `set` - set one secret
- `set_many` - set many secrets from a key/value map
- `get` - get one secret (masked by default)
- `get_many` - get many secrets (masked by default)
- `delete` - delete one secret
- `list` - list keys
- `nuke` - delete all keys
- `rotate_password` - re-encrypt vault with a new password

### `cryptex_pi_state`

Actions:

- `backup` - backup selected files from `~/.pi/agent` into cryptex
- `restore` - restore selected files from cryptex into `~/.pi/agent`

Default backup paths:

- `auth.json`
- `multi-pass.json` (for `pi-multi-pass` subscriptions, pools, chains)
- `settings.json`

Default restore paths:

- `auth.json`
- `multi-pass.json`

You can override with `paths`.

### `cryptex_git_sync`

Actions:

- `push` - commit/push vault to git (current repo or dedicated remote)
- `pull` - pull vault from dedicated remote git repo

## Example prompts

```text
Backup my pi auth and pi-multi-pass accounts to cryptex profile laptop
```

```text
Push the cryptex vault to git@github.com:me/my-cryptex-secrets.git on branch main
```

```text
Pull the cryptex vault from git@github.com:me/my-cryptex-secrets.git and restore pi state from profile laptop with overwrite=true
```

## Security notes

- The vault uses `aes-256-gcm` with `scrypt` key derivation.
- If `reveal=true` is used for reads, plaintext secrets enter model context/session history.
- `cryptex_pi_state backup` stores raw contents of files like `auth.json`; keep vault password strong.
- After restore, restart `pi` if auth or multi-pass state is not picked up immediately.
