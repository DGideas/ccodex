# ccodex

Manually switch Codex auth profiles.

`ccodex` is a small Python script for saving and switching between multiple Codex ChatGPT authentication profiles. It works by copying the current Codex `auth.json` into named profile files, then restoring a selected profile back to Codex's active auth file.

## Requirements

- Python 3.8+
- Codex CLI using the default auth file at `~/.codex/auth.json`

## Installation

Clone or copy this repository, then make the script executable:

```sh
chmod +x ccodex.py
```

Optional: add the repository directory to your `PATH`, or create a shell alias:

```sh
alias ccodex="$HOME/bin/ccodex.py"
```

## Usage

Show current auth status:

```sh
ccodex.py
```

List saved profiles:

```sh
ccodex.py list
```

Save the current Codex auth file as a named profile:

```sh
ccodex.py create work
```

Delete a saved profile:

```sh
ccodex.py delete work
```

Switch Codex to a saved profile:

```sh
ccodex.py work
```

Delete the current active Codex auth file:

```sh
ccodex.py logout
```

Show help:

```sh
ccodex.py help
```

## Profile Storage

By default, `ccodex` reads and writes:

- Active Codex auth file: `~/.codex/auth.json`
- Saved profile directory: `~/bin/codex_auth`

Saved profiles are stored as JSON files named after the profile:

```text
~/bin/codex_auth/work.json
~/bin/codex_auth/personal.json
```

Profile names must match:

```text
[A-Za-z0-9][A-Za-z0-9._-]*
```

The following names are reserved:

```text
create
delete
help
list
logout
status
```

## Environment Variables

Override the active auth file:

```sh
CODEX_AUTH_FILE=/path/to/auth.json ccodex.py status
```

Override the saved profile directory:

```sh
CODEX_AUTH_STORE_DIR=/path/to/profiles ccodex.py list
```

## Security Notes

Codex `auth.json` contains authentication credentials. Treat every saved profile file as sensitive:

- Do not commit `auth.json` or files under `codex_auth/`.
- Keep the profile directory private.
- Remove active credentials with `ccodex.py logout` when needed.

Add this to `.gitignore` before publishing a repository that contains local profiles:

```gitignore
codex_auth/
auth.json
```

## License

WTFPL

The software is provided as is. The author is not responsible for any consequences.
