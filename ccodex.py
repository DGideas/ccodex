#!/usr/bin/env python3
USAGE = """Switch Codex ChatGPT auth profiles.

Usage:
  ccodex.py              Show current auth status.
  ccodex.py list         List saved auth profiles.
  ccodex.py create NAME  Save current auth.json as NAME.
  ccodex.py logout       Delete current auth.json.
  ccodex.py NAME         Switch ~/.codex/auth.json to saved NAME.
"""

import base64
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional


RESERVED_NAMES = {"create", "help", "list", "logout", "status"}
PROFILE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def auth_path() -> Path:
    return Path(os.environ.get("CODEX_AUTH_FILE", "~/.codex/auth.json")).expanduser()


def store_dir() -> Path:
    return Path(os.environ.get("CODEX_AUTH_STORE_DIR", "~/bin/codex_auth")).expanduser()


def fail(message: str, code: int = 1) -> int:
    print(f"error: {message}", file=sys.stderr)
    return code


def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return data


def read_bytes(path: Path) -> bytes:
    with path.open("rb") as f:
        return f.read()


def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, path)
    finally:
        if tmp_path.exists():
            tmp_path.unlink()


def b64url_decode_json(segment: str) -> Dict[str, Any]:
    padding = "=" * (-len(segment) % 4)
    raw = base64.urlsafe_b64decode(segment + padding)
    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("JWT payload is not a JSON object")
    return data


def decode_jwt_payload(token: Any) -> Dict[str, Any]:
    if not isinstance(token, str):
        return {}
    parts = token.split(".")
    if len(parts) < 2:
        return {}
    try:
        return b64url_decode_json(parts[1])
    except Exception:
        return {}


def auth_summary(path: Path) -> Dict[str, Any]:
    data = load_json(path)
    tokens = data.get("tokens")
    if not isinstance(tokens, dict):
        tokens = {}
    payload = decode_jwt_payload(tokens.get("id_token"))
    return {
        "email": payload.get("email"),
        "account_id": tokens.get("account_id"),
        "auth_mode": data.get("auth_mode"),
        "last_refresh": data.get("last_refresh"),
    }


def profile_path(name: str) -> Path:
    return store_dir() / f"{name}.json"


def validate_profile_name(name: str) -> Optional[str]:
    if name in RESERVED_NAMES:
        return f"'{name}' is reserved"
    if not PROFILE_NAME_RE.match(name):
        return "profile name must match [A-Za-z0-9][A-Za-z0-9._-]*"
    return None


def profile_files() -> List[Path]:
    directory = store_dir()
    if not directory.exists():
        return []
    return sorted(
        path
        for path in directory.iterdir()
        if path.is_file() and path.suffix == ".json" and not path.name.startswith(".")
    )


def save_current_as(name: str) -> Path:
    current = auth_path()
    if not current.exists():
        raise FileNotFoundError(f"{current} does not exist")
    target = profile_path(name)
    atomic_write(target, read_bytes(current))
    return target


def find_active_profile() -> Optional[str]:
    current = auth_path()
    if not current.exists():
        return None
    try:
        current_bytes = read_bytes(current)
    except OSError:
        return None
    for path in profile_files():
        try:
            if read_bytes(path) == current_bytes:
                return path.stem
        except OSError:
            continue
    return None


def format_value(value: Any) -> str:
    if value is None:
        return "-"
    return str(value)


def print_profile_line(name: str, path: Path, active: Optional[str]) -> None:
    marker = "*" if name == active else " "
    try:
        summary = auth_summary(path)
        email = format_value(summary["email"])
        account_id = format_value(summary["account_id"])
        last_refresh = format_value(summary["last_refresh"])
        print(f"{marker} {name:<16} {email:<28} {account_id:<36} {last_refresh}")
    except Exception as exc:
        print(f"{marker} {name:<16} <invalid: {exc}>")


def cmd_status() -> int:
    active = find_active_profile()
    current = auth_path()
    print(f"auth_file: {current}")
    print(f"store_dir: {store_dir()}")
    print(f"active_profile: {active or '-'}")

    if current.exists():
        try:
            summary = auth_summary(current)
        except Exception as exc:
            return fail(f"could not read current auth: {exc}")
        print(f"email: {format_value(summary['email'])}")
        print(f"account_id: {format_value(summary['account_id'])}")
        print(f"auth_mode: {format_value(summary['auth_mode'])}")
        print(f"last_refresh: {format_value(summary['last_refresh'])}")
    else:
        print("email: -")
        print("account_id: -")
        print("auth_mode: -")
        print("last_refresh: -")

    profiles = [path.stem for path in profile_files()]
    print(f"stored_profiles: {', '.join(profiles) if profiles else '-'}")
    return 0


def cmd_list() -> int:
    files = profile_files()
    if not files:
        print(f"no profiles stored in {store_dir()}")
        return 0

    active = find_active_profile()
    print(f"{' ':1} {'name':<16} {'email':<28} {'account_id':<36} last_refresh")
    for path in files:
        print_profile_line(path.stem, path, active)
    return 0


def cmd_create(args: List[str]) -> int:
    if len(args) != 1:
        return fail("usage: ccodex.py create NAME")
    name = args[0]
    error = validate_profile_name(name)
    if error:
        return fail(error)

    try:
        target = save_current_as(name)
        summary = auth_summary(target)
    except Exception as exc:
        return fail(str(exc))

    print(f"saved profile '{name}' -> {target}")
    print(f"email: {format_value(summary['email'])}")
    print(f"account_id: {format_value(summary['account_id'])}")
    return 0


def cmd_logout() -> int:
    current = auth_path()
    if not current.exists():
        print(f"already logged out; {current} does not exist")
        return 0

    try:
        current.unlink()
    except Exception as exc:
        return fail(f"could not delete {current}: {exc}")

    print(f"deleted auth_file: {current}")
    return 0


def cmd_switch(name: str) -> int:
    error = validate_profile_name(name)
    if error:
        return fail(error)

    source = profile_path(name)
    if not source.exists():
        return fail(f"profile '{name}' does not exist; run 'ccodex.py list'")

    try:
        summary = auth_summary(source)
        target = auth_path()
        target.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(target, read_bytes(source))
    except Exception as exc:
        return fail(str(exc))

    print(f"switched Codex auth to '{name}'")
    print(f"auth_file: {auth_path()}")
    print(f"email: {format_value(summary['email'])}")
    print(f"account_id: {format_value(summary['account_id'])}")
    return 0


def print_help() -> None:
    print(USAGE.strip())


def main(argv: List[str]) -> int:
    if not argv:
        return cmd_status()

    command = argv[0]
    if command in {"-h", "--help", "help"}:
        print_help()
        return 0
    if command == "status":
        if len(argv) != 1:
            return fail("usage: ccodex.py status")
        return cmd_status()
    if command == "list":
        if len(argv) != 1:
            return fail("usage: ccodex.py list")
        return cmd_list()
    if command == "create":
        return cmd_create(argv[1:])
    if command == "logout":
        if len(argv) != 1:
            return fail("usage: ccodex.py logout")
        return cmd_logout()
    if len(argv) == 1:
        return cmd_switch(command)
    return fail("usage: ccodex.py [list|status|create NAME|logout|NAME]")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
