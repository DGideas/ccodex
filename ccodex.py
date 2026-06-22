#!/usr/bin/env python3

import argparse
import base64
import binascii
import json
import os
import re
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any


RESERVED_NAMES = {"create", "delete", "help", "list", "logout", "status", "update"}
COMMAND_NAMES = RESERVED_NAMES
PROFILE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


@dataclass
class AuthSummary(object):
    email: str | None
    account_id: str | None
    auth_mode: str | None
    last_refresh: str | None


@dataclass
class SaveResult(object):
    profile_name: str
    profile_path: Path
    summary: AuthSummary


@dataclass
class SwitchResult(object):
    profile_name: str
    auth_file: Path
    summary: AuthSummary
    updated_profile: str | None


@dataclass
class DeleteResult(object):
    profile_name: str
    profile_path: Path
    was_active: bool


@dataclass
class LogoutResult(object):
    auth_file: Path
    updated_profile: str | None
    was_logged_in: bool


def auth_path() -> Path:
    return Path(os.environ.get("CODEX_AUTH_FILE", "~/.codex/auth.json")).expanduser()


def store_dir() -> Path:
    return Path(os.environ.get("CODEX_AUTH_STORE_DIR", "~/bin/codex_auth")).expanduser()


def profile_path(name: str) -> Path:
    return store_dir() / f"{name}.json"


def active_profile_marker_path() -> Path:
    return store_dir() / ".active_profile"


def fail(message: str, code: int = 1) -> int:
    print(f"error: {message}", file=sys.stderr)
    return code


def ensure_private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)


def ensure_store_dir() -> None:
    ensure_private_directory(store_dir())


def load_json(path: Path) -> dict[str, Any]:
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


def b64url_decode_json(segment: str) -> dict[str, Any]:
    padding = "=" * (-len(segment) % 4)
    raw = base64.urlsafe_b64decode(segment + padding)
    data = json.loads(raw.decode("utf-8"))

    if not isinstance(data, dict):
        raise ValueError("JWT payload is not a JSON object")

    return data


def decode_jwt_payload(token: Any) -> dict[str, Any]:
    if not isinstance(token, str):
        return {}

    parts = token.split(".")
    if len(parts) < 2:
        return {}

    try:
        return b64url_decode_json(parts[1])
    except (binascii.Error, json.JSONDecodeError, UnicodeDecodeError, ValueError):
        return {}


def auth_summary(path: Path) -> AuthSummary:
    data = load_json(path)
    tokens = data.get("tokens")
    if not isinstance(tokens, dict):
        tokens = {}

    payload = decode_jwt_payload(tokens.get("id_token"))

    return AuthSummary(
        email=string_or_none(payload.get("email")),
        account_id=string_or_none(tokens.get("account_id")),
        auth_mode=string_or_none(data.get("auth_mode")),
        last_refresh=string_or_none(data.get("last_refresh")),
    )


def string_or_none(value: Any) -> str | None:
    if value is None:
        return None

    return str(value)


def validate_profile_name(name: str) -> str | None:
    if name in RESERVED_NAMES:
        return f"'{name}' is reserved"

    if not PROFILE_NAME_RE.match(name):
        return "profile name must match [A-Za-z0-9][A-Za-z0-9._-]*"

    return None


def require_valid_profile_name(name: str) -> None:
    error = validate_profile_name(name)
    if error:
        raise ValueError(error)


def profile_files() -> list[Path]:
    directory = store_dir()
    if not directory.exists():
        return []

    return sorted(
        path
        for path in directory.iterdir()
        if path.is_file() and path.suffix == ".json" and not path.name.startswith(".")
    )


def read_active_profile_marker() -> str | None:
    path = active_profile_marker_path()
    if not path.exists():
        return None

    name = path.read_text(encoding="utf-8").strip()
    if not name or validate_profile_name(name):
        return None

    return name


def write_active_profile_marker(name: str) -> None:
    require_valid_profile_name(name)
    ensure_store_dir()
    atomic_write(active_profile_marker_path(), f"{name}\n".encode("utf-8"))


def clear_active_profile_marker() -> None:
    try:
        active_profile_marker_path().unlink()
    except FileNotFoundError:
        pass


def identity_key(summary: AuthSummary) -> str | None:
    if summary.account_id:
        return f"account_id:{summary.account_id}"

    if summary.email:
        return f"email:{summary.email}"

    return None


def same_auth_identity(left: Path, right: Path) -> bool:
    try:
        left_key = identity_key(auth_summary(left))
        right_key = identity_key(auth_summary(right))
    except (OSError, ValueError, UnicodeDecodeError):
        return False

    return bool(left_key and left_key == right_key)


def profile_with_same_bytes(current: Path) -> str | None:
    current_bytes = read_bytes(current)

    for path in profile_files():
        try:
            if read_bytes(path) == current_bytes:
                return path.stem
        except OSError:
            continue

    return None


def unique_profile_with_same_identity(current: Path) -> str | None:
    current_key = identity_key(auth_summary(current))
    if not current_key:
        return None

    matches = []
    for path in profile_files():
        try:
            if identity_key(auth_summary(path)) == current_key:
                matches.append(path.stem)
        except (OSError, ValueError, UnicodeDecodeError):
            continue

    if len(matches) == 1:
        return matches[0]

    return None


def find_active_profile() -> str | None:
    current = auth_path()
    if not current.exists():
        return None

    marker = read_active_profile_marker()
    if marker and profile_path(marker).exists() and same_auth_identity(current, profile_path(marker)):
        return marker

    same_bytes = profile_with_same_bytes(current)
    if same_bytes:
        return same_bytes

    return unique_profile_with_same_identity(current)


def save_current_as(name: str, force: bool) -> SaveResult:
    require_valid_profile_name(name)

    current = auth_path()
    if not current.exists():
        raise FileNotFoundError(f"{current} does not exist")

    target = profile_path(name)
    if target.exists() and not force:
        raise FileExistsError(f"profile '{name}' already exists; use 'ccodex.py create --force {name}'")

    summary = auth_summary(current)
    ensure_store_dir()
    atomic_write(target, read_bytes(current))
    write_active_profile_marker(name)

    return SaveResult(profile_name=name, profile_path=target, summary=summary)


def update_profile_from_current(name: str) -> SaveResult:
    require_valid_profile_name(name)

    current = auth_path()
    if not current.exists():
        raise FileNotFoundError(f"{current} does not exist")

    target = profile_path(name)
    if not target.exists():
        raise FileNotFoundError(f"profile '{name}' does not exist; run 'ccodex.py list'")

    summary = auth_summary(current)
    ensure_store_dir()
    atomic_write(target, read_bytes(current))
    write_active_profile_marker(name)

    return SaveResult(profile_name=name, profile_path=target, summary=summary)


def update_active_profile_from_current() -> SaveResult | None:
    active = find_active_profile()
    if not active:
        return None

    return update_profile_from_current(active)


def switch_profile(name: str) -> SwitchResult:
    require_valid_profile_name(name)

    source = profile_path(name)
    if not source.exists():
        raise FileNotFoundError(f"profile '{name}' does not exist; run 'ccodex.py list'")

    source_bytes = read_bytes(source)
    summary = auth_summary(source)
    updated = update_active_profile_from_current()

    if updated and updated.profile_name == name:
        source_bytes = read_bytes(source)
        summary = auth_summary(source)

    target = auth_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    atomic_write(target, source_bytes)
    write_active_profile_marker(name)

    updated_profile = None
    if updated:
        updated_profile = updated.profile_name

    return SwitchResult(
        profile_name=name,
        auth_file=target,
        summary=summary,
        updated_profile=updated_profile,
    )


def delete_profile(name: str) -> DeleteResult:
    require_valid_profile_name(name)

    target = profile_path(name)
    if not target.exists():
        raise FileNotFoundError(f"profile '{name}' does not exist; run 'ccodex.py list'")

    active_marker = read_active_profile_marker()
    target.unlink()

    was_active = active_marker == name
    if was_active:
        clear_active_profile_marker()

    return DeleteResult(profile_name=name, profile_path=target, was_active=was_active)


def logout_current_auth() -> LogoutResult:
    current = auth_path()
    if not current.exists():
        clear_active_profile_marker()
        return LogoutResult(auth_file=current, updated_profile=None, was_logged_in=False)

    updated = update_active_profile_from_current()
    current.unlink()
    clear_active_profile_marker()

    updated_profile = None
    if updated:
        updated_profile = updated.profile_name

    return LogoutResult(auth_file=current, updated_profile=updated_profile, was_logged_in=True)


def format_value(value: Any) -> str:
    if value is None:
        return "-"

    return str(value)


def print_summary(summary: AuthSummary) -> None:
    print(f"email: {format_value(summary.email)}")
    print(f"account_id: {format_value(summary.account_id)}")


def print_profile_line(name: str, path: Path, active: str | None) -> None:
    marker = "*" if name == active else " "

    try:
        summary = auth_summary(path)
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        print(f"{marker} {name:<16} <invalid: {exc}>")
        return

    email = format_value(summary.email)
    account_id = format_value(summary.account_id)
    last_refresh = format_value(summary.last_refresh)
    print(f"{marker} {name:<16} {email:<28} {account_id:<36} {last_refresh}")


def cmd_status() -> int:
    active = find_active_profile()
    current = auth_path()

    print(f"auth_file: {current}")
    print(f"store_dir: {store_dir()}")
    print(f"active_profile: {active or '-'}")

    if current.exists():
        summary = auth_summary(current)
        print(f"email: {format_value(summary.email)}")
        print(f"account_id: {format_value(summary.account_id)}")
        print(f"auth_mode: {format_value(summary.auth_mode)}")
        print(f"last_refresh: {format_value(summary.last_refresh)}")
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


def cmd_create(args: argparse.Namespace) -> int:
    result = save_current_as(args.name, args.force)

    print(f"saved profile '{result.profile_name}' -> {result.profile_path}")
    print_summary(result.summary)
    return 0


def cmd_update(args: argparse.Namespace) -> int:
    name = args.name or find_active_profile()
    if not name:
        raise ValueError("could not determine active profile; use 'ccodex.py update NAME'")

    result = update_profile_from_current(name)

    print(f"updated profile '{result.profile_name}' <- {auth_path()}")
    print_summary(result.summary)
    return 0


def cmd_delete(args: argparse.Namespace) -> int:
    result = delete_profile(args.name)

    print(f"deleted profile '{result.profile_name}' -> {result.profile_path}")
    return 0


def cmd_logout() -> int:
    result = logout_current_auth()

    if not result.was_logged_in:
        print(f"already logged out; {result.auth_file} does not exist")
        return 0

    if result.updated_profile:
        print(f"updated profile '{result.updated_profile}' <- {result.auth_file}")
    print(f"deleted auth_file: {result.auth_file}")
    return 0


def cmd_switch(name: str) -> int:
    result = switch_profile(name)

    if result.updated_profile:
        print(f"updated profile '{result.updated_profile}' <- previous auth_file")
    print(f"switched Codex auth to '{result.profile_name}'")
    print(f"auth_file: {result.auth_file}")
    print_summary(result.summary)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ccodex.py",
        description="Switch Codex ChatGPT auth profiles.",
        epilog="Short form:\n  ccodex.py NAME    Save active profile, then switch auth.json to NAME.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("status", help="show current auth status")
    subparsers.add_parser("list", help="list saved auth profiles")

    create_parser = subparsers.add_parser("create", help="save current auth.json as NAME")
    create_parser.add_argument("name")
    create_parser.add_argument("--force", action="store_true", help="overwrite an existing profile")

    update_parser = subparsers.add_parser("update", help="save current auth.json back to a profile")
    update_parser.add_argument("name", nargs="?")

    delete_parser = subparsers.add_parser("delete", help="delete a saved auth profile")
    delete_parser.add_argument("name")

    subparsers.add_parser("logout", help="save active profile, then delete current auth.json")

    return parser


def dispatch_command(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    if args.command is None or args.command == "status":
        return cmd_status()

    if args.command == "list":
        return cmd_list()

    if args.command == "create":
        return cmd_create(args)

    if args.command == "update":
        return cmd_update(args)

    if args.command == "delete":
        return cmd_delete(args)

    if args.command == "logout":
        return cmd_logout()

    parser.error(f"unknown command: {args.command}")
    return 2


def main(argv: list[str]) -> int:
    parser = build_parser()

    try:
        if argv == ["help"]:
            parser.print_help()
            return 0

        if argv and argv[0] not in COMMAND_NAMES and not argv[0].startswith("-"):
            if len(argv) != 1:
                return fail("usage: ccodex.py [list|status|create [--force] NAME|update [NAME]|delete NAME|logout|NAME]")
            return cmd_switch(argv[0])

        args = parser.parse_args(argv)
        return dispatch_command(args, parser)
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        return fail(str(exc))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
