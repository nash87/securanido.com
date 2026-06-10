#!/usr/bin/env python3
"""Static release gate for the securanido.com deploying branch (master).

Ported from the t-6894 public-readiness branch and adapted to the live
countdown page: the gate leak-scans the served files, rejects marketing-slop
wording, asserts the pre-launch noindex posture, pins the countdown target
datetime, and checks i18n locale parity. Release mode stays intentionally
blocked until an operator-owned release-approval.json receipt exists.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from html.parser import HTMLParser
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

REQUIRED_IDS = {"main", "portfolio", "impressum", "privacy"}
PLACEHOLDER_RE = re.compile(r"@@[A-Z0-9_]+@@")
REPLACE_RE = re.compile(r"REPLACE_|YYYY-|TODO|TBD|PLACEHOLDER", re.IGNORECASE)
COMMIT_RE = re.compile(r"[0-9a-f]{40}")
APPROVAL_RECEIPT = Path("release-approval.json")
APPROVAL_PASS_STATUSES = {"approved", "verified", "passed", "green", "go"}
APPROVAL_EXACT_FIELDS = {
    "mode": "public-release",
    "scope": "securanido-com",
    "target_domain": "securanido.com",
    "go_no_go": "go",
}
APPROVAL_EVIDENCE_FIELDS = [
    "legal_review",
    "privacy_review",
    "license_review",
    "claims_review",
    "dns_review",
    "github_pages_settings_review",
    "pages_release_stack",
    "public_release_gate_workflow",
    "external_legal_target_review",
]

# The exact launch instant the countdown script targets. The gate pins it so a
# stray edit cannot silently move the public release date.
COUNTDOWN_TARGET = "2026-06-28T14:00:00+02:00"

# Locales the page ships; mirrors the SUPPORTED list inside index.html.
I18N_SUPPORTED = ("en", "de", "fr", "es", "it", "pt", "tr", "pl", "ja", "zh")

TEXT_FILE_SUFFIXES = {
    ".css",
    ".html",
    ".js",
    ".json",
    ".md",
    ".py",
    ".svg",
    ".txt",
    ".webmanifest",
    ".xml",
    ".yaml",
    ".yml",
}
TEXT_FILE_NAMES = {"CNAME", ".gitignore"}
PUBLIC_SCAN_EXCLUDED_DIRS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "node_modules",
}

# ── Self-reference convention (leak-scan deny list) ─────────────────────────
# This file sits INSIDE its own scan perimeter: audit_public_safe walks *.py
# files too, and the repo-wide pre-push leak scan must stay zero-hit. Pattern
# literals that would otherwise self-match are therefore built from split
# fragments (LOCAL_*_PATTERN below) or kept in regex-escaped form that never
# contains the raw denied substring as contiguous text. When adding a rule,
# never write a bare internal hostname, private IP, or workstation path as one
# contiguous literal — split it, then join at runtime.
LOCAL_VAR_HOME_PATTERN = "/" + "var/" + "home/"
LOCAL_HOME_PATTERN = "/" + "home/" + "florian"
PUBLIC_SAFE_RULES = [
    (
        "private network address",
        re.compile(
            r"\b(?:10(?:\.\d{1,3}){3}|127\.0\.0\.1|192\.168(?:\.\d{1,3}){2}|"
            r"172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2})\b"
        ),
    ),
    (
        "internal test domain",
        re.compile(r"\b(?:[A-Za-z0-9-]+\.)?(?:gitea|homelab|securanido)\.test\b", re.IGNORECASE),
    ),
    (
        "local workstation path",
        re.compile(
            r"(?<![\w-])(?:" + re.escape(LOCAL_VAR_HOME_PATTERN) + "|" + re.escape(LOCAL_HOME_PATTERN) + r"\b)",
            re.IGNORECASE,
        ),
    ),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("OpenAI token", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("Anthropic token", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    (
        "private key material",
        re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----"),
    ),
    (
        "database connection URL",
        re.compile(r"\b(?:postgres|postgresql|mysql|mongodb)://[^@\s:]+:[^@\s]+@[^ \n<>'\"]+", re.IGNORECASE),
    ),
    (
        "base64-like secret assignment",
        re.compile(
            r"(?i)\b(?:api[_-]?key|password|secret|token)[^\n]{0,32}[=:]\s*[A-Za-z0-9+/]{32,}={0,2}"
        ),
    ),
]

# Anti-slop charter: the served copy must never drift into the default
# LLM/SaaS marketing register. Scanned on served text files only (the gate's
# own sources legitimately contain these words as patterns).
SLOP_RE = re.compile(
    r"\b(?:seamless(?:ly)?|effortless(?:ly)?|empower(?:s|ed|ing|ment)?|"
    r"unlock(?:s|ed|ing)?|game-?chang(?:er|ers|ing)|revolutioniz\w*|"
    r"cutting-?edge|supercharg\w*|blazingly|delve[sd]?|next-?level|"
    r"world-?class|paradigm(?:-?shift\w*)?)\b",
    re.IGNORECASE,
)
SLOP_SCAN_FILES = ("index.html", "404.html", "site.webmanifest")

SERVED_REQUIRED_FILES = ("index.html", "404.html", "CNAME", "site.webmanifest", "icon.svg")

ROBOTS_PREP_PATHS = {
    "index.html": {"noindex", "nofollow"},
    "404.html": {"noindex"},
}
ROBOTS_RELEASE_PATHS = {
    "index.html": {"index", "follow"},
    "404.html": {"noindex"},
}


class IndexParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.ids: set[str] = set()
        self.robots: str | None = None
        self.canonical: str | None = None
        self.links: list[tuple[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): value or "" for key, value in attrs}
        if "id" in values:
            self.ids.add(values["id"])
        if tag == "meta" and values.get("name", "").lower() == "robots":
            self.robots = values.get("content", "")
        if tag == "link" and values.get("rel", "").lower() == "canonical":
            self.canonical = values.get("href", "")
        if tag == "a":
            self.links.append((values.get("href", ""), values.get("rel", "")))


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def public_scan_candidate(path: Path) -> bool:
    return path.name in TEXT_FILE_NAMES or path.suffix in TEXT_FILE_SUFFIXES


def skipped_by_public_scan(path: Path) -> bool:
    return any(part in PUBLIC_SCAN_EXCLUDED_DIRS for part in path.parts)


def git_public_file_paths(root: Path) -> list[Path] | None:
    try:
        proc = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
            cwd=root,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return [root / line for line in proc.stdout.splitlines() if line.strip()]


def iter_public_scan_files(root: Path) -> list[Path]:
    git_paths = git_public_file_paths(root)
    if git_paths is None:
        candidates = [path for path in root.rglob("*") if path.is_file()]
    else:
        candidates = [path for path in git_paths if path.is_file()]

    return sorted(
        {
            path
            for path in candidates
            if public_scan_candidate(path) and not skipped_by_public_scan(path.relative_to(root))
        }
    )


def audit_public_safe(root: Path, errors: list[str]) -> None:
    files = iter_public_scan_files(root)
    if not files:
        errors.append("public-safe scan found no candidate source files")
        return

    for path in files:
        try:
            text = read_text(path)
        except UnicodeDecodeError:
            errors.append(f"{path.relative_to(root)}: public-safe scan could not decode UTF-8")
            continue
        for label, regex in PUBLIC_SAFE_RULES:
            if regex.search(text):
                errors.append(f"{path.relative_to(root)}: {label}")


def audit_slop(root: Path, errors: list[str]) -> None:
    for rel in SLOP_SCAN_FILES:
        path = root / rel
        if not path.is_file():
            continue  # missing required files are reported separately
        hits = sorted({match.group(0).lower() for match in SLOP_RE.finditer(read_text(path))})
        if hits:
            errors.append(f"{rel}: marketing-slop wording: " + ", ".join(hits))


def audit_countdown(root: Path, errors: list[str]) -> None:
    index = root / "index.html"
    if not index.is_file():
        return  # missing required files are reported separately
    if COUNTDOWN_TARGET not in read_text(index):
        errors.append(f"index.html must keep the countdown target datetime {COUNTDOWN_TARGET}")


def extract_i18n_locales(index_text: str) -> dict[str, set[str]]:
    """Extract locale → key-set from the inline `var DICT = {...}` table."""
    locale_start_re = re.compile(r'^\s*"([a-z]{2})"\s*:\s*\{\s*$')
    dict_key_re = re.compile(r'^\s*"([A-Za-z0-9_]+)"\s*:\s*"')
    locales: dict[str, set[str]] = {}
    current: str | None = None
    in_dict = False
    for line in index_text.splitlines():
        if not in_dict:
            if "var DICT = {" in line:
                in_dict = True
            continue
        if line.strip() == "};":
            break
        start = locale_start_re.match(line)
        if start:
            current = start.group(1)
            locales[current] = set()
            continue
        key = dict_key_re.match(line)
        if key and current is not None:
            locales[current].add(key.group(1))
    return locales


def audit_i18n(root: Path, errors: list[str]) -> None:
    index = root / "index.html"
    if not index.is_file():
        return  # missing required files are reported separately
    text = read_text(index)
    locales = extract_i18n_locales(text)
    if not locales:
        errors.append("index.html i18n dictionary (var DICT) not found")
        return

    missing_locales = [lang for lang in I18N_SUPPORTED if lang not in locales]
    if missing_locales:
        errors.append("i18n dictionary missing locales: " + ", ".join(missing_locales))

    base = locales.get("en")
    if not base:
        errors.append("i18n dictionary is missing the en baseline locale")
        return

    for lang in sorted(locales):
        if lang == "en":
            continue
        missing = sorted(base - locales[lang])
        extra = sorted(locales[lang] - base)
        if missing:
            errors.append(f"i18n locale {lang} missing keys: " + ", ".join(missing))
        if extra:
            errors.append(f"i18n locale {lang} has keys absent from en: " + ", ".join(extra))

    used = set(re.findall(r'data-i18n(?:-aria-label)?="([A-Za-z0-9_]+)"', text))
    unknown = sorted(used - base)
    if unknown:
        errors.append("markup references i18n keys missing from en: " + ", ".join(unknown))


def has_license_file(root: Path) -> bool:
    return any((root / name).is_file() for name in ("LICENSE", "LICENSE.md", "LICENSE.txt"))


def robots_tokens(value: str | None) -> set[str]:
    if not value:
        return set()
    return {token.strip().lower() for token in value.split(",") if token.strip()}


def html_robots_tokens(path: Path) -> set[str]:
    parser = IndexParser()
    parser.feed(read_text(path))
    return robots_tokens(parser.robots)


def audit_robots(root: Path, expectations: dict[str, set[str]], errors: list[str]) -> None:
    for rel, required in expectations.items():
        tokens = html_robots_tokens(root / rel)
        if not required.issubset(tokens):
            errors.append(f"{rel} requires robots {','.join(sorted(required))}")


def current_head(root: Path) -> str | None:
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    head = proc.stdout.strip()
    return head if COMMIT_RE.fullmatch(head) else None


def approval_value_has_evidence(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    status = str(value.get("status", "")).strip().lower()
    evidence = str(value.get("evidence", "")).strip()
    return status in APPROVAL_PASS_STATUSES and bool(evidence) and REPLACE_RE.search(evidence) is None


def audit_release_approval(root: Path, errors: list[str]) -> None:
    receipt_path = root / APPROVAL_RECEIPT
    if not receipt_path.is_file():
        errors.append("release mode requires ignored repo-root release-approval.json")
        return

    try:
        approval = json.loads(read_text(receipt_path))
    except json.JSONDecodeError as exc:
        errors.append(f"release-approval.json is invalid JSON: {exc}")
        return

    if not isinstance(approval, dict):
        errors.append("release-approval.json must be a JSON object")
        return

    for key, expected in APPROVAL_EXACT_FIELDS.items():
        if approval.get(key) != expected:
            errors.append(f"release-approval.json requires {key}={expected!r}")

    approved_by = str(approval.get("approved_by", "")).strip()
    if not approved_by or REPLACE_RE.search(approved_by):
        errors.append("release-approval.json requires a real approved_by value")

    approved_at = str(approval.get("approved_at", "")).strip()
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", approved_at):
        errors.append("release-approval.json requires approved_at as YYYY-MM-DDTHH:MM:SSZ")

    source_commit = str(approval.get("source_commit", "")).strip()
    if not COMMIT_RE.fullmatch(source_commit):
        errors.append("release-approval.json requires a full 40-character source_commit SHA")
    else:
        head = current_head(root)
        if head and source_commit != head:
            errors.append("release-approval.json source_commit must match current HEAD")

    for key in APPROVAL_EVIDENCE_FIELDS:
        if not approval_value_has_evidence(approval.get(key)):
            errors.append(
                f"release-approval.json {key} requires a passing status and non-placeholder evidence"
            )


def common_errors(root: Path) -> list[str]:
    errors: list[str] = []
    required = [root / rel for rel in SERVED_REQUIRED_FILES]
    for path in required:
        if not path.is_file():
            errors.append(f"missing required file: {path.relative_to(root)}")
    if errors:
        return errors

    index = root / "index.html"
    cname_text = read_text(root / "CNAME").strip()
    index_text = read_text(index)
    parser = IndexParser()
    parser.feed(index_text)

    if cname_text != "securanido.com":
        errors.append("CNAME must contain exactly securanido.com")
    if parser.canonical != "https://securanido.com/":
        errors.append("canonical URL must stay https://securanido.com/")

    missing_ids = sorted(REQUIRED_IDS - parser.ids)
    if missing_ids:
        errors.append(f"index.html is missing required ids: {', '.join(missing_ids)}")

    for needle in ("<<<<<<<", "=======", ">>>>>>>"):
        for path in required:
            if path.suffix == ".svg" or path.name == "CNAME":
                continue
            if needle in read_text(path):
                errors.append(f"conflict marker {needle!r} found in {path.relative_to(root)}")

    audit_public_safe(root, errors)
    audit_slop(root, errors)
    audit_countdown(root, errors)
    audit_i18n(root, errors)

    bad_links = []
    for href, rel in parser.links:
        if href.startswith("http") and "noopener" not in rel.split():
            bad_links.append(href)
    if bad_links:
        errors.append("external links missing rel=noopener: " + ", ".join(sorted(set(bad_links))))

    return errors


def prep_errors(root: Path) -> list[str]:
    errors = common_errors(root)
    if errors:
        return errors

    audit_robots(root, ROBOTS_PREP_PATHS, errors)

    if has_license_file(root):
        errors.append("prep mode should not add a LICENSE until the license decision is approved")

    return errors


def release_errors(root: Path) -> list[str]:
    errors = common_errors(root)
    if errors:
        return errors

    index_tokens = html_robots_tokens(root / "index.html")

    if "noindex" in index_tokens or "nofollow" in index_tokens:
        errors.append("release mode requires removing noindex,nofollow only in the approved release commit")
    audit_robots(root, ROBOTS_RELEASE_PATHS, errors)

    index_text = read_text(root / "index.html")
    placeholders = sorted(set(PLACEHOLDER_RE.findall(index_text)))
    if placeholders:
        errors.append("release mode cannot contain unresolved placeholders: " + ", ".join(placeholders))

    if not has_license_file(root):
        errors.append("release mode requires an approved LICENSE file")

    audit_release_approval(root, errors)

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("prep", "release"), default="prep")
    parser.add_argument(
        "--expect-blocked",
        action="store_true",
        help="Return success only when the selected gate reports blockers.",
    )
    args = parser.parse_args()

    errors = prep_errors(ROOT) if args.mode == "prep" else release_errors(ROOT)

    if args.expect_blocked:
        if errors:
            print(f"securanido.com {args.mode} gate blocked as expected:")
            for error in errors:
                print(f"- {error}")
            return 0
        print(f"expected securanido.com {args.mode} gate to be blocked, but it passed")
        return 1

    if errors:
        print(f"securanido.com {args.mode} gate failed:")
        for error in errors:
            print(f"- {error}")
        return 1

    print(f"securanido.com {args.mode} gate passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
