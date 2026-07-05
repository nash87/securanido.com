#!/usr/bin/env python3
"""Focused tests for the securanido.com release gate."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts/check-public-release-ready.py"


def load_gate():
    spec = importlib.util.spec_from_file_location("check_public_release_ready", MODULE_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def current_head() -> str:
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()


def valid_receipt() -> dict[str, object]:
    return {
        "mode": "public-release",
        "scope": "securanido-com",
        "target_domain": "securanido.com",
        "go_no_go": "go",
        "approved_by": "Operator Review",
        "approved_at": "2026-06-07T17:30:00Z",
        "source_commit": current_head(),
        "legal_review": {"status": "approved", "evidence": "legal-review-receipt"},
        "privacy_review": {"status": "approved", "evidence": "privacy-review-receipt"},
        "license_review": {"status": "approved", "evidence": "license-review-receipt"},
        "claims_review": {"status": "approved", "evidence": "claims-review-receipt"},
        "dns_review": {"status": "verified", "evidence": "dns-dig-receipt"},
        "github_pages_settings_review": {
            "status": "verified",
            "evidence": "github-pages-settings-receipt",
        },
        "pages_release_stack": {"status": "passed", "evidence": "pages-stack-receipt"},
        "public_release_gate_workflow": {"status": "passed", "evidence": "workflow-run-receipt"},
        "external_legal_target_review": {
            "status": "approved",
            "evidence": "external-legal-target-receipt",
        },
    }


def run_receipt_case(receipt: dict[str, object]) -> list[str]:
    gate = load_gate()
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / ".git").write_text("not a git repo\n", encoding="utf-8")
        (root / "release-approval.json").write_text(json.dumps(receipt), encoding="utf-8")
        errors: list[str] = []
        gate.audit_release_approval(root, errors)
        return errors


def test_valid_receipt_contract() -> None:
    errors = run_receipt_case(valid_receipt())
    assert errors == [], errors


def test_placeholder_evidence_is_rejected() -> None:
    receipt = valid_receipt()
    receipt["legal_review"] = {"status": "approved", "evidence": "REPLACE_WITH_LEGAL_REVIEW"}
    errors = run_receipt_case(receipt)
    assert any("legal_review" in error for error in errors), errors


def test_wrong_domain_is_rejected() -> None:
    receipt = valid_receipt()
    receipt["target_domain"] = "example.com"
    errors = run_receipt_case(receipt)
    assert any("target_domain" in error for error in errors), errors


def test_robots_meta_contract() -> None:
    gate = load_gate()
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "index.html").write_text(
            '<html><head><meta name="robots" content="noindex,nofollow"></head></html>',
            encoding="utf-8",
        )
        (root / "404.html").write_text(
            '<html><head><meta name="robots" content="index,follow"></head></html>',
            encoding="utf-8",
        )
        errors: list[str] = []
        gate.audit_robots(root, gate.ROBOTS_PREP_PATHS, errors)
        assert any("404.html" in error for error in errors), errors


def public_safety_cases() -> dict[str, tuple[str, str]]:
    # Fixture bodies are split so no contiguous denied literal (internal
    # domain, private IP, workstation path, token) appears in this file —
    # the gate's public-safe scan walks tests/ too. Same convention as the
    # deny list in scripts/check-public-release-ready.py.
    return {
        "private-ip": ("index.html", "<p>internal " + "192" + ".168.4.20</p>"),
        "test-domain": ("index.html", "<p>preview secura" + "nido" + ".test</p>"),
        "svg-private-ip": ("icon.svg", "<svg><!-- " + "192" + ".168.4.20 --></svg>"),
        "home-path": ("index.html", "<p>" + "/var" + "/home/release/source</p>"),
        "github-token": ("index.html", "<p>ghp_" + "0123456789abcdefghijklmnopqrst</p>"),
        "openai-token": ("index.html", "<p>sk-" + "0123456789abcdefghijklmnopqrst</p>"),
        "anthropic-token": ("index.html", "<p>sk-ant-" + "0123456789abcdefghijklmnopqrst</p>"),
        "aws-key": ("index.html", "<p>AKIA" + "0123456789ABCDEF</p>"),
        "private-key": ("index.html", "-----BEGIN " + "PRIVATE KEY-----\nredacted\n"),
        "database-url": (
            "index.html",
            "<p>postgres" + "://user:pass@example.internal:5432/app</p>",
        ),
        "secret-assignment": (
            "index.html",
            "<p>api_key = " + "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=</p>",
        ),
    }


def test_public_safety_negative_controls() -> None:
    gate = load_gate()
    for case, (filename, body) in public_safety_cases().items():
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / filename).write_text(body, encoding="utf-8")
            errors: list[str] = []
            gate.audit_public_safe(root, errors)
        assert errors, case
        assert all("0123456789" not in error for error in errors), errors


def test_public_safety_allows_public_identity() -> None:
    gate = load_gate()
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "index.html").write_text(
            "<p>Florian Schulz</p><p>hello@securanido.com</p>",
            encoding="utf-8",
        )
        errors: list[str] = []
        gate.audit_public_safe(root, errors)
    assert errors == [], errors


def test_slop_wording_is_rejected() -> None:
    gate = load_gate()
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "index.html").write_text(
            "<p>Seamless, effortless AI that empowers you to unlock value.</p>",
            encoding="utf-8",
        )
        errors: list[str] = []
        gate.audit_slop(root, errors)
    assert errors and "index.html" in errors[0], errors


def test_honest_copy_passes_slop_scan() -> None:
    gate = load_gate()
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "index.html").write_text(
            "<p>Runs on your own Kubernetes, laptop, or air-gapped network.</p>",
            encoding="utf-8",
        )
        errors: list[str] = []
        gate.audit_slop(root, errors)
    assert errors == [], errors


def test_countdown_target_is_pinned() -> None:
    gate = load_gate()
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "index.html").write_text(
            '<script>var TARGET = new Date("2027-01-01T00:00:00+01:00").getTime();</script>',
            encoding="utf-8",
        )
        errors: list[str] = []
        gate.audit_countdown(root, errors)
        assert any(gate.COUNTDOWN_TARGET in error for error in errors), errors

        (root / "index.html").write_text(
            '<script>var TARGET = new Date("' + gate.COUNTDOWN_TARGET + '").getTime();</script>',
            encoding="utf-8",
        )
        errors = []
        gate.audit_countdown(root, errors)
        assert errors == [], errors


def i18n_index_fixture(de_extra: str = "") -> str:
    return (
        '<span data-i18n="skip">Skip</span>\n'
        "<script>\n"
        "      var DICT = {\n"
        '        "en": {\n'
        '                "skip": "Skip to content",\n'
        '                "days": "Days"\n'
        "        },\n"
        '        "de": {\n'
        '                "skip": "Zum Inhalt springen"' + de_extra + "\n"
        "        }\n"
        "};\n"
        "</script>\n"
    )


def test_i18n_key_parity_is_enforced() -> None:
    gate = load_gate()
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "index.html").write_text(i18n_index_fixture(), encoding="utf-8")
        errors: list[str] = []
        gate.audit_i18n(root, errors)
    assert any("i18n locale de missing keys: days" in error for error in errors), errors
    assert any("i18n dictionary missing locales" in error for error in errors), errors


def test_i18n_markup_keys_must_exist() -> None:
    gate = load_gate()
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        fixture = i18n_index_fixture().replace('data-i18n="skip"', 'data-i18n="missingKey"')
        (root / "index.html").write_text(fixture, encoding="utf-8")
        errors: list[str] = []
        gate.audit_i18n(root, errors)
    assert any("missingKey" in error for error in errors), errors


def main() -> int:
    test_valid_receipt_contract()
    test_placeholder_evidence_is_rejected()
    test_wrong_domain_is_rejected()
    test_robots_meta_contract()
    test_public_safety_negative_controls()
    test_public_safety_allows_public_identity()
    test_slop_wording_is_rejected()
    test_honest_copy_passes_slop_scan()
    test_countdown_target_is_pinned()
    test_i18n_key_parity_is_enforced()
    test_i18n_markup_keys_must_exist()
    print("public release gate contract tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
