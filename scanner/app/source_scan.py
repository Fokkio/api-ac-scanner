"""Fail-closed Semgrep execution and normalized source findings."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
from typing import Any

from app.errors import PolicyError, ScannerExecutionError
from app.findings import create_finding
from app.discovery import discover_source_routes

RULES_DIRECTORY = Path(__file__).resolve().parent.parent / "semgrep_rules"
UPLOAD_ROOT = Path(os.environ.get("UPLOAD_ROOT", "/uploads")).resolve()
SCAN_TIMEOUT_SECONDS = 300
MAX_ANALYZER_OUTPUT_BYTES = 16_777_216


def run_source_scan(repository_path: str) -> dict[str, list[Any]]:
    """Runs Semgrep against one upload-root child and fails closed on analyzer errors."""

    scan_path = _resolve_scan_path(repository_path)
    command = [
        "semgrep", "scan", "--config", str(RULES_DIRECTORY),
        "--metrics", "off", "--no-git-ignore", "--jobs", "1",
        "--max-target-bytes", "1048576", "--max-memory", "512",
        "--timeout", "10", "--timeout-threshold", "3",
    ]
    analyzer_output = _execute_semgrep(command, scan_path)
    try:
        payload = json.loads(analyzer_output)
    except json.JSONDecodeError as error:
        raise ScannerExecutionError("Static analyzer returned invalid JSON") from error
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
        raise ScannerExecutionError("Static analyzer returned an unsupported result schema")

    findings = _normalize_results(payload["results"], scan_path)
    return {
        "findings": findings,
        "warnings": ["Static findings are patterns that require manual authorization review."],
    }


def _execute_semgrep(command: list[str], scan_path: Path) -> str:
    """Writes analyzer JSON to a temp file via -o and reads it back.

    Semgrep prints banners, code snippets and progress to stdout even with
    --json, so capturing stdout yields a non-JSON mixture. Writing the report
    with --json -o <file> keeps the result file clean (no tty formatting).
    """

    with tempfile.NamedTemporaryFile(mode="w+b", suffix=".json", delete=True) as output_file:
        output_path = output_file.name
        full_command = [*command, "--json", "-o", output_path, str(scan_path)]
        completed = subprocess.run(
            full_command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=SCAN_TIMEOUT_SECONDS,
            check=False,
        )
        if completed.returncode == 2:
            raise ScannerExecutionError("Static analyzer failed before producing a complete result")
        if not output_file.read(1):
            raise ScannerExecutionError("Static analyzer produced no output")
        output_file.seek(0)
        return output_file.read().decode("utf-8", errors="strict")


def _resolve_scan_path(repository_path: str) -> Path:
    candidate = Path(repository_path).resolve(strict=True)
    if candidate == UPLOAD_ROOT or UPLOAD_ROOT not in candidate.parents:
        raise PolicyError("Source path is outside the upload root")
    if not candidate.is_dir():
        raise PolicyError("Source path must be an uploaded directory")
    return candidate


def _normalize_results(results: list[Any], scan_path: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int]] = set()
    for raw_result in results:
        if not isinstance(raw_result, dict):
            raise ScannerExecutionError("Static analyzer returned a malformed result entry")
        rule_id = str(raw_result.get("check_id", "unknown")).rsplit(".", 1)[-1]
        source_path = Path(str(raw_result.get("path", "")))
        relative_path = _safe_relative_path(source_path, scan_path)
        start = raw_result.get("start", {})
        extra = raw_result.get("extra", {})
        if not isinstance(start, dict) or not isinstance(extra, dict):
            raise ScannerExecutionError("Static analyzer returned malformed result metadata")
        try:
            line = int(start.get("line", 0))
        except (TypeError, ValueError) as error:
            raise ScannerExecutionError("Static analyzer returned an invalid line number") from error
        deduplication_key = (rule_id, relative_path, line)
        if deduplication_key in seen:
            continue
        seen.add(deduplication_key)
        metadata = extra.get("metadata", {})
        if not isinstance(metadata, dict):
            raise ScannerExecutionError("Static analyzer returned malformed rule metadata")
        evidence: dict[str, str | int | bool] = {"line": line, "ruleId": rule_id}
        nearest_route = _nearest_route(scan_path / relative_path, line)
        if nearest_route:
            evidence["endpointMethod"] = str(nearest_route["method"])
            evidence["endpointPath"] = str(nearest_route["path"])
        findings.append(create_finding(
            category=str(metadata.get("category", "source-review")),
            rule_id=rule_id,
            title=str(metadata.get("title", "Potential access-control weakness")),
            description=str(extra.get("message", "Review the matched code path.")),
            state="needs-verification",
            confidence=str(metadata.get("confidence", "medium")),
            severity=str(metadata.get("severity_label", "medium")),
            owasp_id=str(metadata.get("owasp_id", "API1:2023")),
            evidence=evidence,
            recommendation=str(metadata.get("recommendation", "Trace the identifier to a server-side authorization policy.")),
            location=f"{relative_path}:{line}",
        ))
    return findings


def _nearest_route(source_path: Path, finding_line: int) -> dict[str, Any] | None:
    routes = discover_source_routes(source_path)
    candidates = [route for route in routes if 0 <= finding_line - int(route["line"]) <= 25]
    if not candidates:
        return None
    return max(candidates, key=lambda route: int(route["line"]))


def _safe_relative_path(source_path: Path, scan_path: Path) -> str:
    try:
        return source_path.resolve().relative_to(scan_path).as_posix()
    except (ValueError, OSError):
        return source_path.name
