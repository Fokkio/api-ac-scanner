"""Builds a bounded endpoint inventory from explicit local artifacts."""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any, Callable, Iterable
from urllib.parse import urlsplit

import yaml

from app.errors import PolicyError, ScannerExecutionError

MAX_ARTIFACT_FILES = 25
MAX_ARTIFACT_BYTES = 1_048_576
MAX_ENDPOINTS = 500
HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})
SOURCE_EXTENSIONS = frozenset({".js", ".jsx", ".ts", ".tsx", ".py", ".php", ".java"})


def run_discovery(repository_path: str, upload_root: Path, target: str) -> dict[str, list[Any]]:
    """Parses supported artifacts and returns a deduplicated endpoint inventory."""

    scan_path = _resolve_scan_path(repository_path, upload_root)
    target_origin = _normalize_origin(target)
    artifacts = sorted(path for path in scan_path.iterdir() if path.is_file())
    if not artifacts or len(artifacts) > MAX_ARTIFACT_FILES:
        raise PolicyError("Discovery requires between 1 and 25 artifact files")

    endpoints: list[dict[str, Any]] = []
    warnings: list[str] = []
    for artifact in artifacts:
        if artifact.stat().st_size > MAX_ARTIFACT_BYTES:
            raise PolicyError("A discovery artifact exceeded the size limit")
        discovered, artifact_warnings = _discover_file(artifact, target_origin)
        endpoints.extend(discovered)
        warnings.extend(artifact_warnings)
        if len(endpoints) > MAX_ENDPOINTS:
            raise PolicyError("Endpoint inventory exceeded the 500 endpoint limit")

    inventory = _deduplicate_endpoints(endpoints)
    if not inventory:
        warnings.append("No supported endpoint declarations were found in the uploaded artifacts.")
    return {"findings": [], "warnings": warnings, "endpoints": inventory}


def _resolve_scan_path(repository_path: str, upload_root: Path) -> Path:
    resolved_root = upload_root.resolve()
    candidate = Path(repository_path).resolve(strict=True)
    if candidate == resolved_root or resolved_root not in candidate.parents or not candidate.is_dir():
        raise PolicyError("Discovery path is outside the upload root")
    return candidate


def _discover_file(artifact: Path, target_origin: str) -> tuple[list[dict[str, Any]], list[str]]:
    extension = artifact.suffix.lower()
    if extension in SOURCE_EXTENSIONS:
        return _discover_source(artifact), []
    if extension not in {".json", ".yaml", ".yml", ".har"}:
        return [], [f"Skipped unsupported artifact: {artifact.name}"]
    try:
        text = artifact.read_text(encoding="utf-8")
        payload = yaml.safe_load(text) if extension in {".yaml", ".yml"} else json.loads(text)
    except (OSError, UnicodeError, json.JSONDecodeError, yaml.YAMLError) as error:
        raise ScannerExecutionError(f"Could not parse discovery artifact: {artifact.name}") from error
    if not isinstance(payload, dict):
        raise ScannerExecutionError(f"Discovery artifact must contain an object: {artifact.name}")
    if isinstance(payload.get("paths"), dict) and ("openapi" in payload or "swagger" in payload):
        return _discover_openapi(payload, artifact.name), []
    if isinstance(payload.get("log"), dict):
        return _discover_har(payload, artifact.name, target_origin)
    if isinstance(payload.get("item"), list):
        return _discover_postman(payload, artifact.name, target_origin)
    return [], [f"Unrecognized JSON/YAML discovery format: {artifact.name}"]


def _discover_openapi(payload: dict[str, Any], source_file: str) -> list[dict[str, Any]]:
    endpoints: list[dict[str, Any]] = []
    paths = payload.get("paths", {})
    for raw_path, operations in paths.items():
        if not isinstance(raw_path, str) or not isinstance(operations, dict):
            continue
        for method in operations:
            normalized_method = str(method).upper()
            if normalized_method in HTTP_METHODS:
                endpoints.append(_endpoint(normalized_method, raw_path, "openapi", source_file, 0, "high"))
    return endpoints


def _discover_har(
    payload: dict[str, Any], source_file: str, target_origin: str,
) -> tuple[list[dict[str, Any]], list[str]]:
    endpoints: list[dict[str, Any]] = []
    skipped_cross_origin = 0
    entries = payload.get("log", {}).get("entries", [])
    if not isinstance(entries, list):
        raise ScannerExecutionError("HAR entries must be a list")
    for entry in entries:
        request = entry.get("request", {}) if isinstance(entry, dict) else {}
        if not isinstance(request, dict):
            continue
        method = str(request.get("method", "GET")).upper()
        raw_url = str(request.get("url", ""))
        if not _is_same_origin_url(raw_url, target_origin):
            skipped_cross_origin += 1
            continue
        path = urlsplit(raw_url).path
        if method in HTTP_METHODS and path:
            endpoints.append(_endpoint(method, path, "har", source_file, 0, "high"))
    warnings = _cross_origin_warning(source_file, skipped_cross_origin)
    return endpoints, warnings


def _discover_postman(
    payload: dict[str, Any], source_file: str, target_origin: str,
) -> tuple[list[dict[str, Any]], list[str]]:
    endpoints: list[dict[str, Any]] = []
    skipped_cross_origin = 0
    for item in _walk_postman_items(payload.get("item", [])):
        request = item.get("request", {})
        if not isinstance(request, dict):
            continue
        method = str(request.get("method", "GET")).upper()
        path, is_cross_origin = _postman_path(request.get("url"), target_origin)
        if is_cross_origin:
            skipped_cross_origin += 1
            continue
        if method in HTTP_METHODS and path:
            endpoints.append(_endpoint(method, path, "postman", source_file, 0, "high"))
    warnings = _cross_origin_warning(source_file, skipped_cross_origin)
    return endpoints, warnings


def _walk_postman_items(items: Any) -> Iterable[dict[str, Any]]:
    if not isinstance(items, list):
        return
    for item in items:
        if not isinstance(item, dict):
            continue
        if "request" in item:
            yield item
        yield from _walk_postman_items(item.get("item", []))


def _postman_path(raw_url: Any, target_origin: str) -> tuple[str, bool]:
    if isinstance(raw_url, str):
        return _path_from_postman_url(raw_url, target_origin)
    if not isinstance(raw_url, dict):
        return "", False
    raw_path = raw_url.get("path")
    if isinstance(raw_path, list):
        return "/" + "/".join(str(segment) for segment in raw_path), False
    raw = str(raw_url.get("raw", ""))
    return _path_from_postman_url(raw, target_origin)


def _path_from_postman_url(raw_url: str, target_origin: str) -> tuple[str, bool]:
    if raw_url.startswith("{{baseUrl}}"):
        replaced = raw_url.replace("{{baseUrl}}", "http://placeholder.invalid", 1)
        return urlsplit(replaced).path, False
    parsed = urlsplit(raw_url)
    if parsed.scheme or parsed.netloc:
        try:
            return parsed.path, _origin_from_parts(parsed) != target_origin
        except PolicyError:
            return parsed.path, True
    return parsed.path, False


def _discover_source(artifact: Path) -> list[dict[str, Any]]:
    try:
        lines = artifact.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise ScannerExecutionError(f"Could not read source artifact: {artifact.name}") from error
    endpoints: list[dict[str, Any]] = []
    patterns = _source_patterns(artifact.suffix.lower())
    for line_number, line in enumerate(lines, start=1):
        for pattern, method_transform in patterns:
            match = pattern.search(line)
            if not match:
                continue
            method = method_transform(match.group("method"))
            endpoints.append(_endpoint(method, match.group("path"), "source", artifact.name, line_number, "medium"))
    return endpoints


def discover_source_routes(artifact: Path) -> list[dict[str, Any]]:
    """Returns bounded route declarations for source-scan correlation."""

    if artifact.suffix.lower() not in SOURCE_EXTENSIONS:
        return []
    return _discover_source(artifact)


def _source_patterns(extension: str) -> list[tuple[re.Pattern[str], Callable[[str], str]]]:
    normalize_method = str.upper
    if extension in {".js", ".jsx", ".ts", ".tsx"}:
        return [(re.compile(r"(?:app|router)\.(?P<method>get|post|put|patch|delete|head|options)\(\s*['\"](?P<path>/[^'\"]*)"), normalize_method)]
    if extension == ".py":
        return [(re.compile(r"@\w+\.(?P<method>get|post|put|patch|delete|head|options)\(\s*['\"](?P<path>/[^'\"]*)"), normalize_method)]
    if extension == ".java":
        return [(re.compile(r"@(?P<method>Get|Post|Put|Patch|Delete)Mapping\(\s*(?:value\s*=\s*)?['\"](?P<path>/[^'\"]*)"), normalize_method)]
    if extension == ".php":
        return [(re.compile(r"Route::(?P<method>get|post|put|patch|delete|options)\(\s*['\"](?P<path>/[^'\"]*)"), normalize_method)]
    return []


def _normalize_origin(raw_target: str) -> str:
    parsed = urlsplit(raw_target)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise PolicyError("Discovery target must be an HTTP or HTTPS origin")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise PolicyError("Discovery target must not contain a path, query or fragment")
    return _origin_from_parts(parsed)


def _origin_from_parts(parsed: Any) -> str:
    hostname = str(parsed.hostname).lower().rstrip(".")
    try:
        port = parsed.port
    except ValueError as error:
        raise PolicyError("Discovery target contains an invalid port") from error
    default_port = 443 if parsed.scheme.lower() == "https" else 80
    port_suffix = "" if port in {None, default_port} else f":{port}"
    host = f"[{hostname}]" if ":" in hostname else hostname
    return f"{parsed.scheme.lower()}://{host}{port_suffix}"


def _is_same_origin_url(raw_url: str, target_origin: str) -> bool:
    parsed = urlsplit(raw_url)
    if not parsed.scheme or not parsed.netloc:
        return False
    try:
        return _origin_from_parts(parsed) == target_origin
    except PolicyError:
        return False


def _cross_origin_warning(source_file: str, skipped_count: int) -> list[str]:
    if skipped_count == 0:
        return []
    return [f"Skipped {skipped_count} cross-origin request(s) in {source_file}."]


def _endpoint(
    method: str,
    path: str,
    source_type: str,
    source_file: str,
    line: int,
    confidence: str,
) -> dict[str, Any]:
    normalized_path = _normalize_path(path)
    return {
        "method": method, "path": normalized_path, "sourceType": source_type,
        "sourceFile": source_file, "line": line,
        "candidateType": _classify_candidate(method, normalized_path), "confidence": confidence,
    }


def _normalize_path(path: str) -> str:
    normalized = path.strip()
    if not normalized.startswith("/") or "#" in normalized or len(normalized) > 512:
        raise ScannerExecutionError("An artifact contained an invalid endpoint path")
    if any(ord(character) < 32 or ord(character) == 127 for character in normalized):
        raise ScannerExecutionError("An artifact contained a control character in a path")
    return normalized


def _classify_candidate(method: str, path: str) -> str:
    lowered = path.lower()
    if any(segment in lowered for segment in ("/admin", "/manage", "/internal", "/roles", "/permissions")):
        return "function"
    if re.search(r"(?:\{[^/]+\}|:[a-z_]+|/[0-9]+)(?:/|$)", lowered):
        return "object"
    if any(segment in lowered for segment in ("/login", "/register", "/reset", "/search", "/users")):
        return "enumeration"
    if method in {"PATCH", "PUT", "DELETE"}:
        return "object"
    return "other"


def _deduplicate_endpoints(endpoints: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: dict[tuple[str, str], dict[str, Any]] = {}
    for endpoint in endpoints:
        key = (str(endpoint["method"]), str(endpoint["path"]))
        existing = unique.get(key)
        if existing is None or _confidence_rank(endpoint["confidence"]) > _confidence_rank(existing["confidence"]):
            unique[key] = endpoint
    return sorted(unique.values(), key=lambda endpoint: (endpoint["path"], endpoint["method"]))


def _confidence_rank(confidence: str) -> int:
    return {"low": 1, "medium": 2, "high": 3}.get(str(confidence), 0)
