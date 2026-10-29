"""Deterministic Express route and export inventory via ToolDispatcher (Slice S6)."""

from __future__ import annotations

import posixpath
import re
from typing import Iterable

from contracts import DispatcherProtocol, RouteEntry

REQUIRE_DESTRUCTURED_RE = re.compile(
    r"""const\s*\{([^}]+)\}\s*=\s*require\(\s*['"]([^'"]+)['"]\s*\)"""
)
REQUIRE_DEFAULT_RE = re.compile(
    r"""const\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*require\(\s*['"]([^'"]+)['"]\s*\)"""
)
APP_USE_MOUNT_RE = re.compile(
    r"""\b(?:app|router)\.use\(\s*['"]([^'"]+)['"]\s*,\s*([A-Za-z_$][A-Za-z0-9_$]*)"""
)
ROUTE_CALL_RE = re.compile(
    r"""\b(app|router)\.(get|post|put|delete|patch|options)\(\s*['"]([^'"]+)['"]"""
)
MODULE_EXPORTS_OBJ_RE = re.compile(r"""module\.exports\s*=\s*\{([^}]+)\}""", re.DOTALL)
EXPORTS_PROP_RE = re.compile(r"""\bexports\.([A-Za-z_$][A-Za-z0-9_$]*)\s*=""")


def _strip_numbered_lines(numbered_text: str) -> list[str]:
    out: list[str] = []
    for raw in numbered_text.splitlines():
        if ": " in raw:
            prefix, rest = raw.split(": ", 1)
            if prefix.isdigit():
                out.append(rest)
                continue
        out.append(raw)
    return out


def _resolve_js_import(importer_file: str, spec: str, known_files: set[str]) -> str | None:
    if not spec.startswith("."):
        return None
    base_dir = posixpath.dirname(importer_file)
    joined = posixpath.normpath(posixpath.join(base_dir, spec))
    for candidate in (joined, f"{joined}.js", posixpath.join(joined, "index.js")):
        if candidate in known_files:
            return candidate
    return None


def _join_route_paths(prefix: str, subpath: str) -> str:
    p = prefix.rstrip("/")
    s = subpath.strip()
    if s in ("", "/"):
        return p if p else "/"
    if not s.startswith("/"):
        s = "/" + s
    return f"{p}{s}" if p else s


def _list_source_js_files(run_id: str, dispatcher: DispatcherProtocol) -> list[str]:
    listed = dispatcher.call(run_id, "list_files", {})
    if not listed.ok or not isinstance(listed.output, list):
        raise RuntimeError(f"Failed to list workspace files: {listed.rejection_reason}")
    return sorted(
        f
        for f in listed.output
        if isinstance(f, str)
        and f.endswith(".js")
        and not f.startswith("tests/")
        and not f.endswith(".test.js")
    )


def build_route_inventory(run_id: str, dispatcher: DispatcherProtocol) -> list[RouteEntry]:
    """Deterministically discover all Express routes (method, path, file, line) using only Dispatcher."""
    js_files = _list_source_js_files(run_id, dispatcher)
    known_set = set(js_files)
    file_lines: dict[str, list[str]] = {}

    for rel_path in js_files:
        read_res = dispatcher.call(run_id, "read_file", {"path": rel_path})
        if not read_res.ok or not isinstance(read_res.output, str):
            raise RuntimeError(f"Failed to read {rel_path}: {read_res.rejection_reason}")
        file_lines[rel_path] = _strip_numbered_lines(read_res.output)

    # First pass: resolve mount prefixes from app.use('/prefix', routerOrFactory(...))
    mount_prefixes: dict[str, list[str]] = {}
    for rel_path, lines in file_lines.items():
        full_text = "\n".join(lines)
        symbol_to_file: dict[str, str] = {}

        for m in REQUIRE_DESTRUCTURED_RE.finditer(full_text):
            symbols_raw, spec = m.group(1), m.group(2)
            resolved = _resolve_js_import(rel_path, spec, known_set)
            if resolved:
                for sym in symbols_raw.split(","):
                    clean_sym = sym.split(":")[0].strip()
                    if clean_sym:
                        symbol_to_file[clean_sym] = resolved

        for m in REQUIRE_DEFAULT_RE.finditer(full_text):
            sym, spec = m.group(1).strip(), m.group(2)
            resolved = _resolve_js_import(rel_path, spec, known_set)
            if resolved:
                symbol_to_file[sym] = resolved

        for line in lines:
            stripped = line.strip()
            if stripped.startswith(("//", "*", "/*")):
                continue
            for m in APP_USE_MOUNT_RE.finditer(line):
                prefix, target_sym = m.group(1), m.group(2)
                target_file = symbol_to_file.get(target_sym)
                if target_file:
                    mount_prefixes.setdefault(target_file, [])
                    if prefix not in mount_prefixes[target_file]:
                        mount_prefixes[target_file].append(prefix)

    # Second pass: extract route definitions with exact 1-based line numbers
    entries: list[RouteEntry] = []
    in_block_comment = False
    for rel_path, lines in file_lines.items():
        in_block_comment = False
        prefixes = mount_prefixes.get(rel_path, [""])
        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()
            if "/*" in stripped:
                in_block_comment = True
            if in_block_comment:
                if "*/" in stripped:
                    in_block_comment = False
                continue
            if stripped.startswith("//"):
                continue

            for m in ROUTE_CALL_RE.finditer(line):
                receiver, verb, subpath = m.group(1), m.group(2).upper(), m.group(3)
                if receiver == "app":
                    full_path = _join_route_paths("", subpath)
                    entries.append(RouteEntry(method=verb, path=full_path, file=rel_path, line=lineno))
                else:
                    for pref in prefixes:
                        full_path = _join_route_paths(pref, subpath)
                        entries.append(RouteEntry(method=verb, path=full_path, file=rel_path, line=lineno))

    entries.sort(key=lambda r: (r.file, r.line, r.method, r.path))
    return entries


def extract_exported_symbols(run_id: str, dispatcher: DispatcherProtocol) -> dict[str, list[str]]:
    """Extract exported symbol names per source JS file for anti-vandalism guard verification."""
    js_files = _list_source_js_files(run_id, dispatcher)
    exports_map: dict[str, list[str]] = {}
    for rel_path in js_files:
        read_res = dispatcher.call(run_id, "read_file", {"path": rel_path})
        if not read_res.ok or not isinstance(read_res.output, str):
            continue
        text = "\n".join(_strip_numbered_lines(read_res.output))
        names: set[str] = set()
        for m in MODULE_EXPORTS_OBJ_RE.finditer(text):
            for raw_item in m.group(1).split(","):
                tok = raw_item.split(":")[0].strip()
                if re.match(r"^[A-Za-z_$][A-Za-z0-9_$]*$", tok):
                    names.add(tok)
        for m in EXPORTS_PROP_RE.finditer(text):
            names.add(m.group(1))
        exports_map[rel_path] = sorted(names)
    return exports_map


def format_route_inventory(routes: Iterable[RouteEntry]) -> set[str]:
    return {f"{r.method} {r.path}" for r in routes}
