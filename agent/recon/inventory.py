"""Deterministic Express route and export inventory via ToolDispatcher (Slice S6)."""

from __future__ import annotations

import posixpath
import re
from typing import Any, Iterable

from contracts import DispatcherProtocol, RichRouteEntry, RouteEntry

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


REQ_PARAM_RE = re.compile(
    r"""\breq\.(params|query|body|headers)(?:\.([A-Za-z_$][A-Za-z0-9_$]*)|\[\s*['"]([^'"]+)['"]\s*\])"""
)
VAR_DECL_RE = re.compile(r"""\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(.+?);?$""")
GLOBAL_APP_MW_RE = re.compile(r"""\bapp\.use\(\s*([A-Za-z_$][A-Za-z0-9_$.]*)\s*(?:\([^)]*\))?\s*\)""")
ROUTER_MW_RE = re.compile(r"""\brouter\.use\(\s*([A-Za-z_$][A-Za-z0-9_$.]*)\s*(?:\([^)]*\))?\s*\)""")
IDENTITY_FIELD_RE = re.compile(r"""\b(?:req\.user\.[A-Za-z_$][A-Za-z0-9_$]*|[A-Za-z_$][A-Za-z0-9_$]*\.ownerId)\b""")
COMPARISON_EXPR_RE = re.compile(
    r"""([A-Za-z0-9_$.]+\s*(?:===|!==|==|!=)\s*[A-Za-z0-9_$."'']+|\b[A-Za-z0-9_$."'']+\s*(?:===|!==|==|!=)\s*[A-Za-z0-9_$.]+)"""
)

SINK_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("filesystem", "fs.readFileSync", re.compile(r"\bfs\.readFileSync\s*\(([^)]*)\)")),
    ("filesystem", "fs.readFile", re.compile(r"\bfs\.readFile\s*\(([^)]*)\)")),
    ("filesystem", "fs.writeFileSync", re.compile(r"\bfs\.writeFileSync\s*\(([^)]*)\)")),
    ("filesystem", "fs.createReadStream", re.compile(r"\bfs\.createReadStream\s*\(([^)]*)\)")),
    ("filesystem", "res.sendFile", re.compile(r"\bres\.sendFile\s*\(([^)]*)\)")),
    ("filesystem", "res.download", re.compile(r"\bres\.download\s*\(([^)]*)\)")),
    ("database", "db.exec", re.compile(r"\bdb\.exec\s*\(([^)]*)\)")),
    ("database", "db.run", re.compile(r"\bdb\.run\s*\(([^)]*)\)")),
    ("database", "db.prepare", re.compile(r"\bdb\.prepare\s*\(([^)]*)\)")),
    ("database", "db.query", re.compile(r"\bdb\.query\s*\(([^)]*)\)")),
    ("command", "childProcess.execSync", re.compile(r"\bchildProcess\.execSync\s*\(([^)]*)\)")),
    ("command", "childProcess.exec", re.compile(r"\bchildProcess\.exec\s*\(([^)]*)\)")),
    ("command", "childProcess.spawn", re.compile(r"\bchildProcess\.spawn\s*\(([^)]*)\)")),
    ("command", "childProcess.execFileSync", re.compile(r"\bchildProcess\.execFileSync\s*\(([^)]*)\)")),
    ("command", "execSync", re.compile(r"(?<!\.)\bexecSync\s*\(([^)]*)\)")),
)


def _extract_balanced_call_args(lines: list[str], start_line_0: int, open_paren_col: int) -> tuple[list[str], int]:
    """Parse balanced (arg0, arg1, ..., handler) across lines while respecting strings and comments."""
    args: list[str] = []
    cur_chars: list[str] = []
    paren_depth = 0
    brace_depth = 0
    bracket_depth = 0
    in_quote: str | None = None
    in_block_comment = False
    escaped = False
    end_line_0 = start_line_0

    for li in range(start_line_0, len(lines)):
        line = lines[li]
        ci = open_paren_col if li == start_line_0 else 0
        while ci < len(line):
            ch = line[ci]
            nxt = line[ci + 1] if ci + 1 < len(line) else ""

            if in_block_comment:
                cur_chars.append(ch)
                if ch == "*" and nxt == "/":
                    cur_chars.append(nxt)
                    in_block_comment = False
                    ci += 2
                    continue
                ci += 1
                continue

            if in_quote is not None:
                cur_chars.append(ch)
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == in_quote:
                    in_quote = None
                ci += 1
                continue

            if ch == "/" and nxt == "/":
                # Line comment until end of line
                break
            if ch == "/" and nxt == "*":
                in_block_comment = True
                cur_chars.append(ch)
                cur_chars.append(nxt)
                ci += 2
                continue
            if ch in ("'", '"', "`"):
                in_quote = ch
                cur_chars.append(ch)
                ci += 1
                continue

            if ch == "(":
                paren_depth += 1
                if paren_depth > 1:
                    cur_chars.append(ch)
            elif ch == ")":
                paren_depth -= 1
                if paren_depth == 0:
                    end_line_0 = li
                    arg_str = "".join(cur_chars).strip()
                    if arg_str:
                        args.append(arg_str)
                    return args, end_line_0
                cur_chars.append(ch)
            elif ch == "{":
                brace_depth += 1
                cur_chars.append(ch)
            elif ch == "}":
                brace_depth = max(0, brace_depth - 1)
                cur_chars.append(ch)
            elif ch == "[":
                bracket_depth += 1
                cur_chars.append(ch)
            elif ch == "]":
                bracket_depth = max(0, bracket_depth - 1)
                cur_chars.append(ch)
            elif ch == "," and paren_depth == 1 and brace_depth == 0 and bracket_depth == 0:
                args.append("".join(cur_chars).strip())
                cur_chars = []
            else:
                cur_chars.append(ch)
            ci += 1
        cur_chars.append("\n")

    return args, end_line_0


def _normalize_mw_token(raw_arg: str) -> str:
    cleaned = raw_arg.strip()
    if "(" in cleaned and not cleaned.startswith(("(", "async")):
        cleaned = cleaned.split("(", 1)[0].strip()
    return cleaned


def _analyze_handler_slice(handler_lines: list[str], handler_start_line_1: int) -> tuple[list[dict[str, Any]], list[str], list[str], bool]:
    tainted_vars: dict[str, set[str]] = {}
    for _pass in range(2):
        for raw_ln in handler_lines:
            code_ln = raw_ln.split("//", 1)[0].strip()
            m_decl = VAR_DECL_RE.search(code_ln)
            if not m_decl:
                continue
            var_name, rhs = m_decl.group(1), m_decl.group(2)
            sources: set[str] = set()
            for pm in REQ_PARAM_RE.finditer(rhs):
                src_bag = pm.group(1)
                fld = pm.group(2) or pm.group(3)
                sources.add(f"req.{src_bag}.{fld}")
            for known_var, known_srcs in list(tainted_vars.items()):
                if re.search(rf"\b{re.escape(known_var)}\b", rhs):
                    sources.update(known_srcs)
            if sources:
                tainted_vars.setdefault(var_name, set()).update(sources)

    sinks: list[dict[str, Any]] = []
    seen_sinks: set[tuple[str, str, str, int]] = set()
    for offset, raw_ln in enumerate(handler_lines):
        lineno = handler_start_line_1 + offset
        code_ln = raw_ln.split("//", 1)[0]
        for sink_type, sink_name, sink_re in SINK_PATTERNS:
            for sm in sink_re.finditer(code_ln):
                call_args = sm.group(1)
                matched_params: set[str] = set()
                for pm in REQ_PARAM_RE.finditer(call_args):
                    fld = pm.group(2) or pm.group(3)
                    matched_params.add(f"req.{pm.group(1)}.{fld}")
                for var_name, srcs in tainted_vars.items():
                    if re.search(rf"\b{re.escape(var_name)}\b", call_args):
                        matched_params.update(srcs)
                for p in sorted(matched_params):
                    key = (sink_type, p, sink_name, lineno)
                    if key not in seen_sinks:
                        seen_sinks.add(key)
                        sinks.append(
                            {
                                "sink_type": sink_type,
                                "param": p,
                                "sink": sink_name,
                                "line": lineno,
                            }
                        )

    joined_handler = "\n".join(ln.split("//", 1)[0] for ln in handler_lines)
    identity_fields = sorted(set(IDENTITY_FIELD_RE.findall(joined_handler)))
    ownership_comparisons: list[str] = []
    for cm in COMPARISON_EXPR_RE.finditer(joined_handler):
        expr = " ".join(cm.group(1).split())
        if ("req.user" in expr or "ownerId" in expr) and expr not in ownership_comparisons:
            ownership_comparisons.append(expr)

    inline_auth = bool(
        "verifyTokenWithSecret(" in joined_handler
        or "AUTH_TOKEN_SECRET" in joined_handler
        or "WEBHOOK_API_KEY" in joined_handler
    )
    return sinks, identity_fields, ownership_comparisons, inline_auth


def build_rich_route_inventory(run_id: str, dispatcher: DispatcherProtocol) -> list[RichRouteEntry]:
    """Static Express route analysis: middleware chain, auth check, param->sink flows, and ownership checks (Part 2a)."""
    base_routes = build_route_inventory(run_id, dispatcher)
    js_files = _list_source_js_files(run_id, dispatcher)
    file_lines: dict[str, list[str]] = {}
    for rel_path in js_files:
        read_res = dispatcher.call(run_id, "read_file", {"path": rel_path})
        if read_res.ok and isinstance(read_res.output, str):
            file_lines[rel_path] = _strip_numbered_lines(read_res.output)

    # Global app.use(...) middlewares (excluding router mount calls with string path arg0)
    global_middlewares: list[str] = []
    for rel_path, lines in file_lines.items():
        for ln in lines:
            stripped = ln.strip()
            if stripped.startswith(("//", "*", "/*")):
                continue
            for gm in GLOBAL_APP_MW_RE.finditer(ln):
                mw = _normalize_mw_token(gm.group(1))
                if mw and mw not in global_middlewares:
                    global_middlewares.append(mw)

    rich_entries: list[RichRouteEntry] = []
    for br in base_routes:
        lines = file_lines.get(br.file, [])
        start_idx = br.line - 1
        if start_idx < 0 or start_idx >= len(lines):
            rich_entries.append(RichRouteEntry(**br.model_dump()))
            continue

        # Collect any router.use(...) middlewares declared earlier in the same router file
        router_mws: list[str] = []
        for prev_ln in lines[:start_idx]:
            s_prev = prev_ln.strip()
            if s_prev.startswith(("//", "*", "/*")):
                continue
            for rm in ROUTER_MW_RE.finditer(prev_ln):
                mw = _normalize_mw_token(rm.group(1))
                if mw and mw not in router_mws:
                    router_mws.append(mw)

        call_match = ROUTE_CALL_RE.search(lines[start_idx])
        route_mws: list[str] = []
        end_idx = start_idx
        if call_match:
            open_paren = lines[start_idx].find("(", call_match.start())
            if open_paren != -1:
                call_args, end_idx = _extract_balanced_call_args(lines, start_idx, open_paren)
                # call_args[0] is path literal, call_args[-1] is route handler, middle args are route middlewares
                if len(call_args) > 2:
                    for mid_arg in call_args[1:-1]:
                        mw_name = _normalize_mw_token(mid_arg)
                        if mw_name:
                            route_mws.append(mw_name)

        mw_chain = [*global_middlewares, *router_mws, *route_mws]
        handler_slice = lines[start_idx : end_idx + 1]
        sinks, id_fields, owner_cmps, inline_auth = _analyze_handler_slice(handler_slice, br.line)
        mw_auth = any(
            ("auth" in mw.lower() or "admin" in mw.lower())
            for mw in mw_chain
        )

        rich_entries.append(
            RichRouteEntry(
                method=br.method,
                path=br.path,
                file=br.file,
                line=br.line,
                middleware_chain=mw_chain,
                has_auth_check=mw_auth or inline_auth,
                sinks_reached=sinks,
                identity_fields=id_fields,
                ownership_comparisons=owner_cmps,
            )
        )

    return rich_entries
