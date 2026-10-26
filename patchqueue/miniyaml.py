"""Minimal YAML subset reader — stdlib only.

Enough for docker-compose files and patchqueue.yml: block mappings, block
sequences, plain/quoted scalars, flow sequences/maps on one line, comments.
Block scalars (| >) become strings; anchors/tags are ignored; aliases become
None. It is NOT a general YAML parser, and it never executes anything.
"""
from __future__ import annotations

import re


class YamlError(ValueError):
    pass


def _strip_comment(line: str) -> str:
    q = None
    prev = " "
    for i, ch in enumerate(line):
        if q:
            if ch == q:
                q = None
        elif ch in "\"'" and prev in " \t:[{,-":
            q = ch
        elif ch == "#" and prev in " \t":
            return line[:i]
        prev = ch
    return line


def _prep(text: str):
    lines = []
    for raw in text.replace("\r\n", "\n").split("\n"):
        raw = raw.expandtabs(2)
        if raw.strip() in ("---", "..."):
            continue
        s = _strip_comment(raw).rstrip()
        if not s.strip():
            continue
        indent = len(s) - len(s.lstrip(" "))
        lines.append([indent, s.strip()])
    return lines


_KEY = re.compile(
    r"""^(?:"((?:[^"\\]|\\.)*)"|'((?:[^']|'')*)'|([^\s#'"\[\]{},][^#]*?))\s*:(?:\s+(.*))?$"""
)


def _split_key(t: str):
    m = _KEY.match(t)
    if not m:
        return None
    if m.group(1) is not None:
        key = m.group(1)
    elif m.group(2) is not None:
        key = m.group(2).replace("''", "'")
    else:
        key = m.group(3).strip()
    return key, (m.group(4) or "").strip()


def _strip_props(s: str) -> str:
    s = s.strip()
    while s[:1] in ("&", "!"):
        parts = s.split(None, 1)
        s = parts[1].strip() if len(parts) > 1 else ""
    return s


def _split_flow(inner: str):
    out, buf, q, depth = [], "", None, 0
    for ch in inner:
        if q:
            buf += ch
            if ch == q:
                q = None
            continue
        if ch in "\"'":
            q = ch
        elif ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
        elif ch == "," and depth == 0:
            out.append(buf)
            buf = ""
            continue
        buf += ch
    if buf.strip():
        out.append(buf)
    return [x.strip() for x in out if x.strip()]


def _scalar(s: str):
    s = _strip_props(s)
    if not s:
        return None
    if s[0] == '"':
        end = s.find('"', 1)
        while end > 0 and s[end - 1] == "\\":
            end = s.find('"', end + 1)
        inner = s[1:end] if end > 0 else s[1:]
        return inner.replace('\\"', '"').replace("\\n", "\n").replace("\\\\", "\\")
    if s[0] == "'":
        end = 1
        while True:
            end = s.find("'", end)
            if end < 0 or s[end + 1:end + 2] != "'":
                break
            end += 2
        inner = s[1:end] if end > 0 else s[1:]
        return inner.replace("''", "'")
    if s.startswith("[") and s.endswith("]"):
        return [_scalar(x) for x in _split_flow(s[1:-1])]
    if s.startswith("{") and s.endswith("}"):
        d = {}
        for part in _split_flow(s[1:-1]):
            kv = _split_key(part)
            if kv:
                d[kv[0]] = _scalar(kv[1])
        return d
    if s.startswith("*"):
        return None
    low = s.lower()
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    if low in ("null", "~"):
        return None
    return s


def _is_seq(t: str) -> bool:
    return t == "-" or t.startswith("- ")


def _block(lines, i, indent):
    t = lines[i][1]
    if _is_seq(t):
        return _seq(lines, i, indent)
    if _split_key(t) is None:
        return _scalar(t), i + 1
    return _map(lines, i, indent)


def _map(lines, i, indent):
    d = {}
    n = len(lines)
    while i < n:
        ind, t = lines[i]
        if ind < indent:
            break
        if ind > indent:
            i += 1
            continue
        if _is_seq(t):
            break
        kv = _split_key(t)
        if kv is None:
            i += 1
            continue
        k, rest = kv
        i += 1
        rest = _strip_props(rest)
        if rest[:1] in ("|", ">"):
            buf = []
            while i < n and lines[i][0] > ind:
                buf.append(lines[i][1])
                i += 1
            d[k] = "\n".join(buf)
        elif rest == "":
            if i < n and (lines[i][0] > ind or (lines[i][0] == ind and _is_seq(lines[i][1]))):
                d[k], i = _block(lines, i, lines[i][0])
            else:
                d[k] = None
        else:
            d[k] = _scalar(rest)
            while i < n and lines[i][0] > ind:  # continuation of a plain scalar
                i += 1
    return d, i


def _seq(lines, i, indent):
    out = []
    n = len(lines)
    while i < n:
        ind, t = lines[i]
        if ind > indent:
            i += 1
            continue
        if ind < indent or not _is_seq(t):
            break
        rest = t[1:].lstrip()
        off = len(t) - len(rest)
        rest_p = _strip_props(rest)
        if rest_p == "":
            i += 1
            if i < n and lines[i][0] > ind:
                v, i = _block(lines, i, lines[i][0])
            else:
                v = None
            out.append(v)
        elif _is_seq(rest_p):
            lines[i] = [ind + off, rest_p]
            v, i = _seq(lines, i, ind + off)
            out.append(v)
        elif rest_p[0] not in "\"'[{" and _split_key(rest_p) is not None:
            lines[i] = [ind + off, rest_p]
            v, i = _map(lines, i, ind + off)
            out.append(v)
        else:
            out.append(_scalar(rest_p))
            i += 1
            while i < n and lines[i][0] > ind:
                i += 1
    return out, i


def loads(text: str):
    lines = _prep(text)
    if not lines:
        return None
    val, _ = _block(lines, 0, lines[0][0])
    return val
