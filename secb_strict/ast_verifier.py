"""Gate 1: tree-sitter localisation scoring.

Maps the gold fix diff (dataset field ``patch``) onto the enclosing function
nodes of the *base-commit* sources, then scores an agent's Stage-A prediction
``{file, symbol, start_line, end_line}`` against them.

Design notes (why this is a metric, not an AND-gate):
  * Many CVEs admit several valid fix sites (validate at the source vs. bounds
    check at the sink). Gating success on "same function as gold" would mark
    valid alternative fixes as failures. Report localisation next to Gate 2
    and cross-tabulate instead.
  * Most security fixes are *pure additions* (a new bounds check). They have no
    pre-image lines, so the hunk is anchored at its insertion point in the old
    file and mapped to the enclosing function there.
  * Gold patches can touch several functions -> gold is a *set* of spans.
  * Pure-Python, no Docker: file contents come from a ``read_file`` callable
    (e.g. ``git show <base_commit>:<path>`` in the container, or a checkout).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from pathlib import PurePosixPath
from typing import Callable, Iterable, Optional

import tree_sitter_c
import tree_sitter_cpp
from tree_sitter import Language, Parser

_C = Language(tree_sitter_c.language())
_CPP = Language(tree_sitter_cpp.language())
_CPP_EXT = {".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx", ".ipp"}
_SRC_EXT = _CPP_EXT | {".c", ".h"}

_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


# --------------------------------------------------------------------------- #
# data
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Span:
    file: str
    symbol: Optional[str]
    start_line: int  # 1-based, inclusive
    end_line: int
    parse_error: bool = False  # enclosing node came from an ERROR-containing tree

    def lines(self) -> range:
        return range(self.start_line, self.end_line + 1)


@dataclass
class LocScore:
    file_hit: bool = False
    symbol_hit: bool = False
    line_hit: bool = False  # predicted lines overlap any gold function span
    iou: float = 0.0  # best line-IoU vs. any gold function span (same file)
    detail: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


# --------------------------------------------------------------------------- #
# diff parsing
# --------------------------------------------------------------------------- #
def _strip_prefix(path: str) -> str:
    path = path.strip().split("\t")[0]
    if path.startswith(("a/", "b/")):
        path = path[2:]
    return path


def changed_old_lines(diff: str) -> dict[str, list[int]]:
    """Return {file: [old-file line numbers touched]} for a unified diff.

    Removed lines contribute their own old line number. A run of added lines
    with no removals contributes the old line it was inserted *before*
    (clamped to >= 1), so pure additions still land inside a function.
    """
    out: dict[str, list[int]] = {}
    cur: Optional[str] = None
    old_ln = 0
    pending_add_anchor: Optional[int] = None
    in_hunk = False

    for raw in diff.splitlines():
        if raw.startswith("--- "):
            in_hunk = False
            old = _strip_prefix(raw[4:])
            cur = None if old == "/dev/null" else old
            continue
        if raw.startswith("+++ "):
            new = _strip_prefix(raw[4:])
            if cur is None and new != "/dev/null":
                cur = new  # newly created file: nothing in base to map
                out.setdefault(cur, [])
            continue
        m = _HUNK_RE.match(raw)
        if m:
            old_ln = int(m.group(1))
            pending_add_anchor = None
            in_hunk = True
            continue
        if not in_hunk or cur is None:
            continue
        if raw.startswith("\\"):  # "\ No newline at end of file"
            continue
        if raw.startswith("-"):
            out.setdefault(cur, []).append(old_ln)
            old_ln += 1
            pending_add_anchor = None
        elif raw.startswith("+"):
            # anchor at the old line the addition precedes; prefer the previous
            # context line if there is one so we stay inside the function body.
            anchor = max(old_ln - 1, 1) if old_ln > 1 else 1
            out.setdefault(cur, []).append(anchor)
            pending_add_anchor = anchor
        else:  # context
            old_ln += 1
            pending_add_anchor = None
    return {f: sorted(set(v)) for f, v in out.items()}


# --------------------------------------------------------------------------- #
# tree-sitter function mapping
# --------------------------------------------------------------------------- #
def _lang_for(path: str) -> Optional[Language]:
    ext = PurePosixPath(path).suffix.lower()
    if ext in _CPP_EXT:
        return _CPP
    if ext in {".c", ".h"}:
        return _C
    return None


def _decl_name(declarator) -> Optional[str]:
    """Walk a (possibly nested pointer/function) declarator to its identifier."""
    node = declarator
    while node is not None:
        if node.type in {
            "identifier",
            "field_identifier",
            "qualified_identifier",
            "destructor_name",
            "operator_name",
            "type_identifier",
        }:
            return node.text.decode("utf8", "replace")
        nxt = node.child_by_field_name("declarator")
        if nxt is None:
            # e.g. qualified_identifier handled above; otherwise first named child
            nxt = next((c for c in node.named_children), None)
            if nxt is node:
                return None
        node = nxt
    return None


def functions_in(source: str, path: str) -> list[Span]:
    """All function_definition spans in `source` (1-based, inclusive)."""
    lang = _lang_for(path)
    if lang is None:
        return []
    tree = Parser(lang).parse(source.encode("utf8", "replace"))
    spans: list[Span] = []
    stack = [tree.root_node]
    while stack:
        n = stack.pop()
        if n.type == "function_definition":
            name = _decl_name(n.child_by_field_name("declarator"))
            spans.append(
                Span(path, name, n.start_point[0] + 1, n.end_point[0] + 1, n.has_error)
            )
        stack.extend(n.children)
    return sorted(spans, key=lambda s: (s.start_line, -s.end_line))


def _innermost(spans: Iterable[Span], line: int) -> Optional[Span]:
    best: Optional[Span] = None
    for s in spans:
        if s.start_line <= line <= s.end_line:
            if best is None or (s.end_line - s.start_line) < (best.end_line - best.start_line):
                best = s
    return best


def gold_spans(
    gold_diff: str, read_base_file: Callable[[str], Optional[str]]
) -> tuple[list[Span], list[str]]:
    """Map the gold diff to enclosing function spans in the base commit.

    Returns (spans, unmapped_files). `unmapped_files` lists touched files that
    are not C/C++ sources, are new, or have changed lines outside any function
    (globals, macros, struct defs) -- report these rather than hiding them,
    because the patch collector only keeps C/C++ pathspecs anyway.
    """
    spans: list[Span] = []
    unmapped: list[str] = []
    for path, lines in changed_old_lines(gold_diff).items():
        if PurePosixPath(path).suffix.lower() not in _SRC_EXT:
            unmapped.append(path)
            continue
        src = read_base_file(path)
        if src is None or not lines:
            unmapped.append(path)
            continue
        fns = functions_in(src, path)
        hit_any = False
        for ln in lines:
            s = _innermost(fns, ln)
            if s is not None:
                hit_any = True
                if s not in spans:
                    spans.append(s)
        if not hit_any:
            unmapped.append(path)
    return spans, unmapped


# --------------------------------------------------------------------------- #
# scoring
# --------------------------------------------------------------------------- #
def _bare(sym: Optional[str]) -> Optional[str]:
    # "Foo::bar" and "bar" should match; compare the last component.
    return sym.split("::")[-1] if sym else sym


def _norm_file(p: str, work_dir: str = "") -> str:
    p = p.strip()
    if work_dir and p.startswith(work_dir.rstrip("/") + "/"):
        p = p[len(work_dir.rstrip("/")) + 1 :]
    return p.lstrip("./")


def score_prediction(
    pred: dict, gold: list[Span], work_dir: str = ""
) -> LocScore:
    """Score a Stage-A prediction {file, symbol, start_line, end_line}."""
    sc = LocScore()
    pf = _norm_file(str(pred.get("file", "")), work_dir)
    psym = _bare(pred.get("symbol"))
    try:
        ps, pe = int(pred["start_line"]), int(pred["end_line"])
    except (KeyError, TypeError, ValueError):
        sc.detail["error"] = "bad_line_range"
        return sc
    if pe < ps:
        ps, pe = pe, ps
    pred_lines = set(range(ps, pe + 1))
    best_iou = 0.0
    for g in gold:
        if not same_file(_norm_file(g.file), pf):
            continue
        sc.file_hit = True
        if psym and _bare(g.symbol) == psym:
            sc.symbol_hit = True
        glines = set(g.lines())
        inter = len(pred_lines & glines)
        if inter:
            sc.line_hit = True
        union = len(pred_lines | glines)
        best_iou = max(best_iou, inter / union if union else 0.0)
    sc.iou = round(best_iou, 4)
    sc.detail["n_gold_spans"] = len(gold)
    return sc


# --------------------------------------------------------------------------- #
# mandatory baseline: top in-repo frame of the sanitizer report
# --------------------------------------------------------------------------- #
_FRAME_RE = re.compile(
    r"^\s*#(\d+)\s+0x[0-9a-fA-F]+\s+in\s+(.+?)\s+(\S+?):(\d+)(?::\d+)?\s*$", re.M
)
_RUNTIME_RE = re.compile(
    r"libsanitizer|compiler-rt|/asan/|/ubsan/|asan_|ubsan_|sanitizer_common|interceptor", re.I
)
_SYSTEM_PREFIXES = ("/usr/", "/lib/", "/src/llvm", "/llvm-project/", "/build/glibc")


def sanitizer_frames(report: str, work_dir: str = "") -> list[dict]:
    """Parse ASan/UBSan frames -> [{n, symbol, file, line}] (all frames)."""
    frames = []
    for m in _FRAME_RE.finditer(report or ""):
        frames.append(
            {"n": int(m.group(1)), "symbol": m.group(2).split("(")[0].strip(),
             "file": m.group(3), "line": int(m.group(4))}
        )
    return frames


def crash_frame_baseline(report: str, work_dir: str) -> Optional[dict]:
    """First frame that lives under the repo (not libc/libasan/llvm).

    This is the *free* localisation the patch prompt already hands the agent
    (SEC-bench's patch.j2 embeds the sanitizer report). Any claimed Stage-A
    skill must beat this baseline to mean anything.
    """
    wd = work_dir.rstrip("/") + "/"
    frames = sanitizer_frames(report, work_dir)
    for f in frames:
        if (f["file"].startswith(wd) and not f["file"].startswith(_SYSTEM_PREFIXES)
                and not _RUNTIME_RE.search(f["file"])):
            return {"file": _norm_file(f["file"], work_dir), "symbol": f["symbol"],
                    "start_line": f["line"], "end_line": f["line"]}
    # Fallback: many dataset reports (esp. the CVE split) were captured on the
    # reporter's machine, e.g. /home/<user>/.../proj_<hash>/src/x.c, not under
    # work_dir. Take the first non-system frame in a C/C++ source file and keep
    # the raw path; callers compare with `same_file` (path-suffix match).
    for f in frames:
        if f["file"].startswith(_SYSTEM_PREFIXES) or _RUNTIME_RE.search(f["file"]):
            continue
        if PurePosixPath(f["file"]).suffix.lower() in _SRC_EXT:
            return {"file": f["file"].lstrip("./"), "symbol": f["symbol"],
                    "start_line": f["line"], "end_line": f["line"], "raw_path": True}
    return None


def same_file(a: str, b: str) -> bool:
    """Exact match, or one path is a '/'-boundary suffix of the other."""
    a, b = a.lstrip("./"), b.lstrip("./")
    return a == b or a.endswith("/" + b) or b.endswith("/" + a)


def crash_signature(report: str, work_dir: str, depth: int = 3) -> tuple:
    """(sanitizer kind, top-`depth` in-repo function names) for same/shifted-crash tests."""
    kind = re.search(r"(?:ERROR|WARNING): (\w+Sanitizer): ([\w\-]+)", report or "")
    wd = work_dir.rstrip("/") + "/"
    fns = [f["symbol"] for f in sanitizer_frames(report, work_dir) if f["file"].startswith(wd)]
    return (kind.groups() if kind else None, tuple(fns[:depth]))
