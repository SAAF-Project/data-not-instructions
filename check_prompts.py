"""check_prompts: CI check that fails when untrusted documents reach an LLM prompt unguarded.

Static (AST) heuristic for Python. In every file that calls an LLM API, it
flags f-strings and string concatenations that interpolate a document-like
variable (text, document, report, evidence, policy, pdf, page, ...) unless
the value went through data_not_instructions (guard(...).wrapped / wrap(...)).

    python check_prompts.py [PATH ...]        # default: current directory
    exit 0 = completed, no recognised hits; 1 = hits; 2 = incomplete scan

Suppress a reviewed line with a trailing comment:  # dni: ok
"""

from __future__ import annotations

import ast
import os
import re
import sys
from pathlib import Path

LLM_CALL = re.compile(
    r"messages\.create|messages\.stream|chat\.completions\.create|responses\.create|"
    r"generate_content|ClaudeSDKClient|claude_agent_sdk|ChatAnthropic|ChatOpenAI|\.invoke\("
)
DOC_NAME = re.compile(
    r"(^|_)(text|texts|document|documents|doc|docs|content|report|evidence|policy|"
    r"pdf|page|pages|notes|transcript|email|upload|uploaded|extracted|raw|body)(_|$)",
    re.IGNORECASE,
)
SAFE_NAME = re.compile(r"(prompt|instruction|template|system|task|label|title|header|name|id|path|url)s?$", re.I)
GUARD_FUNCS = {"guard", "wrap"}
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "site-packages", "tests", "test"}


class ScanError(Exception):
    """Requested source could not be completely assessed."""


def _name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        if node.attr == "wrapped":  # guard(...).wrapped / doc.wrapped
            return None
        return node.attr
    if isinstance(node, ast.Subscript):
        return _name(node.value)
    if isinstance(node, ast.Call):
        f = node.func
        fname = f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else ""
        if fname in GUARD_FUNCS:
            return None
        if fname in {"str", "strip", "join", "format"} and node.args:
            return _name(node.args[0])
        if isinstance(f, ast.Attribute) and fname in {"strip", "lower", "upper"}:
            return _name(f.value)
    return None


def _is_doc(name: str | None) -> bool:
    return bool(name) and bool(DOC_NAME.search(name)) and not SAFE_NAME.search(name)


def check_file(path: Path) -> list[tuple[int, str]]:
    try:
        src = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ScanError(f"{path}: source could not be read as UTF-8") from exc
    try:
        tree = ast.parse(src, filename=str(path))
    except (SyntaxError, ValueError) as exc:
        raise ScanError(f"{path}: Python could not be parsed") from exc
    if not LLM_CALL.search(src):
        return []
    lines = src.splitlines()
    hits: list[tuple[int, str]] = []

    def report(node: ast.AST, name: str) -> None:
        line = getattr(node, "lineno", 0)
        if 0 < line <= len(lines) and "dni: ok" in lines[line - 1]:
            return
        hits.append((line, name))

    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            for part in node.values:
                if isinstance(part, ast.FormattedValue):
                    n = _name(part.value)
                    if _is_doc(n):
                        report(part.value, n)
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            # "Report:\n" + report_text
            sides = (node.left, node.right)
            if any(isinstance(s, ast.Constant) and isinstance(s.value, str) for s in sides):
                for s in sides:
                    n = _name(s)
                    if _is_doc(n):
                        report(s, n)
    # one hit per (line, name)
    return sorted(set(hits))


def iter_py(paths: list[Path]):
    for root in paths:
        if not root.exists() or root.is_symlink():
            raise ScanError(f"{root}: missing or symlink target is not assessed")
        files = []
        if root.is_file() and root.suffix == ".py":
            files = [root]
        elif root.is_dir():
            def walk_error(error):
                raise ScanError(f"{root}: directory traversal failed") from error
            for directory, dirs, names in os.walk(root, followlinks=False, onerror=walk_error):
                for name in dirs:
                    child = Path(directory) / name
                    if name not in SKIP_DIRS and child.is_symlink():
                        raise ScanError(f"{child}: symlink directory is not assessed")
                dirs[:] = sorted(name for name in dirs if name not in SKIP_DIRS)
                files.extend(Path(directory) / name for name in sorted(names) if name.endswith(".py"))
        files = [f for f in files if f.name not in {"check_prompts.py", "data_not_instructions.py"}]
        if not files:
            raise ScanError(f"{root}: no Python source files in scan scope")
        for source in files:
            if source.is_symlink() or not source.is_file():
                raise ScanError(f"{source}: source is not a regular file")
            yield source


def main(argv: list[str]) -> int:
    roots = [Path(a) for a in argv] or [Path(".")]
    total, errors = 0, []
    for root in roots:
        try:
            for f in iter_py([root]):
                for line, name in check_file(f):
                    total += 1
                    print(f"{str(f)!r}:{line}: untrusted '{name}' interpolated into an LLM prompt without data_not_instructions.guard()")
        except ScanError as exc:
            errors.append(str(exc))
    if errors:
        for error in errors:
            print(f"check_prompts: NOT ASSESSED: {error!r}", file=sys.stderr)
        return 2
    if total:
        print(f"\n{total} unguarded prompt interpolation(s). Wrap untrusted documents with "
              "guard(text, source=...).wrapped and add SYSTEM_RULE to the system prompt, "
              "or mark a reviewed line with '# dni: ok'.")
        return 1
    print("check_prompts: no unguarded document interpolation found.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
