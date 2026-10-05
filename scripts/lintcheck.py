"""Stand-in static checks for environments without ruff or mypy.

Run with: python scripts/lintcheck.py

This is not a replacement for ruff — it exists because this project was built in an
environment with no package-index access. If ruff and mypy are available, prefer:

    ruff check .
    mypy velora


It catches the classes of problem most likely to matter here: unused imports,
mutable default arguments, bare excepts, and syntax errors.
"""
import ast, pathlib, sys, symtable

problems = []
for path in sorted(pathlib.Path("velora").rglob("*.py")):
    src = path.read_text()
    tree = ast.parse(src, filename=str(path))
    imported, used = {}, set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                imported[(a.asname or a.name.split(".")[0])] = node.lineno
        elif isinstance(node, ast.ImportFrom):
            for a in node.names:
                if a.name != "*":
                    imported[(a.asname or a.name)] = node.lineno
        elif isinstance(node, ast.Name):
            used.add(node.id)
        elif isinstance(node, ast.Attribute):
            n = node
            while isinstance(n, ast.Attribute):
                n = n.value
            if isinstance(n, ast.Name):
                used.add(n.id)
    # names can also appear in string annotations
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            for name in imported:
                if name in node.value:
                    used.add(name)
    lines = src.splitlines()
    for name, lineno in imported.items():
        line = lines[lineno - 1] if lineno <= len(lines) else ""
        if "noqa: F401" in line or "noqa: F401," in line:
            continue        # deliberate side-effect import
        if name not in used and name != "annotations":
            problems.append(f"{path}:{lineno}: unused import {name!r}")
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for d in node.args.defaults + [x for x in node.args.kw_defaults if x]:
                if isinstance(d, (ast.List, ast.Dict, ast.Set)):
                    problems.append(f"{path}:{d.lineno}: mutable default argument")
        if isinstance(node, ast.ExceptHandler) and node.type is None:
            problems.append(f"{path}:{node.lineno}: bare except")
for p in problems:
    print(p)
print(f"\n{len(problems)} problem(s)")
sys.exit(1 if problems else 0)
