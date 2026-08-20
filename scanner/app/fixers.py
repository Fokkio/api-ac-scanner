"""Auto-fix (preview-then-apply) generators for detected findings.

Each fixer takes the original code string and returns a tuple:
    (fixed_code: str, changes: list[str])
If no fix is available, returns (original, []).
"""

from __future__ import annotations
import re


def _nodejs_bola_fix(code: str):
    """Inject an ownership guard after a model lookup that uses a user id."""
    changes = []
    # Pattern: const x = Model.findById(req.params.id)
    pat = re.compile(
        r"(const\s+\w+\s*=\s*\w+\.find(?:ById|One|ByPk)\s*\(\s*req\.(?:params|query|body)\.\w+[^;]*\)\s*;)",
        re.MULTILINE,
    )

    def repl(m):
        stmt = m.group(1)
        indent = "  "
        guard = (
            f"\n{indent}// [API-AC-SCANNER] BOLA guard: verify caller owns the object\n"
            f"{indent}if (!{_obj_var(stmt)}.ownerId && {_obj_var(stmt)}.owner_id !== req.user?.id "
            f"&& req.user?.role !== 'admin') {{\n"
            f"{indent}  return res.status(403).json({{ error: 'forbidden' }});\n"
            f"{indent}}}"
        )
        changes.append("Added ownership guard (req.user.id / role === 'admin') before object use.")
        return stmt + guard

    fixed = pat.sub(repl, code)
    return fixed, changes


def _obj_var(stmt: str) -> str:
    m = re.search(r"const\s+(\w+)\s*=", stmt)
    return m.group(1) if m else "obj"


def _nodejs_mass_assignment_fix(code: str):
    changes = []
    # const data = req.body -> explicit pick
    pat = re.compile(r"(\w+)\.create\(\s*req\.body\s*\)", re.MULTILINE)
    if pat.search(code):
        fixed = pat.sub(
            lambda m: (
                f"{m.group(1)}.create(sanitizeInput(req.body))  "
                "// [API-AC-SCANNER] replaced req.body with allowlisted copy"
            ),
            code,
        )
        changes.append("Replaced raw req.body with sanitizeInput() allowlist before create().")
        # ensure a helper note is present
        if "function sanitizeInput" not in fixed:
            fixed += (
                "\n\n// [API-AC-SCANNER] add an allowlist appropriate to your model\n"
                "function sanitizeInput(body) {\n"
                "  const ALLOW = ['name', 'email'];\n"
                "  return Object.fromEntries(Object.entries(body).filter(([k]) => ALLOW.includes(k)));\n"
                "}\n"
            )
            changes.append("Appended sanitizeInput() allowlist helper.")
        return fixed, changes
    return code, changes


def fix_for(rule_id: str, code: str):
    if rule_id == "nodejs-bola-object":
        return _nodejs_bola_fix(code)
    if rule_id == "nodejs-mass-assignment":
        return _nodejs_mass_assignment_fix(code)
    return code, []
