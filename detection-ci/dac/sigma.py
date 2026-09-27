"""
Sigma rule linter.

Checks the structural rules that keep a Sigma corpus healthy and portable:
required fields, a valid `status`/`level`, a `logsource`, a `detection` block
with a `condition`, that every named search identifier the condition references
actually exists, and well-formed ATT&CK tags (`attack.tNNNN[.NNN]`). These are
the same checks a `sigma check` gate would enforce, kept dependency-free.
"""

from __future__ import annotations

import re

import yaml

from .report import Finding, Severity

_VALID_STATUS = {"stable", "test", "experimental", "deprecated", "unsupported"}
_VALID_LEVEL = {"informational", "low", "medium", "high", "critical"}
_ATTACK_TECH_RE = re.compile(r"^attack\.t\d{4}(?:\.\d{3})?$", re.IGNORECASE)
_CONDITION_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_CONDITION_KEYWORDS = {
    "and", "or", "not", "of", "them", "all", "1", "any", "sum", "min", "max",
    "count", "avg", "by", "near", "|",
}


def lint_sigma_text(text: str, path: str = "") -> list[Finding]:
    findings: list[Finding] = []
    try:
        docs = list(yaml.safe_load_all(text))
    except yaml.YAMLError as exc:
        return [Finding(file=path, code="sigma-invalid-yaml",
                        message=f"YAML parse error: {exc}", severity=Severity.ERROR)]

    doc_count = 0
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        doc_count += 1
        findings.extend(_lint_doc(doc, path))
    if doc_count == 0:
        findings.append(Finding(file=path, code="sigma-empty",
                                message="No Sigma rule documents found in file",
                                severity=Severity.ERROR))
    return findings


def _lint_doc(doc: dict, path: str) -> list[Finding]:
    out: list[Finding] = []
    name = str(doc.get("title", "(untitled)"))

    def err(code: str, msg: str, sev: Severity = Severity.ERROR) -> None:
        out.append(Finding(file=path, code=code, message=msg, severity=sev, rule=name))

    # Required top-level fields
    for fieldname in ("title", "logsource", "detection"):
        if fieldname not in doc:
            err("sigma-missing-field", f"missing required field '{fieldname}'")

    if "id" not in doc:
        err("sigma-missing-id", "rule has no 'id' (UUID recommended for tracking)", Severity.WARNING)

    status = str(doc.get("status", "")).lower()
    if status and status not in _VALID_STATUS:
        err("sigma-bad-status", f"status {status!r} is not one of {sorted(_VALID_STATUS)}")

    level = str(doc.get("level", "")).lower()
    if not level:
        err("sigma-missing-level", "rule has no 'level'", Severity.WARNING)
    elif level not in _VALID_LEVEL:
        err("sigma-bad-level", f"level {level!r} is not one of {sorted(_VALID_LEVEL)}")

    # logsource should have at least one selector
    ls = doc.get("logsource")
    if isinstance(ls, dict):
        if not any(k in ls for k in ("category", "product", "service")):
            err("sigma-bad-logsource", "logsource needs at least one of category/product/service")
    elif "logsource" in doc:
        err("sigma-bad-logsource", "logsource must be a mapping")

    # ATT&CK tags
    tags = doc.get("tags", []) or []
    tech_tags = [t for t in tags if str(t).lower().startswith("attack.t")]
    for t in tech_tags:
        if not _ATTACK_TECH_RE.match(str(t)):
            err("sigma-bad-attack-tag", f"malformed ATT&CK technique tag {t!r}")
    if not tech_tags:
        err("sigma-no-attack-tag", "rule has no ATT&CK technique tag (attack.tNNNN)", Severity.WARNING)

    # detection block + condition + identifier resolution
    det = doc.get("detection")
    if isinstance(det, dict):
        if "condition" not in det:
            err("sigma-no-condition", "detection block has no 'condition'")
        else:
            identifiers = {k for k in det if k != "condition"}
            if not identifiers:
                err("sigma-no-selection", "detection block defines no search identifiers")
            conditions = det["condition"]
            cond_text = " ".join(conditions) if isinstance(conditions, list) else str(conditions)
            referenced = {
                tok for tok in _CONDITION_IDENT_RE.findall(cond_text)
                if tok.lower() not in _CONDITION_KEYWORDS
            }
            for ref in referenced:
                # allow wildcard patterns like 'selection*'
                if any(ident == ref or ident.startswith(ref.rstrip("*")) for ident in identifiers):
                    continue
                if "*" in cond_text:  # wildcard condition; skip strict resolution
                    continue
                err("sigma-unknown-identifier",
                    f"condition references '{ref}' but no such search identifier is defined")
    elif "detection" in doc:
        err("sigma-bad-detection", "detection must be a mapping")

    return out
