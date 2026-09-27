"""
Findings and reporters.

A `Finding` is one problem (or note) about one detection file. `Severity.ERROR`
fails the build; `WARNING` and `INFO` are advisory. Reporters render the findings
as human text, machine JSON, or GitHub Actions workflow commands (so problems
show up inline on the PR's Files-changed view).
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum


class Severity(str, Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass(frozen=True)
class Finding:
    file: str
    code: str                     # short slug, e.g. "sigma-missing-field"
    message: str
    severity: Severity = Severity.ERROR
    rule: str = ""                # detection name/title, when known
    line: int | None = None

    def as_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    files_checked: int = 0
    rules_checked: int = 0

    def add(self, f: Finding) -> None:
        self.findings.append(f)

    def extend(self, fs: list[Finding]) -> None:
        self.findings.extend(fs)

    @property
    def errors(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == Severity.ERROR]

    @property
    def warnings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == Severity.WARNING]

    @property
    def ok(self) -> bool:
        return not self.errors

    # --- renderers ---
    def to_text(self) -> str:
        icon = {Severity.ERROR: "✗", Severity.WARNING: "!", Severity.INFO: "·"}
        lines = []
        for f in sorted(self.findings, key=lambda x: (x.file, x.severity.value)):
            loc = f"{f.file}" + (f":{f.line}" if f.line else "")
            rule = f" [{f.rule}]" if f.rule else ""
            lines.append(f"  {icon[f.severity]} {f.severity.value.upper():7} {f.code:26} {loc}{rule}\n      {f.message}")
        header = (
            f"Detection-as-Code validation\n"
            f"  files checked : {self.files_checked}\n"
            f"  rules checked : {self.rules_checked}\n"
            f"  errors        : {len(self.errors)}\n"
            f"  warnings      : {len(self.warnings)}\n"
        )
        body = "\n".join(lines) if lines else "  (no findings)"
        verdict = "PASS" if self.ok else "FAIL"
        return f"{header}\n{body}\n\nResult: {verdict}"

    def to_json(self) -> str:
        return json.dumps(
            {
                "files_checked": self.files_checked,
                "rules_checked": self.rules_checked,
                "errors": len(self.errors),
                "warnings": len(self.warnings),
                "ok": self.ok,
                "findings": [f.as_dict() for f in self.findings],
            },
            indent=2,
        )

    def to_github(self) -> str:
        """GitHub Actions workflow commands -> inline PR annotations."""
        out = []
        for f in self.findings:
            level = "error" if f.severity == Severity.ERROR else (
                "warning" if f.severity == Severity.WARNING else "notice")
            loc = f"file={f.file}" + (f",line={f.line}" if f.line else "")
            title = f"{f.code}" + (f" [{f.rule}]" if f.rule else "")
            msg = f.message.replace("\n", " ")
            out.append(f"::{level} {loc},title={title}::{msg}")
        return "\n".join(out)
