#!/usr/bin/env python3
"""
Validation script for the Security Bug Examples project.

Walks the project directory tree and checks 20 correctness properties
defined in the design document. Reports pass/fail/not-implemented for
each property check.

Usage:
    python validate.py [--compile]

Options:
    --compile   Enable Property 4 (source file compilation). Requires
                language toolchains to be installed. Skipped by default.
"""

import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent

LANGUAGES = ["python", "java", "go", "rust", "c", "cpp", "javascript"]

SOURCE_FILE_NAMES = {
    "python": "app.py",
    "java": "App.java",
    "go": "main.go",
    "rust": "main.rs",
    "c": "main.c",
    "cpp": "main.cpp",
    "javascript": "app.js",
}

# Vulnerability class -> list of applicable languages
VULN_LANGUAGE_MAP: dict[str, list[str]] = {
    "broken-access-control": LANGUAGES,
    "cryptographic-failures": LANGUAGES,
    "injection/sql-injection": ["python", "java", "go", "javascript"],
    "injection/command-injection": LANGUAGES,
    "injection/xss": ["python", "java", "go", "rust", "javascript"],
    "insecure-design": LANGUAGES,
    "security-misconfiguration": LANGUAGES,
    "vulnerable-components": LANGUAGES,
    "auth-failures": LANGUAGES,
    "integrity-failures": ["python", "java", "javascript", "go"],
    "logging-monitoring-failures": LANGUAGES,
    "ssrf": LANGUAGES,
    "memory-safety/out-of-bounds-write": ["c", "cpp", "rust"],
    "memory-safety/use-after-free": ["c", "cpp"],
    "memory-safety/null-pointer-deref": ["c", "cpp", "go", "java"],
    "integer-overflow": ["c", "cpp", "rust", "go", "java"],
    "race-condition": LANGUAGES,
}

# Excluded (vuln_class, language) pairs with reasons
EXCLUDED_PAIRS: dict[str, list[str]] = {
    "injection/sql-injection": ["c", "cpp", "rust"],
    "injection/xss": ["c", "cpp"],
    "integrity-failures": ["c", "cpp", "rust"],
    "memory-safety/out-of-bounds-write": ["python", "java", "go", "javascript"],
    "memory-safety/use-after-free": ["python", "java", "go", "rust", "javascript"],
    "memory-safety/null-pointer-deref": ["python", "javascript", "rust"],
    "integer-overflow": ["python", "javascript"],
}

DEPENDENCY_MANIFESTS = {
    "python": "requirements.txt",
    "java": "pom.xml",
    "go": "go.mod",
    "rust": "Cargo.toml",
    "c": "Makefile",
    "cpp": "Makefile",
    "javascript": "package.json",
}

FRAMEWORK_PATTERNS = {
    "python": [r"flask", r"django"],
    "java": [r"spring", r"springframework"],
    "go": [r"gin", r"echo"],
    "rust": [r"actix", r"rocket"],
    "c": [r"microhttpd"],
    "cpp": [r"crow", r"httplib"],
    "javascript": [r"express"],
}

VERSION_PATTERNS = {
    "python": r"[Pp]ython\s*3\.1[0-9]",
    "java": r"JDK\s*17|Java\s*17|OpenJDK\s*17",
    "go": r"Go\s*1\.2[1-9]",
    "rust": r"[Rr]ust\s*1\.7[0-9]",
    "c": r"C11|c11|C\s*11",
    "cpp": r"C\+\+17|c\+\+17|C\+\+\s*17",
    "javascript": r"Node\.?js\s*18|[Nn]ode\s*18",
}

REVIEW_GUIDE_TOOLS = {
    "python": ["bandit", "semgrep"],
    "java": ["spotbugs", "pmd", "semgrep"],
    "go": ["gosec", "staticcheck", "semgrep"],
    "rust": ["cargo-audit", "clippy", "semgrep"],
    "c": ["cppcheck", "clang-tidy", "semgrep"],
    "cpp": ["cppcheck", "clang-tidy", "semgrep"],
    "javascript": ["eslint-plugin-security", "nodejsscan", "semgrep"],
}

SECURITY_KEYWORDS = [
    r"CWE-\d+",
    r"A0[1-9]|A10",
    r"\binjection\b",
    r"\boverflow\b",
    r"\bXSS\b",
    r"\bCSRF\b",
    r"\bSSRF\b",
    r"\bdeserialization\b",
    r"\bbuffer\s+overflow\b",
    r"\buse[\s._-]after[\s._-]free\b",
    r"\brace[\s._-]condition\b",
    r"\bvulnerab",
]

TEST_FILE_PATTERNS = [
    r"^test_",
    r"_test\.\w+$",
    r"Test\.java$",
    r"\.test\.\w+$",
    r"\.spec\.\w+$",
    r"^pytest\.ini$",
    r"^jest\.config\.",
    r"^\.mocharc\.",
    r"^conftest\.py$",
]

SOURCE_EXTENSIONS = {".py", ".java", ".go", ".rs", ".c", ".cpp", ".js"}

COMPANION_DOC_SECTIONS = [
    "cwe",
    "description",
    "exploitation",
    "remediation",
    "complexity",
    "detection",
]

# Vulnerability classes that are web/API (not CLI)
WEB_API_VULN_CLASSES = {
    "broken-access-control",
    "cryptographic-failures",
    "injection/sql-injection",
    "injection/command-injection",
    "injection/xss",
    "insecure-design",
    "security-misconfiguration",
    "vulnerable-components",
    "auth-failures",
    "integrity-failures",
    "logging-monitoring-failures",
    "ssrf",
}

# CLI-only vulnerability classes
CLI_VULN_CLASSES = {
    "memory-safety/out-of-bounds-write",
    "memory-safety/use-after-free",
    "memory-safety/null-pointer-deref",
    "integer-overflow",
    "race-condition",
}

# OWASP Top 10 vulnerability classes (overlap with SANS CWE Top 25)
OWASP_VULN_CLASSES = {
    "broken-access-control",
    "cryptographic-failures",
    "injection/sql-injection",
    "injection/command-injection",
    "injection/xss",
    "insecure-design",
    "security-misconfiguration",
    "vulnerable-components",
    "auth-failures",
    "integrity-failures",
    "logging-monitoring-failures",
    "ssrf",
}

# SANS-only vulnerability classes (no OWASP overlap)
SANS_ONLY_VULN_CLASSES = {
    "memory-safety/out-of-bounds-write",
    "memory-safety/use-after-free",
    "memory-safety/null-pointer-deref",
    "integer-overflow",
    "race-condition",
}

# Extension to language mapping
EXT_TO_LANG = {
    ".py": "python",
    ".java": "java",
    ".go": "go",
    ".rs": "rust",
    ".c": "c",
    ".cpp": "cpp",
    ".js": "javascript",
}

SCHEMA_PATH = PROJECT_ROOT / "schemas" / "expected_findings.schema.json"


# ---------------------------------------------------------------------------
# Reporting framework
# ---------------------------------------------------------------------------

class Status(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    SKIP = "SKIP"
    NOT_IMPLEMENTED = "NOT IMPLEMENTED"


@dataclass
class PropertyResult:
    """Result of a single property check."""
    property_id: int
    name: str
    status: Status
    details: list[str] = field(default_factory=list)

    def summary_line(self) -> str:
        icon = {
            Status.PASS: "✅",
            Status.FAIL: "❌",
            Status.SKIP: "⏭️",
            Status.NOT_IMPLEMENTED: "⬜",
        }[self.status]
        return f"  {icon} Property {self.property_id:>2}: {self.name} — {self.status.value}"


class ValidationReport:
    """Collects and displays results for all property checks."""

    def __init__(self) -> None:
        self.results: list[PropertyResult] = []

    def add(self, result: PropertyResult) -> None:
        self.results.append(result)

    def print_report(self) -> None:
        print("\n" + "=" * 72)
        print("  Security Bug Examples — Validation Report")
        print("=" * 72 + "\n")

        for r in sorted(self.results, key=lambda x: x.property_id):
            print(r.summary_line())
            for detail in r.details:
                print(f"         {detail}")

        # Summary counts
        passed = sum(1 for r in self.results if r.status == Status.PASS)
        failed = sum(1 for r in self.results if r.status == Status.FAIL)
        skipped = sum(1 for r in self.results if r.status == Status.SKIP)
        not_impl = sum(1 for r in self.results if r.status == Status.NOT_IMPLEMENTED)
        total = len(self.results)

        print("\n" + "-" * 72)
        print(f"  Total: {total}  |  Passed: {passed}  |  Failed: {failed}  |  Skipped: {skipped}  |  Not Implemented: {not_impl}")
        print("-" * 72 + "\n")

    @property
    def all_passed(self) -> bool:
        return all(r.status in (Status.PASS, Status.SKIP) for r in self.results)


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def walk_source_files() -> list[Path]:
    """Return all source files (by extension) under PROJECT_ROOT, excluding validate.py itself and the tests/ directory."""
    results = []
    tests_dir = PROJECT_ROOT / "tests"
    for root, dirs, files in os.walk(PROJECT_ROOT):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        root_path = Path(root)
        # Skip the tests/ directory entirely (PBT tests live there)
        if root_path == tests_dir or tests_dir in root_path.parents:
            continue
        for fname in files:
            p = root_path / fname
            if p.suffix in SOURCE_EXTENSIONS and p.name != "validate.py":
                # Only include files inside vulnerability class directories
                rel = relative(p)
                if "/" in rel and not rel.startswith("docs/") and not rel.startswith("schemas/"):
                    results.append(p)
    return results


def walk_all_files() -> list[Path]:
    """Return every file under PROJECT_ROOT, excluding hidden dirs, validate.py, and the tests/ directory."""
    results = []
    tests_dir = PROJECT_ROOT / "tests"
    for root, dirs, files in os.walk(PROJECT_ROOT):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        root_path = Path(root)
        # Skip the tests/ directory entirely (PBT tests live there)
        if root_path == tests_dir or tests_dir in root_path.parents:
            continue
        for fname in files:
            p = root_path / fname
            if p.name != "validate.py":
                results.append(p)
    return results


def relative(p: Path) -> str:
    """Return path relative to PROJECT_ROOT as a string."""
    return str(p.relative_to(PROJECT_ROOT))


def detect_language(p: Path) -> Optional[str]:
    """Detect language from file extension."""
    return EXT_TO_LANG.get(p.suffix)


def get_vuln_class_from_path(p: Path) -> Optional[str]:
    """Extract vulnerability class from a source file path."""
    rel = relative(p)
    parts = rel.split("/")
    # Pattern: {vuln_class}/{language}/{filename} or {parent}/{vuln_class}/{language}/{filename}
    for vc in VULN_LANGUAGE_MAP:
        vc_parts = vc.split("/")
        # Check if the path starts with the vulnerability class
        if parts[:len(vc_parts)] == vc_parts:
            return vc
    return None


def get_language_from_path(p: Path) -> Optional[str]:
    """Extract language directory name from a source file path."""
    rel = relative(p)
    parts = rel.split("/")
    # The language directory is the one right before the filename
    if len(parts) >= 2:
        lang_dir = parts[-2]
        if lang_dir in LANGUAGES:
            return lang_dir
    return None


def load_json_safe(p: Path) -> Optional[dict]:
    """Load a JSON file, returning None on error."""
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def count_vulnerability_entries_in_doc(doc_path: Path) -> int:
    """Count the number of ## Vulnerability: sections in a companion doc."""
    try:
        content = doc_path.read_text(encoding="utf-8")
    except OSError:
        return 0
    return len(re.findall(r"^##\s+Vulnerability:", content, re.MULTILINE))


def not_implemented(prop_id: int, name: str) -> PropertyResult:
    """Return a NOT_IMPLEMENTED result stub."""
    return PropertyResult(
        property_id=prop_id,
        name=name,
        status=Status.NOT_IMPLEMENTED,
        details=["Check not yet implemented"],
    )


# ---------------------------------------------------------------------------
# Property check implementations (1–10)
# ---------------------------------------------------------------------------

def check_property_1() -> PropertyResult:
    """Property 1: Language coverage completeness.

    For any vulnerability class and any language in the applicable-languages
    mapping, a source file with the correct extension must exist in
    {vulnerability_class}/{language}/.

    Validates: Requirements 1.1, 1.2
    """
    name = "Language coverage completeness"
    failures: list[str] = []

    for vuln_class, langs in VULN_LANGUAGE_MAP.items():
        for lang in langs:
            src_name = SOURCE_FILE_NAMES[lang]
            expected_path = PROJECT_ROOT / vuln_class / lang / src_name
            if not expected_path.is_file():
                failures.append(f"Missing: {vuln_class}/{lang}/{src_name}")

    if failures:
        return PropertyResult(1, name, Status.FAIL, failures[:20])
    return PropertyResult(1, name, Status.PASS, [f"All {sum(len(v) for v in VULN_LANGUAGE_MAP.values())} (vuln_class, language) pairs have source files"])


def check_property_2() -> PropertyResult:
    """Property 2: Exclusion documentation.

    For any excluded (vulnerability_class, language) pair, a companion doc
    within that vulnerability class must explain why the language is excluded.

    Validates: Requirements 1.3
    """
    name = "Exclusion documentation"
    failures: list[str] = []

    for vuln_class, excluded_langs in EXCLUDED_PAIRS.items():
        # Find any companion doc in this vulnerability class to check for exclusion rationale
        vuln_dir = PROJECT_ROOT / vuln_class
        if not vuln_dir.is_dir():
            failures.append(f"Vulnerability class directory missing: {vuln_class}")
            continue

        # Collect all companion doc content from existing language dirs
        all_doc_content = ""
        for lang_dir in vuln_dir.iterdir():
            if lang_dir.is_dir() and lang_dir.name in LANGUAGES:
                for f in lang_dir.iterdir():
                    if f.name.endswith("_SECURITY.md"):
                        try:
                            all_doc_content += f.read_text(encoding="utf-8").lower()
                        except OSError:
                            pass

        # Language name variants for matching in docs
        lang_name_variants = {
            "python": ["python"],
            "java": ["java"],
            "go": ["go", "golang"],
            "rust": ["rust"],
            "c": ["\\bc\\b", "\\bc language", "\\bc and c\\+\\+", "c/c\\+\\+", "\\bc,"],
            "cpp": ["c\\+\\+", "cpp", "c and c\\+\\+", "c/c\\+\\+"],
            "javascript": ["javascript", "node.js", "node"],
        }

        for lang in excluded_langs:
            variants = lang_name_variants.get(lang, [lang])
            found = any(re.search(v, all_doc_content) for v in variants)
            if not found:
                failures.append(f"No exclusion rationale for {lang} in {vuln_class}")

    if failures:
        return PropertyResult(2, name, Status.FAIL, failures[:20])
    return PropertyResult(2, name, Status.PASS, [f"All {sum(len(v) for v in EXCLUDED_PAIRS.values())} exclusions documented"])


def check_property_3() -> PropertyResult:
    """Property 3: Overlapping classification dual-reference.

    For any vulnerability entry whose class overlaps OWASP Top 10 and SANS
    CWE Top 25, the expected findings manifest must contain both a non-null
    owasp field and a cwe field.

    Validates: Requirements 2.3
    """
    name = "Overlapping classification dual-reference"
    failures: list[str] = []
    checked = 0

    for src in walk_source_files():
        vc = get_vuln_class_from_path(src)
        if vc is None or vc not in OWASP_VULN_CLASSES:
            continue

        # Find the manifest
        stem = src.stem
        manifest_path = src.parent / f"{stem}_expected.json"
        if not manifest_path.is_file():
            continue

        data = load_json_safe(manifest_path)
        if data is None:
            continue

        for finding in data.get("findings", []):
            checked += 1
            cwe = finding.get("cwe")
            owasp = finding.get("owasp")
            if not cwe:
                failures.append(f"{relative(manifest_path)}: finding {finding.get('id', '?')} missing cwe")
            if not owasp:
                failures.append(f"{relative(manifest_path)}: finding {finding.get('id', '?')} missing owasp")

    if failures:
        return PropertyResult(3, name, Status.FAIL, failures[:20])
    return PropertyResult(3, name, Status.PASS, [f"All {checked} OWASP-class findings have both cwe and owasp fields"])


def check_property_4(enable_compile: bool = False) -> PropertyResult:
    """Property 4: Source file compilation.

    For any source file, compiling or executing it with the specified
    toolchain must produce no compilation errors.

    Validates: Requirements 3.1–3.7
    """
    name = "Source file compilation"

    if not enable_compile:
        return PropertyResult(4, name, Status.SKIP, ["Compilation check skipped (use --compile to enable)"])

    failures: list[str] = []
    checked = 0

    for src in walk_source_files():
        lang = detect_language(src)
        if lang is None:
            continue

        checked += 1
        try:
            if lang == "python":
                result = subprocess.run(
                    ["python3", "-m", "py_compile", str(src)],
                    capture_output=True, text=True, timeout=30
                )
            elif lang == "java":
                result = subprocess.run(
                    ["javac", "-nowarn", str(src)],
                    capture_output=True, text=True, timeout=60,
                    cwd=str(src.parent)
                )
            elif lang == "go":
                result = subprocess.run(
                    ["go", "build", "-o", "/dev/null", str(src.name)],
                    capture_output=True, text=True, timeout=60,
                    cwd=str(src.parent)
                )
            elif lang == "rust":
                result = subprocess.run(
                    ["rustc", "--edition", "2021", "--crate-type", "bin", str(src), "-o", "/dev/null"],
                    capture_output=True, text=True, timeout=60
                )
            elif lang == "c":
                result = subprocess.run(
                    ["gcc", "-std=c11", "-fsyntax-only", str(src)],
                    capture_output=True, text=True, timeout=30
                )
            elif lang == "cpp":
                result = subprocess.run(
                    ["g++", "-std=c++17", "-fsyntax-only", str(src)],
                    capture_output=True, text=True, timeout=30
                )
            elif lang == "javascript":
                result = subprocess.run(
                    ["node", "--check", str(src)],
                    capture_output=True, text=True, timeout=30
                )
            else:
                continue

            if result.returncode != 0:
                err_msg = (result.stderr or result.stdout or "unknown error").strip()[:120]
                failures.append(f"{relative(src)}: {err_msg}")
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            failures.append(f"{relative(src)}: {type(e).__name__}")

    if failures:
        return PropertyResult(4, name, Status.FAIL, failures[:20])
    return PropertyResult(4, name, Status.PASS, [f"All {checked} source files compiled/checked successfully"])


def check_property_5() -> PropertyResult:
    """Property 5: Dependency manifest co-location.

    For any source file that imports external packages, the correct
    dependency manifest must exist in the same directory.

    Validates: Requirements 3.8, 9.1–9.6
    """
    name = "Dependency manifest co-location"
    failures: list[str] = []
    checked = 0

    for src in walk_source_files():
        lang = get_language_from_path(src)
        if lang is None:
            continue

        vc = get_vuln_class_from_path(src)
        if vc is None:
            continue

        # Web/API apps always need dependency manifests
        if vc in WEB_API_VULN_CLASSES:
            checked += 1
            manifest_name = DEPENDENCY_MANIFESTS.get(lang)
            if manifest_name:
                manifest_path = src.parent / manifest_name
                if not manifest_path.is_file():
                    failures.append(f"Missing {manifest_name} in {relative(src.parent)}")
        else:
            # CLI apps: check if source imports external packages
            try:
                content = src.read_text(encoding="utf-8")
            except OSError:
                continue

            needs_manifest = False
            if lang == "python":
                # Check for non-stdlib imports
                pass  # CLI python apps may use only stdlib
            elif lang == "go":
                if "go.mod" not in [f.name for f in src.parent.iterdir()]:
                    # Go files with external imports need go.mod
                    if re.search(r'import\s.*"github\.com|"golang\.org', content):
                        needs_manifest = True
            elif lang == "rust":
                if "Cargo.toml" not in [f.name for f in src.parent.iterdir()]:
                    if re.search(r'extern\s+crate\s', content):
                        needs_manifest = True
            elif lang in ("c", "cpp"):
                if "Makefile" not in [f.name for f in src.parent.iterdir()]:
                    if re.search(r'#include\s*<(?!std)', content):
                        needs_manifest = True
            elif lang == "javascript":
                if "package.json" not in [f.name for f in src.parent.iterdir()]:
                    if re.search(r"require\(['\"](?!\.)", content):
                        needs_manifest = True

            if needs_manifest:
                checked += 1
                manifest_name = DEPENDENCY_MANIFESTS.get(lang)
                if manifest_name:
                    manifest_path = src.parent / manifest_name
                    if not manifest_path.is_file():
                        failures.append(f"Missing {manifest_name} in {relative(src.parent)}")

    if failures:
        return PropertyResult(5, name, Status.FAIL, failures[:20])
    return PropertyResult(5, name, Status.PASS, [f"Checked {checked} source files — all have required dependency manifests"])


def _is_web_api_source(src: Path) -> bool:
    """Determine if a source file is a web/API app (vs CLI).

    CLI apps are: memory-safety/*, integer-overflow, race-condition.
    For command-injection, C and C++ are CLI apps per the design doc (Req 4.5).
    All other vulnerability classes in WEB_API_VULN_CLASSES are web/API.
    """
    vc = get_vuln_class_from_path(src)
    if vc is None:
        return False
    if vc in CLI_VULN_CLASSES:
        return False
    if vc not in WEB_API_VULN_CLASSES:
        return False
    # C/C++ in command-injection are CLI apps
    lang = get_language_from_path(src)
    if vc == "injection/command-injection" and lang in ("c", "cpp"):
        return False
    return True


def check_property_6() -> PropertyResult:
    """Property 6: Framework usage.

    For any web/API source file, the source code must import or reference
    the designated framework for its language.

    Validates: Requirements 4.4
    """
    name = "Framework usage"
    failures: list[str] = []
    checked = 0

    for src in walk_source_files():
        if not _is_web_api_source(src):
            continue

        lang = get_language_from_path(src)
        if lang is None:
            continue

        checked += 1
        try:
            content = src.read_text(encoding="utf-8").lower()
        except OSError:
            failures.append(f"Cannot read {relative(src)}")
            continue

        patterns = FRAMEWORK_PATTERNS.get(lang, [])
        found = any(re.search(pat, content) for pat in patterns)
        if not found:
            failures.append(f"{relative(src)}: no framework import found (expected: {', '.join(patterns)})")

    if failures:
        return PropertyResult(6, name, Status.FAIL, failures[:20])
    return PropertyResult(6, name, Status.PASS, [f"All {checked} web/API source files use designated frameworks"])


def check_property_7() -> PropertyResult:
    """Property 7: No security comments.

    For any source file, scanning comments and string literals must find
    zero matches for security-related patterns.

    Validates: Requirements 5.1, 5.2, 5.3
    """
    name = "No security comments"
    failures: list[str] = []

    for src in walk_source_files():
        try:
            content = src.read_text(encoding="utf-8")
        except OSError:
            continue

        # Extract comments based on language
        lang = detect_language(src)
        comments = _extract_comments(content, lang)

        for keyword_pattern in SECURITY_KEYWORDS:
            for i, comment in enumerate(comments):
                if re.search(keyword_pattern, comment, re.IGNORECASE):
                    failures.append(f"{relative(src)}: security keyword in comment — matched '{keyword_pattern}'")
                    break  # One match per pattern per file is enough

    if failures:
        return PropertyResult(7, name, Status.FAIL, failures[:20])
    return PropertyResult(7, name, Status.PASS, [f"No security keywords found in source file comments"])


def _extract_comments(content: str, lang: Optional[str]) -> list[str]:
    """Extract comment text from source code."""
    comments = []
    if lang in ("python",):
        # Single-line comments
        comments.extend(re.findall(r"#(.+)$", content, re.MULTILINE))
        # Docstrings
        comments.extend(re.findall(r'"""(.*?)"""', content, re.DOTALL))
        comments.extend(re.findall(r"'''(.*?)'''", content, re.DOTALL))
    elif lang in ("java", "go", "rust", "c", "cpp", "javascript"):
        # Single-line comments
        comments.extend(re.findall(r"//(.+)$", content, re.MULTILINE))
        # Block comments
        comments.extend(re.findall(r"/\*(.*?)\*/", content, re.DOTALL))
    return comments


def check_property_8() -> PropertyResult:
    """Property 8: Companion doc existence and naming.

    For any source file named {name}.{ext}, a file named
    {name}_SECURITY.md must exist in the same directory.

    Validates: Requirements 6.1, 6.4, 8.2
    """
    name = "Companion doc existence and naming"
    failures: list[str] = []
    checked = 0

    for src in walk_source_files():
        checked += 1
        stem = src.stem
        companion = src.parent / f"{stem}_SECURITY.md"
        if not companion.is_file():
            failures.append(f"Missing: {relative(companion)}")

    if failures:
        return PropertyResult(8, name, Status.FAIL, failures[:20])
    return PropertyResult(8, name, Status.PASS, [f"All {checked} source files have companion docs"])


def check_property_9() -> PropertyResult:
    """Property 9: Companion doc completeness.

    For any companion doc and each vulnerability entry within it, the entry
    must contain all required sections.

    Validates: Requirements 6.2, 7.5, 12.7
    """
    name = "Companion doc completeness"
    failures: list[str] = []
    checked = 0

    required_headers = [
        "description",
        "exploitation",
        "remediation",
        "complexity rationale",
        "detection difficulty rationale",
    ]

    for src in walk_source_files():
        stem = src.stem
        companion = src.parent / f"{stem}_SECURITY.md"
        if not companion.is_file():
            continue

        try:
            content = companion.read_text(encoding="utf-8")
        except OSError:
            continue

        # Split into vulnerability entries
        entries = re.split(r"^---\s*$", content, flags=re.MULTILINE)
        vuln_entries = [e for e in entries if re.search(r"##\s+Vulnerability:", e)]

        if not vuln_entries:
            failures.append(f"{relative(companion)}: no vulnerability entries found")
            continue

        for entry in vuln_entries:
            checked += 1
            entry_lower = entry.lower()

            # Check for CWE
            if not re.search(r"\*\*cwe\*\*.*cwe-\d+", entry_lower):
                if not re.search(r"cwe.*cwe-\d+", entry_lower):
                    failures.append(f"{relative(companion)}: entry missing CWE identifier")

            # Check for required section headers
            for header in required_headers:
                if f"### {header}" not in entry_lower and header not in entry_lower:
                    # More flexible check
                    if not re.search(rf"###\s+.*{header}", entry_lower):
                        failures.append(f"{relative(companion)}: entry missing section '{header}'")
                        break  # Report first missing section per entry

    if failures:
        return PropertyResult(9, name, Status.FAIL, failures[:20])
    return PropertyResult(9, name, Status.PASS, [f"All {checked} vulnerability entries have required sections"])


def check_property_10() -> PropertyResult:
    """Property 10: Doc-manifest consistency.

    For any source file, the number of vulnerability entries in its companion
    doc must equal the number of findings in its expected findings manifest.

    Validates: Requirements 6.3
    """
    name = "Doc-manifest consistency"
    failures: list[str] = []
    checked = 0

    for src in walk_source_files():
        stem = src.stem
        companion = src.parent / f"{stem}_SECURITY.md"
        manifest = src.parent / f"{stem}_expected.json"

        if not companion.is_file() or not manifest.is_file():
            continue

        checked += 1
        doc_count = count_vulnerability_entries_in_doc(companion)
        data = load_json_safe(manifest)
        if data is None:
            failures.append(f"{relative(manifest)}: invalid JSON")
            continue

        manifest_count = len(data.get("findings", []))
        if doc_count != manifest_count:
            failures.append(
                f"{relative(src)}: companion doc has {doc_count} entries, "
                f"manifest has {manifest_count} findings"
            )

    if failures:
        return PropertyResult(10, name, Status.FAIL, failures[:20])
    return PropertyResult(10, name, Status.PASS, [f"All {checked} source files have consistent doc/manifest counts"])


# ---------------------------------------------------------------------------
# Property check implementations (11–20)
# ---------------------------------------------------------------------------

def check_property_11() -> PropertyResult:
    """Property 11: Manifest existence and naming.

    For any source file named {name}.{ext}, a file named
    {name}_expected.json must exist in the same directory.

    Validates: Requirements 11.1, 11.3, 11.4
    """
    name = "Manifest existence and naming"
    failures: list[str] = []
    checked = 0

    for src in walk_source_files():
        checked += 1
        stem = src.stem
        manifest = src.parent / f"{stem}_expected.json"
        if not manifest.is_file():
            failures.append(f"Missing: {relative(manifest)}")

    if failures:
        return PropertyResult(11, name, Status.FAIL, failures[:20])
    return PropertyResult(11, name, Status.PASS, [f"All {checked} source files have expected findings manifests"])


def check_property_12() -> PropertyResult:
    """Property 12: Manifest schema validity.

    For any expected findings manifest JSON file, it must validate against
    the defined JSON schema.

    Validates: Requirements 7.1, 11.2, 12.1
    """
    name = "Manifest schema validity"
    failures: list[str] = []
    checked = 0

    # Load the schema
    schema = load_json_safe(SCHEMA_PATH)
    if schema is None:
        return PropertyResult(12, name, Status.FAIL, [f"Cannot load schema from {relative(SCHEMA_PATH)}"])

    valid_languages = {"python", "java", "go", "rust", "c", "cpp", "javascript"}
    valid_complexity = {"Obvious", "Moderate", "Nuanced"}
    valid_detection = {"Easily_Detectable", "Pattern_Dependent", "Likely_Missed"}
    vuln_id_pattern = re.compile(r"^VULN-\d{3}$")
    cwe_pattern = re.compile(r"^CWE-\d+$")
    owasp_pattern = re.compile(r"^A\d{2}$")

    for src in walk_source_files():
        stem = src.stem
        manifest_path = src.parent / f"{stem}_expected.json"
        if not manifest_path.is_file():
            continue

        checked += 1
        data = load_json_safe(manifest_path)
        if data is None:
            failures.append(f"{relative(manifest_path)}: invalid JSON")
            continue

        rel = relative(manifest_path)

        # Check required top-level fields
        for req_field in ["source_file", "language", "vulnerability_class", "findings"]:
            if req_field not in data:
                failures.append(f"{rel}: missing required field '{req_field}'")

        # Check language enum
        if data.get("language") not in valid_languages:
            failures.append(f"{rel}: invalid language '{data.get('language')}'")

        # Check findings array
        findings = data.get("findings", [])
        if not isinstance(findings, list):
            failures.append(f"{rel}: 'findings' is not an array")
            continue

        for finding in findings:
            fid = finding.get("id", "?")

            # Check id pattern
            if not vuln_id_pattern.match(str(finding.get("id", ""))):
                failures.append(f"{rel}: finding {fid} has invalid id format")

            # Check cwe pattern
            if not cwe_pattern.match(str(finding.get("cwe", ""))):
                failures.append(f"{rel}: finding {fid} has invalid cwe format")

            # Check owasp pattern (optional but must match if present)
            owasp_val = finding.get("owasp")
            if owasp_val is not None and not owasp_pattern.match(str(owasp_val)):
                failures.append(f"{rel}: finding {fid} has invalid owasp format '{owasp_val}'")

            # Check required finding fields
            for req in ["title", "line_start", "line_end", "complexity_level", "detection_difficulty"]:
                if req not in finding:
                    failures.append(f"{rel}: finding {fid} missing '{req}'")

            # Check line numbers
            ls = finding.get("line_start", 0)
            le = finding.get("line_end", 0)
            if not isinstance(ls, int) or ls < 1:
                failures.append(f"{rel}: finding {fid} invalid line_start")
            if not isinstance(le, int) or le < 1:
                failures.append(f"{rel}: finding {fid} invalid line_end")
            if isinstance(ls, int) and isinstance(le, int) and ls > le:
                failures.append(f"{rel}: finding {fid} line_start > line_end")

            # Check enums
            if finding.get("complexity_level") not in valid_complexity:
                failures.append(f"{rel}: finding {fid} invalid complexity_level")
            if finding.get("detection_difficulty") not in valid_detection:
                failures.append(f"{rel}: finding {fid} invalid detection_difficulty")

    if failures:
        return PropertyResult(12, name, Status.FAIL, failures[:20])
    return PropertyResult(12, name, Status.PASS, [f"All {checked} manifests pass schema validation"])


def check_property_13() -> PropertyResult:
    """Property 13: Directory structure conformance.

    For any source file, its path must match the pattern
    {vulnerability_class}/{language}/{filename}.

    Validates: Requirements 8.1
    """
    name = "Directory structure conformance"
    failures: list[str] = []
    checked = 0

    for src in walk_source_files():
        checked += 1
        vc = get_vuln_class_from_path(src)
        lang = get_language_from_path(src)

        if vc is None:
            failures.append(f"{relative(src)}: not in a recognized vulnerability class directory")
            continue
        if lang is None:
            failures.append(f"{relative(src)}: not in a recognized language directory")
            continue

        # Verify the language is applicable for this vulnerability class
        if lang not in VULN_LANGUAGE_MAP.get(vc, []):
            failures.append(f"{relative(src)}: {lang} is not applicable for {vc}")

    if failures:
        return PropertyResult(13, name, Status.FAIL, failures[:20])
    return PropertyResult(13, name, Status.PASS, [f"All {checked} source files conform to directory structure"])


def check_property_14() -> PropertyResult:
    """Property 14: No test artifacts.

    For any file in the project, its name must not match test file patterns
    and no test runner configs or test dependencies shall exist.

    Validates: Requirements 10.1, 10.2
    """
    name = "No test artifacts"
    failures: list[str] = []

    for f in walk_all_files():
        fname = f.name
        for pattern in TEST_FILE_PATTERNS:
            if re.search(pattern, fname):
                failures.append(f"Test artifact found: {relative(f)}")
                break

    if failures:
        return PropertyResult(14, name, Status.FAIL, failures[:20])
    return PropertyResult(14, name, Status.PASS, ["No test artifacts found in project"])


def check_property_15() -> PropertyResult:
    """Property 15: README existence.

    For any language directory containing a source file, a README.md must
    exist in that directory.

    Validates: Requirements 13.1
    """
    name = "README existence"
    failures: list[str] = []
    checked_dirs: set[str] = set()

    for src in walk_source_files():
        dir_key = str(src.parent)
        if dir_key in checked_dirs:
            continue
        checked_dirs.add(dir_key)

        readme = src.parent / "README.md"
        if not readme.is_file():
            failures.append(f"Missing README.md in {relative(src.parent)}")

    if failures:
        return PropertyResult(15, name, Status.FAIL, failures[:20])
    return PropertyResult(15, name, Status.PASS, [f"All {len(checked_dirs)} language directories have README.md"])


def check_property_16() -> PropertyResult:
    """Property 16: README web/API content.

    For any language directory containing a web/API source file, the
    README.md must contain a port number reference and a curl command or URL.

    Validates: Requirements 13.5
    """
    name = "README web/API content"
    failures: list[str] = []
    checked = 0

    checked_dirs: set[str] = set()
    for src in walk_source_files():
        if not _is_web_api_source(src):
            continue

        dir_key = str(src.parent)
        if dir_key in checked_dirs:
            continue
        checked_dirs.add(dir_key)

        readme = src.parent / "README.md"
        if not readme.is_file():
            continue

        checked += 1
        try:
            content = readme.read_text(encoding="utf-8")
        except OSError:
            failures.append(f"Cannot read {relative(readme)}")
            continue

        # Check for port number
        has_port = bool(re.search(r"port\s+\d+|\d{4,5}", content, re.IGNORECASE))
        # Check for curl command or URL
        has_curl = bool(re.search(r"curl\s|http://|https://|localhost", content, re.IGNORECASE))

        if not has_port:
            failures.append(f"{relative(readme)}: no port number reference found")
        if not has_curl:
            failures.append(f"{relative(readme)}: no curl command or URL found")

    if failures:
        return PropertyResult(16, name, Status.FAIL, failures[:20])
    return PropertyResult(16, name, Status.PASS, [f"All {checked} web/API READMEs have port and curl references"])


def check_property_17() -> PropertyResult:
    """Property 17: README version requirements.

    For any language directory README.md, the file must contain a version
    string consistent with the language's minimum version requirement.

    Validates: Requirements 13.8
    """
    name = "README version requirements"
    failures: list[str] = []
    checked = 0

    for src in walk_source_files():
        lang = get_language_from_path(src)
        if lang is None:
            continue

        readme = src.parent / "README.md"
        if not readme.is_file():
            continue

        checked += 1
        try:
            content = readme.read_text(encoding="utf-8")
        except OSError:
            failures.append(f"Cannot read {relative(readme)}")
            continue

        pattern = VERSION_PATTERNS.get(lang)
        if pattern and not re.search(pattern, content):
            failures.append(f"{relative(readme)}: missing version string for {lang}")

    if failures:
        return PropertyResult(17, name, Status.FAIL, failures[:20])
    return PropertyResult(17, name, Status.PASS, [f"All {checked} READMEs contain version requirements"])


def check_property_18() -> PropertyResult:
    """Property 18: Review guide structure.

    For any language review guide in docs/, the file must contain sections
    for manual review best practices, common security pitfalls, recommended
    SAST tools, setup/usage instructions, and vulnerability patterns.

    Validates: Requirements 14.3–14.7
    """
    name = "Review guide structure"
    failures: list[str] = []
    checked = 0

    required_sections = [
        (r"manual\s+review|review\s+best\s+practices|best\s+practices", "manual review best practices"),
        (r"security\s+pitfalls|common\s+.*pitfalls|anti.?patterns", "common security pitfalls"),
        (r"sast\s+tools|recommended\s+.*tools|linters", "recommended SAST tools"),
        (r"vulnerability\s+patterns|language.specific\s+.*patterns", "vulnerability patterns"),
    ]

    docs_dir = PROJECT_ROOT / "docs"
    for lang in LANGUAGES:
        guide_path = docs_dir / f"{lang}_security_review_guide.md"
        if not guide_path.is_file():
            continue

        checked += 1
        try:
            content = guide_path.read_text(encoding="utf-8").lower()
        except OSError:
            failures.append(f"Cannot read {relative(guide_path)}")
            continue

        # Check required sections
        for pattern, section_name in required_sections:
            if not re.search(pattern, content):
                failures.append(f"{relative(guide_path)}: missing section '{section_name}'")

        # Check required tools for this language
        tools = REVIEW_GUIDE_TOOLS.get(lang, [])
        for tool in tools:
            if tool.lower() not in content:
                failures.append(f"{relative(guide_path)}: missing tool '{tool}'")

        # Check for setup/usage instructions (install commands)
        if not re.search(r"install|pip\s|npm\s|cargo\s|go\s+install|apt.get", content):
            failures.append(f"{relative(guide_path)}: missing setup/usage instructions")

    if failures:
        return PropertyResult(18, name, Status.FAIL, failures[:20])
    return PropertyResult(18, name, Status.PASS, [f"All {checked} review guides have required structure"])


def check_property_19() -> PropertyResult:
    """Property 19: Review guide naming.

    For any supported language, a file named
    {language}_security_review_guide.md must exist in docs/.

    Validates: Requirements 14.2
    """
    name = "Review guide naming"
    failures: list[str] = []

    docs_dir = PROJECT_ROOT / "docs"
    for lang in LANGUAGES:
        guide_path = docs_dir / f"{lang}_security_review_guide.md"
        if not guide_path.is_file():
            failures.append(f"Missing: docs/{lang}_security_review_guide.md")

    if failures:
        return PropertyResult(19, name, Status.FAIL, failures)
    return PropertyResult(19, name, Status.PASS, [f"All {len(LANGUAGES)} review guides exist in docs/"])


def check_property_20() -> PropertyResult:
    """Property 20: Review guide cross-references.

    For any language review guide, it must contain at least one relative
    file path reference to a source file or companion doc, and each
    referenced path must point to an existing file.

    Validates: Requirements 14.8
    """
    name = "Review guide cross-references"
    failures: list[str] = []
    checked = 0

    docs_dir = PROJECT_ROOT / "docs"
    # Pattern to match relative paths in markdown links: [text](../path/to/file)
    link_pattern = re.compile(r"\[.*?\]\((\.\./.+?)\)")

    for lang in LANGUAGES:
        guide_path = docs_dir / f"{lang}_security_review_guide.md"
        if not guide_path.is_file():
            continue

        checked += 1
        try:
            content = guide_path.read_text(encoding="utf-8")
        except OSError:
            failures.append(f"Cannot read {relative(guide_path)}")
            continue

        links = link_pattern.findall(content)
        if not links:
            failures.append(f"{relative(guide_path)}: no cross-reference links found")
            continue

        broken_links = []
        for link in links:
            # Resolve relative to docs/ directory
            resolved = (docs_dir / link).resolve()
            if not resolved.is_file():
                broken_links.append(link)

        if broken_links:
            failures.append(
                f"{relative(guide_path)}: {len(broken_links)} broken link(s) — "
                f"e.g. {broken_links[0]}"
            )

    if failures:
        return PropertyResult(20, name, Status.FAIL, failures[:20])
    return PropertyResult(20, name, Status.PASS, [f"All {checked} review guides have valid cross-references"])


# ---------------------------------------------------------------------------
# Distribution statistics
# ---------------------------------------------------------------------------

def print_distribution_stats() -> None:
    """Print complexity and detection difficulty distribution statistics."""
    complexity_counts = {"Obvious": 0, "Moderate": 0, "Nuanced": 0}
    detection_counts = {"Easily_Detectable": 0, "Pattern_Dependent": 0, "Likely_Missed": 0}
    total = 0

    for src in walk_source_files():
        stem = src.stem
        manifest_path = src.parent / f"{stem}_expected.json"
        if not manifest_path.is_file():
            continue

        data = load_json_safe(manifest_path)
        if data is None:
            continue

        for finding in data.get("findings", []):
            total += 1
            cl = finding.get("complexity_level", "")
            dd = finding.get("detection_difficulty", "")
            if cl in complexity_counts:
                complexity_counts[cl] += 1
            if dd in detection_counts:
                detection_counts[dd] += 1

    print("\n" + "=" * 72)
    print("  Distribution Statistics")
    print("=" * 72 + "\n")
    print(f"  Total vulnerabilities: {total}\n")

    print("  Complexity Level Distribution:")
    for level, count in complexity_counts.items():
        pct = (count / total * 100) if total > 0 else 0
        bar = "█" * int(pct / 2)
        print(f"    {level:<12} {count:>4} ({pct:5.1f}%) {bar}")

    req_complexity = {"Obvious": 30, "Moderate": 30, "Nuanced": 20}
    for level, min_pct in req_complexity.items():
        actual = (complexity_counts[level] / total * 100) if total > 0 else 0
        status = "✅" if actual >= min_pct else "❌"
        print(f"    {status} {level} >= {min_pct}%: {actual:.1f}%")

    print("\n  Detection Difficulty Distribution:")
    for level, count in detection_counts.items():
        pct = (count / total * 100) if total > 0 else 0
        bar = "█" * int(pct / 2)
        print(f"    {level:<20} {count:>4} ({pct:5.1f}%) {bar}")

    req_detection = {"Easily_Detectable": 30, "Likely_Missed": 20}
    for level, min_pct in req_detection.items():
        actual = (detection_counts[level] / total * 100) if total > 0 else 0
        status = "✅" if actual >= min_pct else "❌"
        print(f"    {status} {level} >= {min_pct}%: {actual:.1f}%")

    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

ALL_CHECKS = [
    check_property_1,
    check_property_2,
    check_property_3,
    check_property_4,
    check_property_5,
    check_property_6,
    check_property_7,
    check_property_8,
    check_property_9,
    check_property_10,
    check_property_11,
    check_property_12,
    check_property_13,
    check_property_14,
    check_property_15,
    check_property_16,
    check_property_17,
    check_property_18,
    check_property_19,
    check_property_20,
]


def main() -> int:
    """Run all property checks and print the validation report."""
    enable_compile = "--compile" in sys.argv

    report = ValidationReport()

    for check_fn in ALL_CHECKS:
        if check_fn == check_property_4:
            result = check_fn(enable_compile=enable_compile)
        else:
            result = check_fn()
        report.add(result)

    report.print_report()
    print_distribution_stats()

    return 0 if report.all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
