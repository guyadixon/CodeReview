"""
Property-based tests for companion doc and manifest consistency.

These tests use Hypothesis to verify that companion docs and expected
findings manifests exist, are correctly named, are mutually consistent,
and conform to the required schema. They are placed in a separate
tests/ directory so validate.py does not scan them as project artifacts.
"""

import re
import sys
from pathlib import Path

import hypothesis.strategies as st
from hypothesis import given, settings

# Add parent directory to path so we can import from validate.py
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from validate import (
    PROJECT_ROOT,
    SOURCE_FILE_NAMES,
    VULN_LANGUAGE_MAP,
    count_vulnerability_entries_in_doc,
    load_json_safe,
)


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

def vuln_language_pairs():
    """Generate random (vuln_class, language) pairs from the applicable-languages mapping."""
    pairs = [
        (vuln_class, lang)
        for vuln_class, langs in VULN_LANGUAGE_MAP.items()
        for lang in langs
    ]
    return st.sampled_from(pairs)


# ---------------------------------------------------------------------------
# Feature: security-bug-examples, Property 8: Companion doc existence and naming
#
# For any source file named {name}.{ext}, verify {name}_SECURITY.md
# exists in the same directory.
#
# Validates: Requirements 6.1, 6.4
# ---------------------------------------------------------------------------


@settings(max_examples=100)
@given(pair=vuln_language_pairs())
def test_companion_doc_existence_and_naming(pair):
    """**Validates: Requirements 6.1, 6.4**

    For any (vuln_class, language) pair, the companion security doc
    {name}_SECURITY.md must exist alongside the source file.
    """
    vuln_class, lang = pair
    src_name = SOURCE_FILE_NAMES[lang]
    stem = Path(src_name).stem
    companion = PROJECT_ROOT / vuln_class / lang / f"{stem}_SECURITY.md"
    assert companion.is_file(), (
        f"Missing companion doc: {vuln_class}/{lang}/{stem}_SECURITY.md"
    )


# ---------------------------------------------------------------------------
# Feature: security-bug-examples, Property 10: Doc-manifest consistency
#
# For any source file, verify the vulnerability count in companion doc
# equals the findings count in manifest.
#
# Validates: Requirements 6.3
# ---------------------------------------------------------------------------


@settings(max_examples=100)
@given(pair=vuln_language_pairs())
def test_doc_manifest_consistency(pair):
    """**Validates: Requirements 6.3**

    For any (vuln_class, language) pair, the number of vulnerability
    entries in the companion doc must equal the number of findings in
    the expected findings manifest.
    """
    vuln_class, lang = pair
    src_name = SOURCE_FILE_NAMES[lang]
    stem = Path(src_name).stem
    base_dir = PROJECT_ROOT / vuln_class / lang

    companion = base_dir / f"{stem}_SECURITY.md"
    manifest_path = base_dir / f"{stem}_expected.json"

    # Both files must exist for this check to be meaningful
    assert companion.is_file(), (
        f"Missing companion doc: {vuln_class}/{lang}/{stem}_SECURITY.md"
    )
    assert manifest_path.is_file(), (
        f"Missing manifest: {vuln_class}/{lang}/{stem}_expected.json"
    )

    doc_count = count_vulnerability_entries_in_doc(companion)
    data = load_json_safe(manifest_path)
    assert data is not None, (
        f"Invalid JSON in manifest: {vuln_class}/{lang}/{stem}_expected.json"
    )

    manifest_count = len(data.get("findings", []))
    assert doc_count == manifest_count, (
        f"{vuln_class}/{lang}: companion doc has {doc_count} vulnerability entries, "
        f"manifest has {manifest_count} findings"
    )


# ---------------------------------------------------------------------------
# Feature: security-bug-examples, Property 11: Manifest existence and naming
#
# For any source file named {name}.{ext}, verify {name}_expected.json
# exists in the same directory.
#
# Validates: Requirements 11.1, 11.3, 11.4
# ---------------------------------------------------------------------------


@settings(max_examples=100)
@given(pair=vuln_language_pairs())
def test_manifest_existence_and_naming(pair):
    """**Validates: Requirements 11.1, 11.3, 11.4**

    For any (vuln_class, language) pair, the expected findings manifest
    {name}_expected.json must exist alongside the source file.
    """
    vuln_class, lang = pair
    src_name = SOURCE_FILE_NAMES[lang]
    stem = Path(src_name).stem
    manifest = PROJECT_ROOT / vuln_class / lang / f"{stem}_expected.json"
    assert manifest.is_file(), (
        f"Missing manifest: {vuln_class}/{lang}/{stem}_expected.json"
    )


# ---------------------------------------------------------------------------
# Feature: security-bug-examples, Property 12: Manifest schema validity
#
# For any manifest, validate it has required fields (source_file,
# language, vulnerability_class, findings) and each finding has required
# fields with correct formats (id: VULN-NNN, cwe: CWE-XXX,
# complexity_level enum, detection_difficulty enum, line_start/line_end
# positive integers).
#
# Validates: Requirements 11.2
# ---------------------------------------------------------------------------

VULN_ID_PATTERN = re.compile(r"^VULN-\d{3}$")
CWE_PATTERN = re.compile(r"^CWE-\d+$")
VALID_COMPLEXITY = {"Obvious", "Moderate", "Nuanced"}
VALID_DETECTION = {"Easily_Detectable", "Pattern_Dependent", "Likely_Missed"}


@settings(max_examples=100)
@given(pair=vuln_language_pairs())
def test_manifest_schema_validity(pair):
    """**Validates: Requirements 11.2**

    For any (vuln_class, language) pair, the expected findings manifest
    must conform to the required schema: top-level required fields and
    each finding with correct field formats.
    """
    vuln_class, lang = pair
    src_name = SOURCE_FILE_NAMES[lang]
    stem = Path(src_name).stem
    manifest_path = PROJECT_ROOT / vuln_class / lang / f"{stem}_expected.json"

    assert manifest_path.is_file(), (
        f"Missing manifest: {vuln_class}/{lang}/{stem}_expected.json"
    )

    data = load_json_safe(manifest_path)
    assert data is not None, (
        f"Invalid JSON: {vuln_class}/{lang}/{stem}_expected.json"
    )

    rel = f"{vuln_class}/{lang}/{stem}_expected.json"

    # Required top-level fields
    for req_field in ("source_file", "language", "vulnerability_class", "findings"):
        assert req_field in data, f"{rel}: missing required field '{req_field}'"

    # Findings must be a list
    findings = data.get("findings", [])
    assert isinstance(findings, list), f"{rel}: 'findings' is not an array"

    for finding in findings:
        fid = finding.get("id", "?")

        # id format: VULN-NNN
        assert VULN_ID_PATTERN.match(str(finding.get("id", ""))), (
            f"{rel}: finding {fid} has invalid id format (expected VULN-NNN)"
        )

        # cwe format: CWE-XXX
        assert CWE_PATTERN.match(str(finding.get("cwe", ""))), (
            f"{rel}: finding {fid} has invalid cwe format (expected CWE-XXX)"
        )

        # complexity_level enum
        assert finding.get("complexity_level") in VALID_COMPLEXITY, (
            f"{rel}: finding {fid} has invalid complexity_level "
            f"'{finding.get('complexity_level')}'"
        )

        # detection_difficulty enum
        assert finding.get("detection_difficulty") in VALID_DETECTION, (
            f"{rel}: finding {fid} has invalid detection_difficulty "
            f"'{finding.get('detection_difficulty')}'"
        )

        # line_start: positive integer
        ls = finding.get("line_start")
        assert isinstance(ls, int) and ls >= 1, (
            f"{rel}: finding {fid} has invalid line_start (must be positive int)"
        )

        # line_end: positive integer
        le = finding.get("line_end")
        assert isinstance(le, int) and le >= 1, (
            f"{rel}: finding {fid} has invalid line_end (must be positive int)"
        )
