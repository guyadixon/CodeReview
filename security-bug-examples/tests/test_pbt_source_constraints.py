"""
Property-based tests for source file constraints.

These tests use Hypothesis to verify that source files contain no security
keywords in comments, that the directory structure conforms to the expected
pattern, and that no test artifacts exist within the project artifact
directories. They are placed in a separate tests/ directory so validate.py
does not scan them as project artifacts.
"""

import os
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
    SECURITY_KEYWORDS,
    TEST_FILE_PATTERNS,
    LANGUAGES,
    SOURCE_EXTENSIONS,
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
# Helpers
# ---------------------------------------------------------------------------

def _extract_comments(content: str, lang: str) -> list[str]:
    """Extract comment text from source code based on language."""
    comments = []
    if lang == "python":
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


# Map language name to file extension for detection
_LANG_TO_EXT = {
    "python": ".py",
    "java": ".java",
    "go": ".go",
    "rust": ".rs",
    "c": ".c",
    "cpp": ".cpp",
    "javascript": ".js",
}


# ---------------------------------------------------------------------------
# Feature: security-bug-examples, Property 7: No security information in source code
#
# For any source file, scanning all comments (inline, block, and doc-strings)
# must find zero matches for security-related patterns including CWE
# identifiers, OWASP category references, and vulnerability class keywords.
#
# Validates: Requirements 5.1, 5.2, 5.3
# ---------------------------------------------------------------------------


@settings(max_examples=100)
@given(pair=vuln_language_pairs())
def test_no_security_information_in_source_code(pair):
    """**Validates: Requirements 5.1, 5.2, 5.3**

    For any (vuln_class, language) pair, the source file must contain no
    security-related keywords in its comments or docstrings.
    """
    vuln_class, lang = pair
    src_name = SOURCE_FILE_NAMES[lang]
    src_path = PROJECT_ROOT / vuln_class / lang / src_name

    assert src_path.is_file(), (
        f"Missing source file: {vuln_class}/{lang}/{src_name}"
    )

    content = src_path.read_text(encoding="utf-8")
    comments = _extract_comments(content, lang)

    for keyword_pattern in SECURITY_KEYWORDS:
        for comment in comments:
            match = re.search(keyword_pattern, comment, re.IGNORECASE)
            assert match is None, (
                f"{vuln_class}/{lang}/{src_name}: security keyword found in comment — "
                f"matched pattern '{keyword_pattern}' in: {comment.strip()[:80]}"
            )


# ---------------------------------------------------------------------------
# Feature: security-bug-examples, Property 13: Directory structure conformance
#
# For any (vuln_class, language) pair, verify the path pattern matches the
# expected directory structure: {vulnerability_class}/{language}/{filename}.
#
# Validates: Requirements 8.1
# ---------------------------------------------------------------------------


@settings(max_examples=100)
@given(pair=vuln_language_pairs())
def test_directory_structure_conformance(pair):
    """**Validates: Requirements 8.1**

    For any (vuln_class, language) pair, the source file must exist at the
    expected path {vulnerability_class}/{language}/{filename} and the
    language must be in the applicable-languages mapping for that class.
    """
    vuln_class, lang = pair
    src_name = SOURCE_FILE_NAMES[lang]
    expected_path = PROJECT_ROOT / vuln_class / lang / src_name

    # Verify the directory exists
    lang_dir = PROJECT_ROOT / vuln_class / lang
    assert lang_dir.is_dir(), (
        f"Language directory missing: {vuln_class}/{lang}/"
    )

    # Verify the source file exists at the expected path
    assert expected_path.is_file(), (
        f"Source file missing at expected path: {vuln_class}/{lang}/{src_name}"
    )

    # Verify the language is applicable for this vulnerability class
    applicable_langs = VULN_LANGUAGE_MAP.get(vuln_class, [])
    assert lang in applicable_langs, (
        f"{lang} is not in the applicable-languages mapping for {vuln_class}"
    )


# ---------------------------------------------------------------------------
# Feature: security-bug-examples, Property 14: No test artifacts
#
# For any file in the project artifact directories, its name must not match
# test file patterns. The tests/ directory is excluded since PBT tests
# live there intentionally.
#
# Validates: Requirements 10.1, 10.2
# ---------------------------------------------------------------------------


def _collect_project_artifact_files() -> list[Path]:
    """Collect all files under PROJECT_ROOT, excluding hidden dirs,
    validate.py, and the tests/ directory (where PBT tests live)."""
    results = []
    tests_dir = PROJECT_ROOT / "tests"
    for root, dirs, files in os.walk(PROJECT_ROOT):
        # Skip hidden directories
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        root_path = Path(root)
        # Skip the tests/ directory entirely
        if root_path == tests_dir or tests_dir in root_path.parents:
            continue
        for fname in files:
            p = root_path / fname
            if p.name != "validate.py":
                results.append(p)
    return results


# Pre-collect the artifact files once for the strategy
_ARTIFACT_FILES = _collect_project_artifact_files()


@settings(max_examples=100)
@given(artifact=st.sampled_from(_ARTIFACT_FILES) if _ARTIFACT_FILES else st.nothing())
def test_no_test_artifacts(artifact):
    """**Validates: Requirements 10.1, 10.2**

    For any file in the project artifact directories (excluding the tests/
    directory where PBT tests live), the filename must not match any test
    file pattern.
    """
    fname = artifact.name
    for pattern in TEST_FILE_PATTERNS:
        match = re.search(pattern, fname)
        assert match is None, (
            f"Test artifact found: {artifact.relative_to(PROJECT_ROOT)} — "
            f"matched pattern '{pattern}'"
        )
