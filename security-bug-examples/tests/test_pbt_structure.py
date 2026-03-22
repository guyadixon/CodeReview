"""
Property-based tests for artifact structure validation.

These tests use Hypothesis to verify structural correctness properties
of the security-bug-examples project. They are placed in a separate
tests/ directory so validate.py does not scan them as project artifacts.
"""

import sys
from pathlib import Path

import hypothesis.strategies as st
from hypothesis import given, settings

# Add parent directory to path so we can import from validate.py
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from validate import PROJECT_ROOT, SOURCE_FILE_NAMES, VULN_LANGUAGE_MAP


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
# Feature: security-bug-examples, Property 1: Language coverage completeness
#
# For any vulnerability class and any language in the applicable-languages
# mapping, a source file with the correct extension must exist in
# {vulnerability_class}/{language}/.
#
# Validates: Requirements 1.1, 1.2
# ---------------------------------------------------------------------------


@settings(max_examples=100)
@given(pair=vuln_language_pairs())
def test_language_coverage_completeness(pair):
    """**Validates: Requirements 1.1, 1.2**

    For any (vuln_class, language) pair drawn from the applicable-languages
    mapping, the expected source file must exist on disk.
    """
    vuln_class, lang = pair
    src_name = SOURCE_FILE_NAMES[lang]
    expected_path = PROJECT_ROOT / vuln_class / lang / src_name
    assert expected_path.is_file(), (
        f"Missing source file: {vuln_class}/{lang}/{src_name}"
    )
