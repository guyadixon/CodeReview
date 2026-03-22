"""
Property-based tests for README and review guide validation.

These tests use Hypothesis to verify that per-directory READMEs exist and
contain required content (port/curl for web/API apps, version strings),
and that the seven language review guides in docs/ have the required
structure, naming, and valid cross-references. They are placed in a
separate tests/ directory so validate.py does not scan them as project
artifacts.
"""

import re
import sys
from pathlib import Path

import hypothesis.strategies as st
from hypothesis import given, settings

# Add parent directory to path so we can import from validate.py
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from validate import (
    LANGUAGES,
    PROJECT_ROOT,
    SOURCE_FILE_NAMES,
    VULN_LANGUAGE_MAP,
    WEB_API_VULN_CLASSES,
    VERSION_PATTERNS,
    REVIEW_GUIDE_TOOLS,
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


def web_api_vuln_language_pairs():
    """Generate random (vuln_class, language) pairs for web/API vulnerability classes only."""
    pairs = []
    for vuln_class, langs in VULN_LANGUAGE_MAP.items():
        if vuln_class not in WEB_API_VULN_CLASSES:
            continue
        for lang in langs:
            # C/C++ in command-injection are CLI apps per design doc
            if vuln_class == "injection/command-injection" and lang in ("c", "cpp"):
                continue
            pairs.append((vuln_class, lang))
    return st.sampled_from(pairs)


# ---------------------------------------------------------------------------
# Feature: security-bug-examples, Property 15: Build/run README existence
#
# For any (vuln_class, language) pair, verify a README.md exists in the
# language directory.
#
# Validates: Requirements 13.1, 13.5
# ---------------------------------------------------------------------------


@settings(max_examples=100)
@given(pair=vuln_language_pairs())
def test_readme_existence(pair):
    """**Validates: Requirements 13.1, 13.5**

    For any (vuln_class, language) pair, a README.md must exist in the
    language directory.
    """
    vuln_class, lang = pair
    readme = PROJECT_ROOT / vuln_class / lang / "README.md"
    assert readme.is_file(), (
        f"Missing README.md: {vuln_class}/{lang}/README.md"
    )


# ---------------------------------------------------------------------------
# Feature: security-bug-examples, Property 16: Build/run README content for web/API apps
#
# For web/API application source files, verify the README contains port
# numbers and curl examples.
#
# Validates: Requirements 13.8
# ---------------------------------------------------------------------------


@settings(max_examples=100)
@given(pair=web_api_vuln_language_pairs())
def test_readme_web_api_content(pair):
    """**Validates: Requirements 13.8**

    For any web/API (vuln_class, language) pair, the README.md must
    contain at least one port number reference and at least one curl
    command or URL example.
    """
    vuln_class, lang = pair
    readme = PROJECT_ROOT / vuln_class / lang / "README.md"

    assert readme.is_file(), (
        f"Missing README.md: {vuln_class}/{lang}/README.md"
    )

    content = readme.read_text(encoding="utf-8")

    # Check for port number (4-5 digit number or "port" followed by a number)
    has_port = bool(re.search(r"port\s+\d+|\d{4,5}", content, re.IGNORECASE))
    assert has_port, (
        f"{vuln_class}/{lang}/README.md: no port number reference found"
    )

    # Check for curl command or URL
    has_curl = bool(re.search(r"curl\s|http://|https://|localhost", content, re.IGNORECASE))
    assert has_curl, (
        f"{vuln_class}/{lang}/README.md: no curl command or URL found"
    )


# ---------------------------------------------------------------------------
# Feature: security-bug-examples, Property 17: Build/run README version requirements
#
# For any README, verify it contains version strings (e.g., Python 3.x,
# Java 11+, Go 1.x, etc.).
#
# Validates: Requirements 13.5
# ---------------------------------------------------------------------------


@settings(max_examples=100)
@given(pair=vuln_language_pairs())
def test_readme_version_requirements(pair):
    """**Validates: Requirements 13.5**

    For any (vuln_class, language) pair, the README.md must contain a
    version string consistent with the language's minimum version
    requirement.
    """
    vuln_class, lang = pair
    readme = PROJECT_ROOT / vuln_class / lang / "README.md"

    assert readme.is_file(), (
        f"Missing README.md: {vuln_class}/{lang}/README.md"
    )

    content = readme.read_text(encoding="utf-8")
    pattern = VERSION_PATTERNS.get(lang)

    assert pattern is not None, f"No version pattern defined for {lang}"
    assert re.search(pattern, content), (
        f"{vuln_class}/{lang}/README.md: missing version string for {lang} "
        f"(expected pattern: {pattern})"
    )


# ---------------------------------------------------------------------------
# Feature: security-bug-examples, Property 18: Review guide structure completeness
#
# For each of the 7 language review guides in docs/, verify all required
# sections are present (manual review best practices, common pitfalls,
# recommended SAST tools, vulnerability patterns, cross-references,
# checklist).
#
# Validates: Requirements 14.2, 14.3, 14.4, 14.5, 14.6, 14.7, 14.8
# ---------------------------------------------------------------------------

REQUIRED_GUIDE_SECTIONS = [
    (r"manual\s+review|review\s+best\s+practices|best\s+practices", "manual review best practices"),
    (r"security\s+pitfalls|common\s+.*pitfalls|anti.?patterns", "common security pitfalls"),
    (r"sast\s+tools|recommended\s+.*tools|linters", "recommended SAST tools"),
    (r"vulnerability\s+patterns|language.specific\s+.*patterns", "vulnerability patterns"),
]


@settings(max_examples=100)
@given(lang=st.sampled_from(LANGUAGES))
def test_review_guide_structure_completeness(lang):
    """**Validates: Requirements 14.2, 14.3, 14.4, 14.5, 14.6, 14.7, 14.8**

    For each language review guide in docs/, verify all required sections
    are present: manual review best practices, common pitfalls, recommended
    SAST tools, vulnerability patterns. Also verify required tools for the
    language are mentioned and setup/usage instructions are included.
    """
    guide_path = PROJECT_ROOT / "docs" / f"{lang}_security_review_guide.md"

    assert guide_path.is_file(), (
        f"Missing review guide: docs/{lang}_security_review_guide.md"
    )

    content = guide_path.read_text(encoding="utf-8").lower()

    # Check required sections
    for pattern, section_name in REQUIRED_GUIDE_SECTIONS:
        assert re.search(pattern, content), (
            f"docs/{lang}_security_review_guide.md: missing section '{section_name}'"
        )

    # Check required tools for this language
    tools = REVIEW_GUIDE_TOOLS.get(lang, [])
    for tool in tools:
        assert tool.lower() in content, (
            f"docs/{lang}_security_review_guide.md: missing tool '{tool}'"
        )

    # Check for setup/usage instructions (install commands)
    assert re.search(r"install|pip\s|npm\s|cargo\s|go\s+install|apt.get", content), (
        f"docs/{lang}_security_review_guide.md: missing setup/usage instructions"
    )


# ---------------------------------------------------------------------------
# Feature: security-bug-examples, Property 19: Review guide naming and placement
#
# Verify all 7 review guide files exist in docs/ with correct naming:
# {language}_security_review_guide.md.
#
# Validates: Requirements 14.2
# ---------------------------------------------------------------------------


@settings(max_examples=100)
@given(lang=st.sampled_from(LANGUAGES))
def test_review_guide_naming_and_placement(lang):
    """**Validates: Requirements 14.2**

    For each supported language, a file named
    {language}_security_review_guide.md must exist in the docs/ directory.
    """
    guide_path = PROJECT_ROOT / "docs" / f"{lang}_security_review_guide.md"
    assert guide_path.is_file(), (
        f"Missing: docs/{lang}_security_review_guide.md"
    )


# ---------------------------------------------------------------------------
# Feature: security-bug-examples, Property 20: Review guide cross-references
#
# For each review guide, verify that relative path cross-references to
# source files and companion docs actually resolve to existing files.
#
# Validates: Requirements 14.8
# ---------------------------------------------------------------------------

LINK_PATTERN = re.compile(r"\[.*?\]\((\.\./.+?)\)")


@settings(max_examples=100)
@given(lang=st.sampled_from(LANGUAGES))
def test_review_guide_cross_references(lang):
    """**Validates: Requirements 14.8**

    For each language review guide, verify that it contains at least one
    relative path cross-reference and that each referenced path resolves
    to an existing file.
    """
    docs_dir = PROJECT_ROOT / "docs"
    guide_path = docs_dir / f"{lang}_security_review_guide.md"

    assert guide_path.is_file(), (
        f"Missing review guide: docs/{lang}_security_review_guide.md"
    )

    content = guide_path.read_text(encoding="utf-8")
    links = LINK_PATTERN.findall(content)

    assert len(links) > 0, (
        f"docs/{lang}_security_review_guide.md: no cross-reference links found"
    )

    broken_links = []
    for link in links:
        # Resolve relative to docs/ directory
        resolved = (docs_dir / link).resolve()
        if not resolved.is_file():
            broken_links.append(link)

    assert len(broken_links) == 0, (
        f"docs/{lang}_security_review_guide.md: {len(broken_links)} broken link(s) — "
        f"e.g. {broken_links[0] if broken_links else 'N/A'}"
    )
