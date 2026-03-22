# Security Bug Examples

A curated library of intentionally vulnerable source code across seven programming languages, organized by vulnerability class. This project serves two purposes:

1. **SAST Tool Benchmarking** — Each source file ships with a machine-readable expected-findings manifest (`_expected.json`) so you can automatically compare static analysis tool output against known vulnerabilities and measure detection rates.
2. **Manual Security Code Review Training** — Source files contain no security-related comments, making them suitable for unbiased code review exercises. Companion answer-key documents (`_SECURITY.md`) explain every vulnerability in detail.

Languages covered: Python, Java, Go, Rust, C, C++, and JavaScript.

---

## Vulnerability Classes

| # | OWASP / SANS Category | Directory | CWE Sub-classes | Applicable Languages | App Type |
|---|---|---|---|---|---|
| 1 | A01: Broken Access Control | `broken-access-control/` | CWE-200, CWE-284, CWE-639 | Python, Java, Go, Rust, C, C++, JS | API Service |
| 2 | A02: Cryptographic Failures | `cryptographic-failures/` | CWE-327, CWE-328, CWE-330 | Python, Java, Go, Rust, C, C++, JS | API Service |
| 3 | A03: Injection (SQL) | `injection/sql-injection/` | CWE-89 | Python, Java, Go, JS | Web / API |
| 4 | A03: Injection (Command) | `injection/command-injection/` | CWE-78 | Python, Java, Go, Rust, C, C++, JS | API / CLI |
| 5 | A03: Injection (XSS) | `injection/xss/` | CWE-79 | Python, Java, Go, Rust, JS | Web App |
| 6 | A04: Insecure Design | `insecure-design/` | CWE-209, CWE-522 | Python, Java, Go, Rust, C, C++, JS | API Service |
| 7 | A05: Security Misconfiguration | `security-misconfiguration/` | CWE-16, CWE-611 | Python, Java, Go, Rust, C, C++, JS | API Service |
| 8 | A06: Vulnerable Components | `vulnerable-components/` | CWE-1104 | Python, Java, Go, Rust, C, C++, JS | API Service |
| 9 | A07: Auth Failures | `auth-failures/` | CWE-287, CWE-307, CWE-798 | Python, Java, Go, Rust, C, C++, JS | API Service |
| 10 | A08: Integrity Failures | `integrity-failures/` | CWE-502, CWE-829 | Python, Java, Go, JS | API Service |
| 11 | A09: Logging / Monitoring Failures | `logging-monitoring-failures/` | CWE-778 | Python, Java, Go, Rust, C, C++, JS | API Service |
| 12 | A10: SSRF | `ssrf/` | CWE-918 | Python, Java, Go, Rust, C, C++, JS | API Service |
| 13 | Out-of-bounds Write | `memory-safety/out-of-bounds-write/` | CWE-787 | C, C++, Rust (unsafe) | CLI |
| 14 | Use After Free | `memory-safety/use-after-free/` | CWE-416 | C, C++ | CLI |
| 15 | NULL Pointer Dereference | `memory-safety/null-pointer-deref/` | CWE-476 | C, C++, Go, Java | CLI |
| 16 | Integer Overflow | `integer-overflow/` | CWE-190 | C, C++, Rust, Go, Java | CLI |
| 17 | Race Condition | `race-condition/` | CWE-362 | Python, Java, Go, Rust, C, C++, JS | CLI |

---

## Quick Start

### Python 3.10+

```bash
sudo apt-get update && sudo apt-get install -y python3 python3-pip python3-venv
cd <vulnerability-class>/python/
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

### Java — JDK 17+

```bash
sudo apt-get update && sudo apt-get install -y openjdk-17-jdk maven
cd <vulnerability-class>/java/
mvn compile exec:java
```

Or compile directly:

```bash
javac App.java && java App
```

### Go 1.21+

```bash
# Install Go from https://go.dev/dl/ or via snap
sudo snap install go --classic
cd <vulnerability-class>/go/
go mod download
go run main.go
```

### Rust 1.70+

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
cd <vulnerability-class>/rust/
cargo build && cargo run
```

### C — gcc / clang (C11+)

```bash
sudo apt-get update && sudo apt-get install -y gcc make
cd <vulnerability-class>/c/
make        # or: gcc -std=c11 -o main main.c -lpthread
./main
```

### C++ — g++ / clang++ (C++17+)

```bash
sudo apt-get update && sudo apt-get install -y g++ make
cd <vulnerability-class>/cpp/
make        # or: g++ -std=c++17 -o main main.cpp -lpthread
./main
```

### JavaScript — Node.js 18+

```bash
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs
cd <vulnerability-class>/javascript/
npm install
node app.js
```

> Each language directory also contains its own `README.md` with build/run instructions specific to that example, including prerequisite installation, dependency setup, and commands to exercise the vulnerable code paths.

---

## Security Code Review Guides

Comprehensive per-language guides live in the [`docs/`](docs/) directory. Each guide covers manual review best practices, common security pitfalls, recommended SAST tools with setup instructions, language-specific vulnerability patterns, and cross-references to the examples in this project.

| Language | Guide |
|---|---|
| Python | [docs/python_security_review_guide.md](docs/python_security_review_guide.md) |
| Java | [docs/java_security_review_guide.md](docs/java_security_review_guide.md) |
| Go | [docs/go_security_review_guide.md](docs/go_security_review_guide.md) |
| Rust | [docs/rust_security_review_guide.md](docs/rust_security_review_guide.md) |
| C | [docs/c_security_review_guide.md](docs/c_security_review_guide.md) |
| C++ | [docs/cpp_security_review_guide.md](docs/cpp_security_review_guide.md) |
| JavaScript | [docs/javascript_security_review_guide.md](docs/javascript_security_review_guide.md) |

See [docs/README.md](docs/README.md) for the full index.

---

## Artifact Types

Every language directory within a vulnerability class contains the following artifacts:

| Artifact | Filename Pattern | Description |
|---|---|---|
| **Source File** | `app.py`, `App.java`, `main.go`, `main.rs`, `main.c`, `main.cpp`, `app.js` | A compilable, runnable application containing one or more intentional security vulnerabilities. Source files contain no security-related comments so they can be used for unbiased manual code review exercises. |
| **Companion Doc** | `{name}_SECURITY.md` (e.g., `app_SECURITY.md`) | The answer key. Documents every vulnerability in the source file including CWE identifiers, OWASP categories, affected line ranges, exploitation scenarios, remediation guidance, complexity level, and detection difficulty. |
| **Expected Findings Manifest** | `{name}_expected.json` (e.g., `app_expected.json`) | Machine-readable JSON listing all intentional vulnerabilities with CWE, line ranges, complexity level, and SAST detection difficulty. Use this to automatically compare SAST tool output against known ground truth. |
| **Build / Run Instructions** | `README.md` | Per-directory instructions for installing prerequisites, building, and running the specific example on Linux. Includes port numbers and `curl` examples for web/API apps, or sample CLI invocations for command-line apps. |
| **Dependency Manifest** | `requirements.txt`, `pom.xml`, `go.mod`, `Cargo.toml`, `Makefile`, `package.json` | Language-specific dependency file with pinned versions, ensuring reproducible builds. |

### JSON Schema

The expected findings manifests conform to the JSON schema at [`schemas/expected_findings.schema.json`](schemas/expected_findings.schema.json).

---

## Distribution Statistics

Computed from 534 total vulnerability findings across 95 expected-findings manifests.

### Complexity Level Breakdown

| Level | Description | Count | Percentage |
|---|---|---|---|
| **Obvious** | Vulnerability is immediately visible with basic code reading skills | 162 | 30.3% |
| **Moderate** | Requires understanding of the framework or language semantics to identify | 223 | 41.8% |
| **Nuanced** | Requires deep contextual understanding, multi-step reasoning, or business logic analysis | 149 | 27.9% |

> Minimum thresholds: ≥30% Obvious ✓, ≥30% Moderate ✓, ≥20% Nuanced ✓.

### Detection Difficulty Breakdown

| Level | Description | Count | Percentage |
|---|---|---|---|
| **Easily_Detectable** | Well-known pattern with direct taint flow; most SAST tools will flag it | 187 | 35.0% |
| **Pattern_Dependent** | Requires interprocedural analysis or framework-specific knowledge | 184 | 34.5% |
| **Likely_Missed** | Depends on business logic, configuration state, or multi-step cross-module data flow | 163 | 30.5% |

> Minimum thresholds: ≥30% Easily_Detectable ✓, ≥20% Likely_Missed ✓.

---

## Project Structure

```
security-bug-examples/
├── README.md                              ← You are here
├── docs/                                  ← Security code review guides
│   ├── README.md
│   ├── python_security_review_guide.md
│   ├── java_security_review_guide.md
│   ├── go_security_review_guide.md
│   ├── rust_security_review_guide.md
│   ├── c_security_review_guide.md
│   ├── cpp_security_review_guide.md
│   └── javascript_security_review_guide.md
├── schemas/
│   └── expected_findings.schema.json      ← JSON schema for manifests
├── broken-access-control/                 ← OWASP A01
├── cryptographic-failures/                ← OWASP A02
├── injection/
│   ├── sql-injection/                     ← OWASP A03 (CWE-89)
│   ├── command-injection/                 ← OWASP A03 (CWE-78)
│   └── xss/                              ← OWASP A03 (CWE-79)
├── insecure-design/                       ← OWASP A04
├── security-misconfiguration/             ← OWASP A05
├── vulnerable-components/                 ← OWASP A06
├── auth-failures/                         ← OWASP A07
├── integrity-failures/                    ← OWASP A08
├── logging-monitoring-failures/           ← OWASP A09
├── ssrf/                                  ← OWASP A10
├── memory-safety/
│   ├── out-of-bounds-write/               ← CWE-787
│   ├── use-after-free/                    ← CWE-416
│   └── null-pointer-deref/                ← CWE-476
├── integer-overflow/                      ← CWE-190
├── race-condition/                        ← CWE-362
└── validate.py                            ← Validation script
```

---

## License

This project is intended for educational and security research purposes only. The intentionally vulnerable code should never be deployed in production environments.
