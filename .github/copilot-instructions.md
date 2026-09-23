.github/copilot-instructions.md

# ez-appsec Copilot Instructions

## Project Overview
Deterministic application security scanning tool that serves as a free replacement for GitLab and GitHub security scanning.

## Key Objectives
- Build an open-source security scanner with deterministic remediation metadata
- Support multiple programming languages (Python, JavaScript, Java, Go, Ruby, PHP)
- Keep scanner execution independent of all LLM providers and API keys
- Provide CI/CD integration for GitLab and GitHub
- Offer free alternative to commercial security scanning solutions

## Architecture
- **CLI**: Click-based command interface
- **Scanner**: Core orchestration engine
- **Detectors**: Modular detection (SAST, Secrets, Dependencies)
- **No-LLM scan boundary**: scans never send source or findings to an LLM provider
- **Reporter**: Output formatting (JSON, SARIF, HTML)

## Development Priorities
1. Core SAST detection engine
2. Deterministic remediation metadata from scanner-native output
3. CI/CD pipeline templates
4. Multi-language parser support
5. Custom rule engine

## Technology Stack
- Python 3.9+
- Click (CLI framework)
- No LLM provider dependency in scanner runtime
- Pydantic (configuration)
- pytest (testing)
