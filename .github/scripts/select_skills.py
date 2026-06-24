#!/usr/bin/env python3
"""Select security review skills for a target repository.

The selector is intentionally local-only: it scans filenames and a small
bounded amount of manifest/config text, then writes ``selected-skills.json``.
It never treats target-repo agent instruction files or plugin hook metadata as
governing instructions.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import shutil
import sys
from collections.abc import Iterable
from typing import cast


MAX_TEXT_BYTES = 64 * 1024

MAX_ADDITIONAL_SKILLS = 5

PYTHON_COMPLEXITY_FILE_THRESHOLD = 50

TIER_MANDATORY_ALWAYS = "mandatory_always"
TIER_MANDATORY_CONDITIONAL = "mandatory_conditional"
TIER_OPTIONAL = "optional"

MODE_PR_REVIEW = "pr_review"
MODE_BASELINE = "baseline"
MODES = (MODE_PR_REVIEW, MODE_BASELINE)

SKIP_DIRS = {
    ".cache",
    ".claude",
    ".claude-plugin",
    ".codex",
    ".codex-plugin",
    ".git",
    ".hg",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".svn",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "target",
    "vendor",
    "venv",
}

IGNORED_FILENAMES = {
    "AGENTS.md",
    "CLAUDE.md",
}

SOURCE_EXTENSIONS: dict[str, str] = {
    ".c": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".go": "go",
    ".h": "c_header",
    ".hh": "cpp",
    ".hpp": "cpp",
    ".hxx": "cpp",
    ".java": "java",
    ".js": "javascript",
    ".jsx": "javascript",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".mjs": "javascript",
    ".py": "python",
    ".pyx": "python",
    ".rb": "ruby",
    ".rs": "rust",
    ".swift": "swift",
    ".ts": "typescript",
    ".tsx": "typescript",
}

SMART_CONTRACT_EXTENSIONS: dict[str, str] = {
    ".cairo": "cairo",
    ".fc": "ton",
    ".func": "ton",
    ".sol": "solidity",
    ".teal": "algorand",
    ".tlb": "ton",
    ".vy": "vyper",
}

PACKAGE_MANIFESTS = {
    "Cargo.lock",
    "Cargo.toml",
    "Gemfile",
    "Gemfile.lock",
    "Package.resolved",
    "Package.swift",
    "go.mod",
    "go.sum",
    "package-lock.json",
    "package.json",
    "pnpm-lock.yaml",
    "poetry.lock",
    "pom.xml",
    "pyproject.toml",
    "requirements.txt",
    "requirements-dev.txt",
    "requirements-test.txt",
    "uv.lock",
    "yarn.lock",
}

CPP_BUILD_FILES = {
    "CMakeLists.txt",
    "Makefile",
    "configure.ac",
    "meson.build",
}

CRYPTO_PATH_RE = re.compile(
    r"(crypto|cryptography|constant[-_]?time|tls|ssl|openssl|"
    r"curve25519|ed25519|ecdsa|rsa|aes|hmac|sha[0-9]*|keccak|bls)",
    re.IGNORECASE,
)

TOKEN_RE = re.compile(r"(erc20|erc721|erc1155|token|openzeppelin)", re.IGNORECASE)

AI_WORKFLOW_RE = re.compile(
    r"(anthropic|claude|codex|openai|gemini|agentic|ai[-_ ]?agent|aider|cursor)",
    re.IGNORECASE,
)

AI_ML_RE = re.compile(
    r"(tensorflow|pytorch|\btorch\b|keras|\bjax\b|onnx|transformers|huggingface|"
    r"langchain|llama[-_]?index|vllm|sentence[-_]transformers|scikit[-_]?learn|"
    r"\bsklearn\b|diffusers|mlflow|litellm|ollama|openai|anthropic|cohere|"
    r"mistralai|\bllm\b|langgraph|autogen|crewai)",
    re.IGNORECASE,
)

AI_MODEL_EXTENSIONS = {
    ".ckpt",
    ".gguf",
    ".h5",
    ".onnx",
    ".pt",
    ".pth",
    ".safetensors",
}

MITRE_ATLAS_SIGNALS = {"ai_ml", "ai_workflow", "github-actions-ai"}
MITRE_ATLAS_DATA_REPOSITORY = "mitre-atlas/atlas-data"
MITRE_ATLAS_DATA_URL = "https://github.com/mitre-atlas/atlas-data"
MITRE_ATLAS_DATA_FILE = "dist/ATLAS-latest.yaml"

CODEQL_RE = re.compile(r"(codeql-action|github/codeql|codeql)", re.IGNORECASE)
SEMGREP_RE = re.compile(r"(semgrep|p/ci|rules:)", re.IGNORECASE)


@dataclass(frozen=True)
class Skill:
    """A concrete skill entry in a security-review skills marketplace."""

    key: str
    plugin: str
    skill: str
    path: str
    repository: str = "trailofbits/skills"
    root_dir: str = "skills"
    ref_override: str | None = None

    @property
    def ref(self) -> str:
        if self.ref_override is not None:
            return self.ref_override
        plugin_ref = f"{self.repository}/plugins/{self.plugin}"
        if self.plugin == self.skill:
            return plugin_ref
        return f"{plugin_ref}/skills/{self.skill}"


@dataclass(frozen=True)
class Rule:
    """Mapping from detected context signals to a candidate skill."""

    skill_key: str
    signals: tuple[str, ...]
    reason: str


@dataclass
class RepoContext:
    """Signals collected from a bounded local scan of the target repo."""

    languages: Counter[str]
    configs: set[str]
    signals: set[str]
    signal_paths: dict[str, set[str]]
    scanned_files: int = 0

    def add_signal(self, signal: str, path: str) -> None:
        self.signals.add(signal)
        self.signal_paths[signal].add(path)


SKILLS: dict[str, Skill] = {
    "differential-review": Skill(
        "differential-review",
        "differential-review",
        "differential-review",
        "plugins/differential-review/skills/differential-review/SKILL.md",
    ),
    "sharp-edges": Skill(
        "sharp-edges",
        "sharp-edges",
        "sharp-edges",
        "plugins/sharp-edges/skills/sharp-edges/SKILL.md",
    ),
    "agentic-actions-auditor": Skill(
        "agentic-actions-auditor",
        "agentic-actions-auditor",
        "agentic-actions-auditor",
        "plugins/agentic-actions-auditor/skills/agentic-actions-auditor/SKILL.md",
    ),
    "audit-context-building": Skill(
        "audit-context-building",
        "audit-context-building",
        "audit-context-building",
        "plugins/audit-context-building/skills/audit-context-building/SKILL.md",
    ),
    "burpsuite-project-parser": Skill(
        "burpsuite-project-parser",
        "burpsuite-project-parser",
        "burpsuite-project-parser",
        "plugins/burpsuite-project-parser/skills/burpsuite-project-parser/SKILL.md",
    ),
    "c-review": Skill(
        "c-review",
        "c-review",
        "c-review",
        "plugins/c-review/skills/c-review/SKILL.md",
    ),
    "constant-time-analysis": Skill(
        "constant-time-analysis",
        "constant-time-analysis",
        "constant-time-analysis",
        "plugins/constant-time-analysis/skills/constant-time-analysis/SKILL.md",
    ),
    "devcontainer-setup": Skill(
        "devcontainer-setup",
        "devcontainer-setup",
        "devcontainer-setup",
        "plugins/devcontainer-setup/skills/devcontainer-setup/SKILL.md",
    ),
    "entry-point-analyzer": Skill(
        "entry-point-analyzer",
        "entry-point-analyzer",
        "entry-point-analyzer",
        "plugins/entry-point-analyzer/skills/entry-point-analyzer/SKILL.md",
    ),
    "firebase-apk-scanner": Skill(
        "firebase-apk-scanner",
        "firebase-apk-scanner",
        "firebase-apk-scanner",
        "plugins/firebase-apk-scanner/skills/firebase-apk-scanner/SKILL.md",
    ),
    "insecure-defaults": Skill(
        "insecure-defaults",
        "insecure-defaults",
        "insecure-defaults",
        "plugins/insecure-defaults/skills/insecure-defaults/SKILL.md",
    ),
    "second-opinion": Skill(
        "second-opinion",
        "second-opinion",
        "second-opinion",
        "plugins/second-opinion/skills/second-opinion/SKILL.md",
    ),
    "modern-python": Skill(
        "modern-python",
        "modern-python",
        "modern-python",
        "plugins/modern-python/skills/modern-python/SKILL.md",
    ),
    "mutation-testing": Skill(
        "mutation-testing",
        "mutation-testing",
        "mutation-testing",
        "plugins/mutation-testing/skills/mutation-testing/SKILL.md",
    ),
    "property-based-testing": Skill(
        "property-based-testing",
        "property-based-testing",
        "property-based-testing",
        "plugins/property-based-testing/skills/property-based-testing/SKILL.md",
    ),
    "semgrep": Skill(
        "semgrep",
        "static-analysis",
        "semgrep",
        "plugins/static-analysis/skills/semgrep/SKILL.md",
    ),
    "sarif-parsing": Skill(
        "sarif-parsing",
        "static-analysis",
        "sarif-parsing",
        "plugins/static-analysis/skills/sarif-parsing/SKILL.md",
    ),
    "codeql": Skill(
        "codeql",
        "static-analysis",
        "codeql",
        "plugins/static-analysis/skills/codeql/SKILL.md",
    ),
    "supply-chain-risk-auditor": Skill(
        "supply-chain-risk-auditor",
        "supply-chain-risk-auditor",
        "supply-chain-risk-auditor",
        "plugins/supply-chain-risk-auditor/skills/supply-chain-risk-auditor/SKILL.md",
    ),
    "deps-dev-scan-dependencies": Skill(
        "deps-dev-scan-dependencies",
        "scan-dependencies",
        "scan-dependencies",
        "examples/skills/scan-dependencies/SKILL.md",
        "google/deps.dev",
        "deps.dev",
        ref_override="google/deps.dev/examples/skills/scan-dependencies",
    ),
    "trailmark": Skill(
        "trailmark",
        "trailmark",
        "trailmark",
        "plugins/trailmark/skills/trailmark/SKILL.md",
    ),
    "variant-analysis": Skill(
        "variant-analysis",
        "variant-analysis",
        "variant-analysis",
        "plugins/variant-analysis/skills/variant-analysis/SKILL.md",
    ),
    "yara-rule-authoring": Skill(
        "yara-rule-authoring",
        "yara-authoring",
        "yara-rule-authoring",
        "plugins/yara-authoring/skills/yara-rule-authoring/SKILL.md",
    ),
    "zeroize-audit": Skill(
        "zeroize-audit",
        "zeroize-audit",
        "zeroize-audit",
        "plugins/zeroize-audit/skills/zeroize-audit/SKILL.md",
    ),
    "openai-security-best-practices": Skill(
        "openai-security-best-practices",
        "openai-security-best-practices",
        "openai-security-best-practices",
        "plugins/openai-security-best-practices/skills/openai-security-best-practices/SKILL.md",
        "trailofbits/skills-curated",
        "skills-curated",
    ),
    "humanizer": Skill(
        "humanizer",
        "humanizer",
        "humanizer",
        "plugins/humanizer/skills/humanizer/SKILL.md",
        "trailofbits/skills-curated",
        "skills-curated",
    ),
    "python-code-simplifier": Skill(
        "python-code-simplifier",
        "python-code-simplifier",
        "python-code-simplifier",
        "plugins/python-code-simplifier/skills/python-code-simplifier/SKILL.md",
        "trailofbits/skills-curated",
        "skills-curated",
    ),
    "openai-gh-address-comments": Skill(
        "openai-gh-address-comments",
        "openai-gh-address-comments",
        "openai-gh-address-comments",
        "plugins/openai-gh-address-comments/skills/openai-gh-address-comments/SKILL.md",
        "trailofbits/skills-curated",
        "skills-curated",
    ),
    "openai-gh-fix-ci": Skill(
        "openai-gh-fix-ci",
        "openai-gh-fix-ci",
        "openai-gh-fix-ci",
        "plugins/openai-gh-fix-ci/skills/openai-gh-fix-ci/SKILL.md",
        "trailofbits/skills-curated",
        "skills-curated",
    ),
    "openai-security-ownership-map": Skill(
        "openai-security-ownership-map",
        "openai-security-ownership-map",
        "openai-security-ownership-map",
        "plugins/openai-security-ownership-map/skills/openai-security-ownership-map/SKILL.md",
        "trailofbits/skills-curated",
        "skills-curated",
    ),
    "openai-security-threat-model": Skill(
        "openai-security-threat-model",
        "openai-security-threat-model",
        "openai-security-threat-model",
        "plugins/openai-security-threat-model/skills/openai-security-threat-model/SKILL.md",
        "trailofbits/skills-curated",
        "skills-curated",
    ),
    "address-sanitizer": Skill(
        "address-sanitizer",
        "testing-handbook-skills",
        "address-sanitizer",
        "plugins/testing-handbook-skills/skills/address-sanitizer/SKILL.md",
    ),
    "aflpp": Skill(
        "aflpp",
        "testing-handbook-skills",
        "aflpp",
        "plugins/testing-handbook-skills/skills/aflpp/SKILL.md",
    ),
    "atheris": Skill(
        "atheris",
        "testing-handbook-skills",
        "atheris",
        "plugins/testing-handbook-skills/skills/atheris/SKILL.md",
    ),
    "cargo-fuzz": Skill(
        "cargo-fuzz",
        "testing-handbook-skills",
        "cargo-fuzz",
        "plugins/testing-handbook-skills/skills/cargo-fuzz/SKILL.md",
    ),
    "constant-time-testing": Skill(
        "constant-time-testing",
        "testing-handbook-skills",
        "constant-time-testing",
        "plugins/testing-handbook-skills/skills/constant-time-testing/SKILL.md",
    ),
    "coverage-analysis": Skill(
        "coverage-analysis",
        "testing-handbook-skills",
        "coverage-analysis",
        "plugins/testing-handbook-skills/skills/coverage-analysis/SKILL.md",
    ),
    "fuzzing-dictionary": Skill(
        "fuzzing-dictionary",
        "testing-handbook-skills",
        "fuzzing-dictionary",
        "plugins/testing-handbook-skills/skills/fuzzing-dictionary/SKILL.md",
    ),
    "harness-writing": Skill(
        "harness-writing",
        "testing-handbook-skills",
        "harness-writing",
        "plugins/testing-handbook-skills/skills/harness-writing/SKILL.md",
    ),
    "libfuzzer": Skill(
        "libfuzzer",
        "testing-handbook-skills",
        "libfuzzer",
        "plugins/testing-handbook-skills/skills/libfuzzer/SKILL.md",
    ),
    "ruzzy": Skill(
        "ruzzy",
        "testing-handbook-skills",
        "ruzzy",
        "plugins/testing-handbook-skills/skills/ruzzy/SKILL.md",
    ),
    "wycheproof": Skill(
        "wycheproof",
        "testing-handbook-skills",
        "wycheproof",
        "plugins/testing-handbook-skills/skills/wycheproof/SKILL.md",
    ),
    "algorand-vulnerability-scanner": Skill(
        "algorand-vulnerability-scanner",
        "building-secure-contracts",
        "algorand-vulnerability-scanner",
        "plugins/building-secure-contracts/skills/algorand-vulnerability-scanner/SKILL.md",
    ),
    "cairo-vulnerability-scanner": Skill(
        "cairo-vulnerability-scanner",
        "building-secure-contracts",
        "cairo-vulnerability-scanner",
        "plugins/building-secure-contracts/skills/cairo-vulnerability-scanner/SKILL.md",
    ),
    "code-maturity-assessor": Skill(
        "code-maturity-assessor",
        "building-secure-contracts",
        "code-maturity-assessor",
        "plugins/building-secure-contracts/skills/code-maturity-assessor/SKILL.md",
    ),
    "cosmos-vulnerability-scanner": Skill(
        "cosmos-vulnerability-scanner",
        "building-secure-contracts",
        "cosmos-vulnerability-scanner",
        "plugins/building-secure-contracts/skills/cosmos-vulnerability-scanner/SKILL.md",
    ),
    "secure-workflow-guide": Skill(
        "secure-workflow-guide",
        "building-secure-contracts",
        "secure-workflow-guide",
        "plugins/building-secure-contracts/skills/secure-workflow-guide/SKILL.md",
    ),
    "solana-vulnerability-scanner": Skill(
        "solana-vulnerability-scanner",
        "building-secure-contracts",
        "solana-vulnerability-scanner",
        "plugins/building-secure-contracts/skills/solana-vulnerability-scanner/SKILL.md",
    ),
    "substrate-vulnerability-scanner": Skill(
        "substrate-vulnerability-scanner",
        "building-secure-contracts",
        "substrate-vulnerability-scanner",
        "plugins/building-secure-contracts/skills/substrate-vulnerability-scanner/SKILL.md",
    ),
    "token-integration-analyzer": Skill(
        "token-integration-analyzer",
        "building-secure-contracts",
        "token-integration-analyzer",
        "plugins/building-secure-contracts/skills/token-integration-analyzer/SKILL.md",
    ),
    "ton-vulnerability-scanner": Skill(
        "ton-vulnerability-scanner",
        "building-secure-contracts",
        "ton-vulnerability-scanner",
        "plugins/building-secure-contracts/skills/ton-vulnerability-scanner/SKILL.md",
    ),
}

RULES: tuple[Rule, ...] = (
    Rule(
        "burpsuite-project-parser",
        ("burp-project",),
        "Burp Suite project artifacts are present.",
    ),
    Rule(
        "firebase-apk-scanner",
        ("android-firebase", "apk"),
        "Android or Firebase mobile artifacts are present.",
    ),
    Rule("yara-rule-authoring", ("yara",), "YARA rules are present."),
    Rule(
        "codeql",
        ("codeql-config", "codeql-workflow"),
        "CodeQL configuration or workflow context is present.",
    ),
    Rule("sarif-parsing", ("sarif",), "SARIF analysis output is present."),
    Rule(
        "semgrep",
        ("semgrep-config",),
        "Semgrep configuration or rules are present.",
    ),
    Rule(
        "solana-vulnerability-scanner",
        ("solana",),
        "Solana or Anchor smart-contract context is present.",
    ),
    Rule(
        "cosmos-vulnerability-scanner",
        ("cosmos", "cosmwasm"),
        "Cosmos SDK or CosmWasm context is present.",
    ),
    Rule(
        "substrate-vulnerability-scanner",
        ("substrate",),
        "Substrate or FRAME context is present.",
    ),
    Rule(
        "cairo-vulnerability-scanner",
        ("cairo",),
        "Cairo or StarkNet smart-contract context is present.",
    ),
    Rule(
        "algorand-vulnerability-scanner",
        ("algorand",),
        "Algorand TEAL or PyTeal smart-contract context is present.",
    ),
    Rule(
        "ton-vulnerability-scanner",
        ("ton",),
        "TON FunC/Tact smart-contract context is present.",
    ),
    Rule(
        "secure-workflow-guide",
        ("solidity", "vyper", "foundry", "hardhat"),
        "EVM smart-contract context is present.",
    ),
    Rule(
        "entry-point-analyzer",
        ("smart-contract",),
        "Smart-contract entry point analysis is relevant.",
    ),
    Rule(
        "token-integration-analyzer",
        ("token-contract",),
        "Token implementation or integration context is present.",
    ),
    Rule(
        "c-review",
        ("c", "cpp", "cpp-build"),
        "C or C++ source/build context is present.",
    ),
    Rule(
        "python-code-simplifier",
        ("python-many-files",),
        "Large Python codebase can benefit from complexity-reducing simplification.",
    ),
    Rule(
        "cargo-fuzz",
        ("rust-fuzzing",),
        "Rust fuzzing context is present.",
    ),
    Rule(
        "atheris",
        ("python-fuzzing",),
        "Python fuzzing context is present.",
    ),
    Rule(
        "ruzzy",
        ("ruby-fuzzing",),
        "Ruby fuzzing context is present.",
    ),
    Rule(
        "address-sanitizer",
        ("native-fuzzing", "memory-unsafe"),
        "Native memory-unsafe code can benefit from sanitizer-backed testing.",
    ),
    Rule(
        "libfuzzer",
        ("native-fuzzing",),
        "C/C++ fuzzing context is present.",
    ),
    Rule(
        "harness-writing",
        ("fuzzing",),
        "Fuzz target or harness context is present.",
    ),
    Rule(
        "fuzzing-dictionary",
        ("parser-protocol",),
        "Parser, protocol, or file-format code can benefit from dictionaries.",
    ),
    Rule(
        "constant-time-analysis",
        ("crypto",),
        "Cryptographic implementation context is present.",
    ),
    Rule(
        "constant-time-testing",
        ("crypto",),
        "Cryptographic code can benefit from timing side-channel tests.",
    ),
    Rule(
        "wycheproof",
        ("crypto",),
        "Cryptographic implementation context can use known-answer vectors.",
    ),
    Rule(
        "zeroize-audit",
        ("secret-zeroization",),
        "Secret-bearing native or Rust code may need zeroization review.",
    ),
    Rule(
        "property-based-testing",
        ("property-testing", "smart-contract"),
        "Existing test context suggests property-based testing is relevant.",
    ),
    Rule(
        "mutation-testing",
        ("mutation-testing",),
        "Mutation testing configuration or tooling is present.",
    ),
    Rule(
        "supply-chain-risk-auditor",
        ("dependencies",),
        "Package manifests or lockfiles are present.",
    ),
    Rule(
        "deps-dev-scan-dependencies",
        ("dependencies",),
        "Package manifests or lockfiles can be enriched with deps.dev metadata.",
    ),
    Rule(
        "openai-gh-fix-ci",
        ("github-actions",),
        "CI workflows are present and may need failing-check remediation.",
    ),
    Rule(
        "openai-security-ownership-map",
        ("ownership",),
        "Ownership metadata is present and can help route security fixes.",
    ),
    Rule(
        "insecure-defaults",
        ("configuration",),
        "Configuration files are present.",
    ),
    Rule(
        "devcontainer-setup",
        ("devcontainer",),
        "Devcontainer or containerized development context is present.",
    ),
    Rule(
        "variant-analysis",
        ("security-rules",),
        "Security rules or findings suggest variant analysis is useful.",
    ),
    Rule(
        "trailmark",
        ("source",),
        "Source code is present and can benefit from structural code graph analysis.",
    ),
    Rule(
        "audit-context-building",
        ("source",),
        "Source code is present and can benefit from audit context building.",
    ),
    Rule(
        "openai-security-threat-model",
        ("source",),
        "Source code is present and can benefit from repository-grounded threat modeling.",
    ),
    Rule(
        "openai-security-best-practices",
        ("source",),
        "Source code is present and can benefit from language/framework security guidance.",
    ),
)


@dataclass(frozen=True)
class MandatoryRule:
    """A mandatory-tier skill with conditional signal gating and usage guidance."""

    skill_key: str
    signals: tuple[str, ...]
    reason: str
    usage: str


MANDATORY_ALWAYS: tuple[MandatoryRule, ...] = (
    MandatoryRule(
        "differential-review",
        (),
        "Baseline security-focused differential review.",
        "Always run as the canonical base review of the diff.",
    ),
    MandatoryRule(
        "sharp-edges",
        (),
        "Flag error-prone APIs, footguns, and insecure-by-default designs.",
        "Always check changed APIs and configuration for misuse-prone patterns.",
    ),
    MandatoryRule(
        "insecure-defaults",
        (),
        "Detect fail-open defaults, hardcoded secrets, and permissive settings.",
        "Always audit configuration and defaults for fail-open behavior.",
    ),
    MandatoryRule(
        "second-opinion",
        (),
        "Challenge candidate findings before producing externally visible output.",
        "Always independently re-check exploitability and reachability before reporting.",
    ),
    MandatoryRule(
        "humanizer",
        (),
        "Keep generated review prose natural and free of AI tells.",
        "Always apply to review narrative before posting comments.",
    ),
)

# Baseline (whole-repo) scans have no diff, so differential-review is replaced by
# repo-wide audit-context-building and threat modeling; the rest of the always-on
# tier carries over unchanged.
BASELINE_MANDATORY_ALWAYS: tuple[MandatoryRule, ...] = (
    MandatoryRule(
        "audit-context-building",
        (),
        "Build whole-repository audit context before scanning.",
        "Always map entry points, trust boundaries, and assets across the repo first.",
    ),
    MandatoryRule(
        "sharp-edges",
        (),
        "Flag error-prone APIs, footguns, and insecure-by-default designs.",
        "Always check public APIs and configuration for misuse-prone patterns.",
    ),
    MandatoryRule(
        "insecure-defaults",
        (),
        "Detect fail-open defaults, hardcoded secrets, and permissive settings.",
        "Always audit configuration and defaults for fail-open behavior.",
    ),
    MandatoryRule(
        "openai-security-threat-model",
        (),
        "Produce a repository-grounded threat model for the whole codebase.",
        "Always frame findings against the repo's threat model and asset inventory.",
    ),
    MandatoryRule(
        "second-opinion",
        (),
        "Challenge candidate findings before producing externally visible output.",
        "Always independently re-check exploitability and reachability before reporting.",
    ),
    MandatoryRule(
        "humanizer",
        (),
        "Keep generated review prose natural and free of AI tells.",
        "Always apply to issue and report narrative before posting.",
    ),
)

MANDATORY_CONDITIONAL: tuple[MandatoryRule, ...] = (
    MandatoryRule(
        "agentic-actions-auditor",
        ("github-actions",),
        "GitHub Actions workflows are present and require agentic-CI review.",
        "Audit every changed workflow for prompt-injection and unsafe agent wiring.",
    ),
    MandatoryRule(
        "modern-python",
        ("python",),
        "Python is present; enforce modern tooling and idioms.",
        "Apply to Python changes for uv/ruff/ty conventions and modern idioms.",
    ),
)

OPTIONAL_USAGE: dict[str, str] = {
    "supply-chain-risk-auditor": "Use when dependency manifests or lockfiles change.",
    "deps-dev-scan-dependencies": (
        "Use to enrich dependencies with deps.dev advisory, license, and OpenSSF Scorecard data."
    ),
    "semgrep": "Run when static-analysis config or security rules are in scope.",
    "codeql": "Run when CodeQL config or workflows indicate dataflow analysis.",
    "sarif-parsing": "Use to triage SARIF output from static-analysis tooling.",
    "python-code-simplifier": "Use to reduce complexity in large Python changes.",
    "openai-security-best-practices": (
        "Use for language/framework-specific secure-coding guidance."
    ),
    "openai-gh-fix-ci": "Use only when CI checks are failing — runtime decision.",
}

DEFAULT_OPTIONAL_USAGE = "Apply when the matched signals are relevant to the diff."


def _read_text_prefix(path: Path) -> str:
    try:
        return path.read_bytes()[:MAX_TEXT_BYTES].decode("utf-8", errors="ignore")
    except OSError:
        return ""


def _is_plugin_hook_metadata(parts: tuple[str, ...]) -> bool:
    if "hooks" not in parts:
        return False
    for marker in (".claude", ".codex", ".claude-plugin", ".codex-plugin"):
        if marker in parts:
            return True
    return len(parts) >= 3 and parts[0] == "plugins" and "hooks" in parts[2:]


def _should_skip_file(rel_path: Path) -> bool:
    parts = rel_path.parts
    if not parts:
        return True
    if rel_path.name in IGNORED_FILENAMES:
        return True
    if any(part in {".claude-plugin", ".codex-plugin"} for part in parts):
        return True
    return _is_plugin_hook_metadata(parts)


def _repo_files(root: Path) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(
            d for d in dirnames if d not in SKIP_DIRS and not d.endswith(".egg-info")
        )
        base = Path(dirpath)
        for filename in sorted(filenames):
            rel_path = (base / filename).relative_to(root)
            if _should_skip_file(rel_path):
                continue
            yield rel_path


def _add_language_signal(context: RepoContext, language: str, rel: str) -> None:
    context.languages[language] += 1
    context.add_signal(language, rel)
    context.add_signal("source", rel)
    if language in {"c", "cpp", "c_header", "rust"}:
        context.add_signal("memory-unsafe", rel)


def _detect_manifest_signals(path: Path, rel: str, context: RepoContext) -> None:
    name = path.name
    lower_rel = rel.lower()
    lower_name = name.lower()

    if name in PACKAGE_MANIFESTS or lower_name.startswith("requirements"):
        context.configs.add("dependencies")
        context.add_signal("dependencies", rel)

    if name in CPP_BUILD_FILES or lower_name.endswith((".bzl", ".bazel")):
        context.configs.add("cpp-build")
        context.add_signal("cpp-build", rel)

    if name in {"pyproject.toml", "requirements.txt", "uv.lock"}:
        context.configs.add("python-package")
        context.add_signal("python-package", rel)

    if name in {"Dockerfile", "docker-compose.yml", "docker-compose.yaml"}:
        context.configs.add("configuration")
        context.add_signal("configuration", rel)

    if lower_rel.startswith(".devcontainer/") or name == "devcontainer.json":
        context.configs.add("devcontainer")
        context.add_signal("devcontainer", rel)

    if lower_rel.startswith(".github/workflows/") and path.suffix.lower() in {
        ".yaml",
        ".yml",
    }:
        context.configs.add("github-actions")
        context.add_signal("github-actions", rel)
        text = _read_text_prefix(path)
        if AI_WORKFLOW_RE.search(text):
            context.add_signal("ai_workflow", rel)
            context.add_signal("github-actions-ai", rel)
        if CODEQL_RE.search(text):
            context.add_signal("codeql-workflow", rel)

    if "codeql" in lower_rel and path.suffix.lower() in {".yaml", ".yml", ".ql"}:
        context.configs.add("codeql")
        context.add_signal("codeql-config", rel)

    if (
        ".semgrep" in lower_rel
        or lower_name.startswith("semgrep")
        or (path.suffix.lower() in {".yaml", ".yml"} and SEMGREP_RE.search(lower_rel))
    ):
        context.configs.add("semgrep")
        context.add_signal("semgrep-config", rel)

    if path.suffix.lower() == ".sarif":
        context.configs.add("sarif")
        context.add_signal("sarif", rel)

    if name == "CODEOWNERS" or lower_rel.endswith("/codeowners"):
        context.configs.add("ownership")
        context.add_signal("ownership", rel)

    if path.suffix.lower() in {".yar", ".yara"}:
        context.configs.add("yara")
        context.add_signal("yara", rel)

    if path.suffix.lower() == ".burp":
        context.configs.add("burp-project")
        context.add_signal("burp-project", rel)

    if path.suffix.lower() == ".apk":
        context.configs.add("apk")
        context.add_signal("apk", rel)

    if name in {"google-services.json", "AndroidManifest.xml"}:
        context.configs.add("android-firebase")
        context.add_signal("android-firebase", rel)

    if lower_name in {".env", ".env.example"} or "config" in lower_name:
        context.configs.add("configuration")
        context.add_signal("configuration", rel)


def _detect_content_signals(path: Path, rel: str, context: RepoContext) -> None:
    name = path.name
    lower_rel = rel.lower()
    needs_text = (
        name in {"Cargo.toml", "go.mod", "package.json", "pyproject.toml"}
        or lower_rel.startswith(".github/workflows/")
        or name.lower().startswith("requirements")
        or path.suffix.lower() in {".sol", ".rs", ".go", ".py", ".yaml", ".yml", ".ipynb"}
    )
    if not needs_text:
        return

    text = _read_text_prefix(path)
    lower_text = text.lower()
    if not lower_text:
        return

    if AI_ML_RE.search(lower_text):
        context.add_signal("ai_ml", rel)

    if AI_WORKFLOW_RE.search(lower_text):
        context.add_signal("ai_workflow", rel)
        if lower_rel.startswith(".github/workflows/"):
            context.add_signal("github-actions-ai", rel)

    if CODEQL_RE.search(lower_text) and lower_rel.startswith(".github/workflows/"):
        context.add_signal("codeql-workflow", rel)

    if SEMGREP_RE.search(lower_text) and path.suffix.lower() in {".yaml", ".yml"}:
        context.add_signal("semgrep-config", rel)

    if any(token in lower_text for token in ("anchor-lang", "anchor_lang", "solana_program")):
        context.add_signal("solana", rel)
        context.add_signal("smart-contract", rel)

    if any(token in lower_text for token in ("cosmos-sdk", "cosmwasm", "wasmvm")):
        context.add_signal("cosmos", rel)
        context.add_signal("smart-contract", rel)

    if any(token in lower_text for token in ("frame-support", "frame_support", "substrate")):
        context.add_signal("substrate", rel)
        context.add_signal("smart-contract", rel)

    if any(token in lower_text for token in ("hardhat", "truffle", "openzeppelin")):
        context.add_signal("hardhat", rel)
        context.add_signal("smart-contract", rel)

    if any(token in lower_text for token in ("hypothesis", "proptest", "quickcheck", "fast-check")):
        context.add_signal("property-testing", rel)

    if any(token in lower_text for token in ("mutmut", "mutagen", "muton", "mewt", "stryker")):
        context.add_signal("mutation-testing", rel)

    if any(
        token in lower_text
        for token in ("atheris", "cargo-fuzz", "libfuzzer", "afl++", "aflplusplus")
    ):
        context.add_signal("fuzzing", rel)

    if CRYPTO_PATH_RE.search(lower_text):
        context.add_signal("crypto", rel)

    if TOKEN_RE.search(lower_text):
        context.add_signal("token-contract", rel)


def _detect_path_signals(rel_path: Path, context: RepoContext) -> None:
    rel = rel_path.as_posix()
    suffix = rel_path.suffix.lower()
    lower_rel = rel.lower()
    lower_name = rel_path.name.lower()

    _detect_manifest_signals(rel_path, rel, context)

    language = SOURCE_EXTENSIONS.get(suffix)
    if language is not None:
        _add_language_signal(context, language, rel)

    if suffix in AI_MODEL_EXTENSIONS or suffix == ".ipynb":
        context.add_signal("ai_ml", rel)

    smart_contract = SMART_CONTRACT_EXTENSIONS.get(suffix)
    if smart_contract is not None:
        context.languages[smart_contract] += 1
        context.add_signal(smart_contract, rel)
        context.add_signal("smart-contract", rel)
        context.add_signal("source", rel)

    if lower_name in {"foundry.toml", "slither.config.json", "slither.config.yaml"}:
        context.add_signal("foundry", rel)
        context.add_signal("smart-contract", rel)

    if lower_name.startswith("hardhat.config") or lower_name.startswith("truffle-config"):
        context.add_signal("hardhat", rel)
        context.add_signal("smart-contract", rel)

    if lower_name in {"anchor.toml", "scarb.toml", "algokit.toml"}:
        signal = {
            "anchor.toml": "solana",
            "scarb.toml": "cairo",
            "algokit.toml": "algorand",
        }[lower_name]
        context.add_signal(signal, rel)
        context.add_signal("smart-contract", rel)

    if lower_name in {"tact.config.json", "tact.config.ts"}:
        context.add_signal("ton", rel)
        context.add_signal("smart-contract", rel)

    if CRYPTO_PATH_RE.search(lower_rel):
        context.add_signal("crypto", rel)

    if TOKEN_RE.search(lower_rel):
        context.add_signal("token-contract", rel)

    if any(part in lower_rel for part in ("fuzz", "fuzzer", "fuzzing")):
        context.add_signal("fuzzing", rel)
        if context.signals.intersection({"c", "cpp", "cpp-build"}):
            context.add_signal("native-fuzzing", rel)
        if "rust" in context.signals or "cargo.toml" in lower_rel:
            context.add_signal("rust-fuzzing", rel)
        if "python" in context.signals:
            context.add_signal("python-fuzzing", rel)
        if "ruby" in context.signals:
            context.add_signal("ruby-fuzzing", rel)

    if any(part in lower_rel for part in ("parser", "protocol", "codec", "protobuf")):
        context.add_signal("parser-protocol", rel)

    if ("semgrep" in lower_rel or "rules/" in lower_rel) and suffix in {".yaml", ".yml"}:
        context.add_signal("security-rules", rel)


def detect_context(root: Path) -> RepoContext:
    context = RepoContext(
        languages=Counter(),
        configs=set(),
        signals=set(),
        signal_paths=defaultdict(set),
    )
    for rel_path in _repo_files(root):
        context.scanned_files += 1
        _detect_path_signals(rel_path, context)
        _detect_content_signals(root / rel_path, rel_path.as_posix(), context)

    if context.languages["c_header"] and context.languages["cpp"]:
        context.languages["cpp"] += context.languages.pop("c_header")
        context.add_signal("cpp", "headers")
    elif context.languages["c_header"]:
        context.languages["c"] += context.languages.pop("c_header")
        context.add_signal("c", "headers")

    if context.signals.intersection({"c", "cpp", "cpp-build"}) and "fuzzing" in context.signals:
        context.add_signal("native-fuzzing", "fuzzing")
    if "rust" in context.signals and "fuzzing" in context.signals:
        context.add_signal("rust-fuzzing", "fuzzing")
    if "python" in context.signals and "fuzzing" in context.signals:
        context.add_signal("python-fuzzing", "fuzzing")
    if "ruby" in context.signals and "fuzzing" in context.signals:
        context.add_signal("ruby-fuzzing", "fuzzing")
    if context.signals.intersection({"c", "cpp", "rust"}) and "crypto" in context.signals:
        context.add_signal("secret-zeroization", "crypto")

    if context.languages["python"] >= PYTHON_COMPLEXITY_FILE_THRESHOLD:
        context.add_signal("python-many-files", "python")

    return context


@dataclass(frozen=True)
class SelectedSkill:
    """A skill chosen for the target repo together with its tier and rationale."""

    skill: Skill
    tier: str
    reason: str
    usage: str
    signals: list[str]


def _matched_signals(signals: tuple[str, ...], context: RepoContext) -> list[str]:
    return [signal for signal in signals if signal in context.signals]


def _select_mandatory_always(mode: str) -> list[SelectedSkill]:
    rules = BASELINE_MANDATORY_ALWAYS if mode == MODE_BASELINE else MANDATORY_ALWAYS
    return [
        SelectedSkill(
            SKILLS[rule.skill_key],
            TIER_MANDATORY_ALWAYS,
            rule.reason,
            rule.usage,
            ["always"],
        )
        for rule in rules
    ]


def _select_mandatory_conditional(
    context: RepoContext, selected_keys: set[str]
) -> list[SelectedSkill]:
    selected: list[SelectedSkill] = []
    for rule in MANDATORY_CONDITIONAL:
        if rule.skill_key in selected_keys:
            continue
        matched = _matched_signals(rule.signals, context)
        if not matched:
            continue
        selected.append(
            SelectedSkill(
                SKILLS[rule.skill_key],
                TIER_MANDATORY_CONDITIONAL,
                rule.reason,
                rule.usage,
                matched,
            )
        )
        selected_keys.add(rule.skill_key)
    return selected


def _select_optional(context: RepoContext, selected_keys: set[str]) -> list[SelectedSkill]:
    selected: list[SelectedSkill] = []
    for rule in RULES:
        if len(selected) >= MAX_ADDITIONAL_SKILLS:
            break
        if rule.skill_key in selected_keys:
            continue
        matched = _matched_signals(rule.signals, context)
        if not matched:
            continue
        selected.append(
            SelectedSkill(
                SKILLS[rule.skill_key],
                TIER_OPTIONAL,
                rule.reason,
                OPTIONAL_USAGE.get(rule.skill_key, DEFAULT_OPTIONAL_USAGE),
                matched,
            )
        )
        selected_keys.add(rule.skill_key)
    return selected


def select_skills(context: RepoContext, mode: str = MODE_PR_REVIEW) -> list[SelectedSkill]:
    """Select skills under the tiered policy for a scanned target repo.

    Mandatory tiers (always and signal-gated conditional) are emitted regardless
    of count; only the optional tier is bounded by ``MAX_ADDITIONAL_SKILLS``.

    Args:
        context: Signals collected from a bounded local scan of the target repo.
        mode: ``pr_review`` opens with diff-focused differential review;
            ``baseline`` swaps in whole-repository audit and threat-model skills.

    Returns:
        Selected skills ordered mandatory-always, mandatory-conditional, optional.
    """
    selected = _select_mandatory_always(mode)
    selected_keys = {entry.skill.key for entry in selected}
    selected += _select_mandatory_conditional(context, selected_keys)
    selected += _select_optional(context, selected_keys)
    return selected


def _signal_paths(context: RepoContext, signals: Iterable[str]) -> list[str]:
    paths: set[str] = set()
    for signal in signals:
        paths.update(context.signal_paths.get(signal, set()))
    return sorted(paths)[:8]


def _skill_base(root: Path, skills_root: Path | None, skill: Skill) -> Path:
    if skills_root is None:
        return root
    return skills_root / skill.root_dir


def build_payload(
    root: Path,
    skills_root: Path | None = None,
    mode: str = MODE_PR_REVIEW,
) -> dict[str, object]:
    context = detect_context(root)
    selected = select_skills(context, mode)
    selected_entries: list[dict[str, object]] = []

    for entry in selected:
        skill = entry.skill
        skill_md_path = _skill_base(root, skills_root, skill) / skill.path
        selected_entries.append(
            {
                "id": skill.ref,
                "repository": skill.repository,
                "plugin": skill.plugin,
                "skill": skill.skill,
                "path": skill.path,
                "skill_md": skill.path,
                "absolute_skill_md": str(skill_md_path),
                "path_exists": skill_md_path.is_file(),
                "tier": entry.tier,
                "usage": entry.usage,
                "reason": entry.reason,
                "signals": entry.signals,
                "evidence": _signal_paths(context, entry.signals),
            }
        )

    mitre_atlas_signals = sorted(context.signals.intersection(MITRE_ATLAS_SIGNALS))
    mitre_atlas_data_path = (
        skills_root / "atlas-data" / MITRE_ATLAS_DATA_FILE
        if skills_root is not None
        else root / MITRE_ATLAS_DATA_FILE
    )
    return {
        "target_repo": str(root),
        "mode": mode,
        "skills": [entry["id"] for entry in selected_entries],
        "skill_paths": [entry["path"] for entry in selected_entries],
        "selected_skills": selected_entries,
        "detected": {
            "languages": dict(sorted(context.languages.items())),
            "configs": sorted(context.configs),
            "signals": sorted(context.signals),
            "scanned_files": context.scanned_files,
        },
        "mitre_atlas": {
            "required": bool(mitre_atlas_signals),
            "framework": "MITRE ATLAS",
            "repository": MITRE_ATLAS_DATA_REPOSITORY,
            "source_url": MITRE_ATLAS_DATA_URL,
            "data_file": MITRE_ATLAS_DATA_FILE,
            "absolute_data_file": str(mitre_atlas_data_path),
            "data_file_exists": mitre_atlas_data_path.is_file(),
            "trigger_signals": mitre_atlas_signals,
            "evidence": _signal_paths(context, mitre_atlas_signals),
            "finding_requirement": (
                "For AI/ML/LLM/agentic findings, map applicable findings to "
                "MITRE ATLAS AML tactic and technique IDs when the selected "
                "ATLAS data supports a precise mapping. Do not invent IDs."
            ),
        },
    }


def _stage_selected(payload: dict[str, object], stage_dir: Path) -> None:
    """Copy each selected skill directory into an agent-readable stage directory.

    The awf agent sandbox can only read ``/tmp/gh-aw`` and ``${RUNNER_TEMP}/gh-aw``;
    the Trail of Bits clones under ``${RUNNER_TEMP}/tob-skills`` are outside its
    mounts. Copy the directory holding each selected ``SKILL.md`` (so directly
    referenced supporting docs travel with it) into ``stage_dir`` and rewrite the
    entry's path to the staged copy the agent can actually open.

    Args:
        payload: The selection payload; its ``selected_skills`` entries are
            mutated in place with staged paths.
        stage_dir: Agent-readable directory to copy selected skill folders into.
    """
    stage_dir.mkdir(parents=True, exist_ok=True)
    entries = payload.get("selected_skills")
    if not isinstance(entries, list):
        return
    for raw in entries:
        if not isinstance(raw, dict):
            continue
        entry = cast("dict[str, object]", raw)
        source = Path(str(entry["absolute_skill_md"]))
        entry["source_skill_md"] = str(source)
        if not source.is_file():
            entry["staged"] = False
            entry["path_exists"] = False
            continue
        dest_dir = stage_dir / str(entry["skill"])
        if dest_dir.exists():
            shutil.rmtree(dest_dir, ignore_errors=True)
        shutil.copytree(source.parent, dest_dir)
        staged_md = dest_dir / source.name
        entry["absolute_skill_md"] = str(staged_md)
        entry["staged"] = True
        entry["path_exists"] = staged_md.is_file()


def write_selected_skills(
    target_repo: Path,
    output_path: Path | None = None,
    skills_root: Path | None = None,
    mode: str = MODE_PR_REVIEW,
    stage_dir: Path | None = None,
) -> Path:
    root = target_repo.resolve()
    if not root.exists():
        raise FileNotFoundError(f"target repo does not exist: {target_repo}")
    if not root.is_dir():
        raise NotADirectoryError(f"target repo is not a directory: {target_repo}")

    output = output_path or root / "selected-skills.json"
    resolved_skills_root = skills_root.resolve() if skills_root is not None else None
    payload = build_payload(root, resolved_skills_root, mode)
    if stage_dir is not None:
        _stage_selected(payload, stage_dir.resolve())
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return output


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Select Trail of Bits skills for a local target repository."
    )
    parser.add_argument(
        "target_repo",
        nargs="?",
        type=Path,
        help="Repository path to inspect",
    )
    parser.add_argument(
        "--target-repo",
        dest="target_repo_option",
        type=Path,
        default=None,
        help="Repository path to inspect; preferred for CI workflow calls",
    )
    parser.add_argument(
        "--skills-root",
        type=Path,
        default=None,
        help="Directory containing skills/ and skills-curated/ clones",
    )
    parser.add_argument(
        "--mode",
        choices=MODES,
        default=MODE_PR_REVIEW,
        help="Selection mode: pr_review (diff-focused) or baseline (whole-repo)",
    )
    parser.add_argument(
        "--stage-dir",
        type=Path,
        default=None,
        help="Copy each selected skill directory here (agent-readable) and emit staged paths",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Path to write JSON output; defaults to TARGET_REPO/selected-skills.json",
    )
    args = parser.parse_args(argv)
    args.target_repo = args.target_repo_option or args.target_repo
    if args.target_repo is None:
        parser.error("target repo is required")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        output = write_selected_skills(
            args.target_repo,
            args.output,
            args.skills_root,
            args.mode,
            args.stage_dir,
        )
    except (FileNotFoundError, NotADirectoryError, OSError) as exc:
        print(f"select_skills.py: {exc}", file=sys.stderr)
        return 1
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
