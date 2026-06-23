#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

require_tool() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required tool: $1"
}

safe_temp_dir() {
  local path=$1
  local temp=${RUNNER_TEMP:-}

  [ -n "$temp" ] || fail "RUNNER_TEMP must be set"
  case "$path" in
    "$temp" | "$temp"/*) ;;
    *) fail "TOB_SKILLS_ROOT must be inside RUNNER_TEMP: $path" ;;
  esac
}

clone_at_ref() {
  local repo=$1
  local ref=$2
  local dest=$3

  printf 'Cloning %s at %s into %s\n' "$repo" "$ref" "$dest"
  git clone --filter=blob:none --no-tags "https://github.com/${repo}.git" "$dest"
  git -C "$dest" checkout --detach "$ref"
  git -C "$dest" rev-parse HEAD
}

fetch_file_at_ref() {
  local repo=$1
  local ref=$2
  local path=$3
  local dest=$4

  printf 'Fetching %s@%s:%s into %s\n' "$repo" "$ref" "$path" "$dest"
  mkdir -p "$(dirname "$dest")"
  curl -fsSL --proto '=https' --tlsv1.2 \
    "https://raw.githubusercontent.com/${repo}/${ref}/${path}" -o "$dest"
}

make_read_only() {
  local root=$1

  chmod -R u+rwX "$root"
  find "$root" -type f -exec chmod a-w {} +
  find "$root" -type d -exec chmod a-w {} +
}

require_tool git
require_tool curl
require_tool python3

TOB_SKILLS_REF=${TOB_SKILLS_REF:-d5fe2e6a7896236c3102fd5477e833623ad70298}
TOB_SKILLS_CURATED_REF=${TOB_SKILLS_CURATED_REF:-022fa0948818c9f2f738a428f4546cc65c427767}
# deps.dev (google) is not a Trail of Bits repo; only the single scan-dependencies
# SKILL.md is needed, so fetch that one pinned file rather than clone the monorepo.
DEPS_DEV_REF=${DEPS_DEV_REF:-7863f23c450a8b8e0b21c23d11cbb191842984a3}
DEPS_DEV_SKILL_PATH=examples/skills/scan-dependencies/SKILL.md
# MITRE ATLAS publishes monthly AI-threat data releases. Fetch only the latest
# distributable YAML from the pinned release tag so AI/agentic findings can cite
# real AML tactic/technique IDs without cloning the full repository.
MITRE_ATLAS_REF=${MITRE_ATLAS_REF:-v2026.05}
MITRE_ATLAS_DATA_PATH=dist/ATLAS-latest.yaml
TOB_SKILLS_ROOT=${TOB_SKILLS_ROOT:-"${RUNNER_TEMP:?}/tob-skills"}
AGENT_CONTEXT_DIR=${AGENT_CONTEXT_DIR:-/tmp/gh-aw/agent/raptor-review}

safe_temp_dir "$TOB_SKILLS_ROOT"

if [ -e "$TOB_SKILLS_ROOT" ]; then
  chmod -R u+rwX "$TOB_SKILLS_ROOT"
  rm -rf "$TOB_SKILLS_ROOT"
fi

mkdir -p "$TOB_SKILLS_ROOT" "$AGENT_CONTEXT_DIR"

skills_head=$(clone_at_ref "trailofbits/skills" "$TOB_SKILLS_REF" "$TOB_SKILLS_ROOT/skills")
curated_head=$(clone_at_ref "trailofbits/skills-curated" "$TOB_SKILLS_CURATED_REF" "$TOB_SKILLS_ROOT/skills-curated")
fetch_file_at_ref "google/deps.dev" "$DEPS_DEV_REF" "$DEPS_DEV_SKILL_PATH" \
  "$TOB_SKILLS_ROOT/deps.dev/$DEPS_DEV_SKILL_PATH"
fetch_file_at_ref "mitre-atlas/atlas-data" "$MITRE_ATLAS_REF" "$MITRE_ATLAS_DATA_PATH" \
  "$TOB_SKILLS_ROOT/atlas-data/$MITRE_ATLAS_DATA_PATH"

make_read_only "$TOB_SKILLS_ROOT"

python3 - "$TOB_SKILLS_ROOT" "$skills_head" "$curated_head" "$DEPS_DEV_REF" \
  "$MITRE_ATLAS_REF" \
  "$AGENT_CONTEXT_DIR/skill-library.json" <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path

root, skills_head, curated_head, deps_dev_ref, mitre_atlas_ref, out = sys.argv[1:]
payload = {
    "root": root,
    "repositories": [
        {
            "name": "trailofbits/skills",
            "path": str(Path(root) / "skills"),
            "commit": skills_head,
            "governing_instructions": "ignored unless a selected SKILL.md explicitly references them",
        },
        {
            "name": "trailofbits/skills-curated",
            "path": str(Path(root) / "skills-curated"),
            "commit": curated_head,
            "governing_instructions": "ignored unless a selected SKILL.md explicitly references them",
        },
        {
            "name": "google/deps.dev",
            "path": str(Path(root) / "deps.dev"),
            "commit": deps_dev_ref,
            "governing_instructions": "single scan-dependencies SKILL.md; used as a read-only reference",
        },
        {
            "name": "mitre-atlas/atlas-data",
            "path": str(Path(root) / "atlas-data"),
            "commit": mitre_atlas_ref,
            "data_file": "dist/ATLAS-latest.yaml",
            "governing_instructions": "ATLAS data only; used to map AI/ML/agentic findings to AML IDs",
        },
    ],
}
Path(out).write_text(json.dumps(payload, indent=2) + "\n")
PY

printf 'Trail of Bits skill library manifest: %s\n' "$AGENT_CONTEXT_DIR/skill-library.json"
