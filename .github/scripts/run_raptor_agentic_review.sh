#!/usr/bin/env bash
set -euo pipefail

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

path_is_within() {
  local child=$1
  local parent=$2

  [[ "$child" == "$parent" || "$child" == "$parent"/* ]]
}

resolve_existing_dir() {
  local path=$1

  [[ -d "$path" ]] || die "directory does not exist: $path"
  (cd "$path" >/dev/null && pwd -P)
}

lexical_abs_path() {
  local path=$1
  local part
  local old_ifs
  local -a input_parts
  local -a output_parts=()

  if [[ "$path" != /* ]]; then
    path="$(pwd -P)/$path"
  fi

  old_ifs=$IFS
  IFS=/
  read -r -a input_parts <<<"$path"
  IFS=$old_ifs

  for part in "${input_parts[@]}"; do
    case "$part" in
      "" | .)
        ;;
      ..)
        if ((${#output_parts[@]} > 0)); then
          unset "output_parts[${#output_parts[@]}-1]"
        fi
        ;;
      *)
        output_parts+=("$part")
        ;;
    esac
  done

  if ((${#output_parts[@]} == 0)); then
    printf '/\n'
  else
    (IFS=/; printf '/%s\n' "${output_parts[*]}")
  fi
}

nearest_existing_dir() {
  local path=$1
  local probe=$path

  while [[ ! -d "$probe" ]]; do
    [[ "$probe" == "/" ]] && break
    probe=$(dirname "$probe")
  done

  resolve_existing_dir "$probe"
}

bool_requested() {
  local name=$1
  local value=${2:-false}

  case "$value" in
    1 | true | TRUE | yes | YES | on | ON)
      return 0
      ;;
    0 | false | FALSE | no | NO | off | OFF | "")
      return 1
      ;;
    *)
      die "$name must be one of true/false, 1/0, yes/no, on/off"
      ;;
  esac
}

require_nonnegative_integer() {
  local name=$1
  local value=$2

  case "$value" in
    '' | *[!0-9]*) die "$name must be a non-negative integer" ;;
  esac
}

enable_codeql_requested() {
  bool_requested ENABLE_CODEQL "${1:-false}"
}

phase_seconds() {
  local start=$1
  local end

  end=$(date +%s)
  printf '%s\n' "$((end - start))"
}

print_phase_timing() {
  local phase=$1
  local duration=$2
  local status=${3:-}

  if [[ -n "$status" ]]; then
    printf 'KITE_PHASE_TIMING phase=%s duration_seconds=%s status=%s\n' \
      "$phase" "$duration" "$status"
  else
    printf 'KITE_PHASE_TIMING phase=%s duration_seconds=%s\n' "$phase" "$duration"
  fi
}

has_explicit_codeql_arg() {
  local arg

  for arg in "$@"; do
    case "$arg" in
      --codeql | --codeql-only | --no-codeql)
        return 0
        ;;
    esac
  done

  return 1
}

reject_control_arg_overrides() {
  local arg

  for arg in "$@"; do
    case "$arg" in
      --repo | --repo=* | --out | --out=*)
        die "pass TARGET_REPO_PATH and RAPTOR_OUT_DIR via environment; refusing pass-through override: $arg"
        ;;
    esac
  done
}

run_and_log() {
  local log_path=$1
  shift
  local status
  local tee_status
  local -a pipe_status

  set +e
  "$@" 2>&1 | tee "$log_path"
  pipe_status=("${PIPESTATUS[@]}")
  set -e

  status=${pipe_status[0]}
  tee_status=${pipe_status[1]}

  if [[ "$tee_status" -ne 0 ]]; then
    die "failed to write Raptor log: $log_path"
  fi

  return "$status"
}

prepare_canonical_artifacts() {
  local canonical_dir=$1
  local repo=$2
  local mode=$3
  local run_id=$4
  local run_attempt=$5
  local run_started_at=$6
  local object_prefix=$7
  local run_status=$8
  local run_exit_code=$9
  shift 9

  mkdir -p "$canonical_dir"
  python3 - "$canonical_dir" "$repo" "$mode" "$run_id" "$run_attempt" \
    "$run_started_at" "$object_prefix" "$run_status" "$run_exit_code" "$@" <<'PY'
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
from pathlib import Path

script_dir = os.environ.get("KITE_SCRIPT_DIR")
if script_dir:
    sys.path.insert(0, script_dir)

from kite_artifact_utils import redact_artifact_bytes, redact_tree, validate_findings_document

(
    canonical_dir,
    repo,
    mode,
    run_id,
    run_attempt,
    run_started_at,
    object_prefix,
    run_status,
    run_exit_code,
    target_repo_path,
    raptor_source_path,
    out_dir,
    json_report_path,
    markdown_report_path,
    sca_out_dir,
    sca_status,
) = sys.argv[1:]

canonical = Path(canonical_dir)
out = Path(out_dir)
sca = Path(sca_out_dir)


def existing(paths: list[Path]) -> Path | None:
    for path in paths:
        if path.is_file() and canonical not in path.parents:
            return path
    return None


def glob_existing(root: Path, pattern: str) -> list[Path]:
    if not root.is_dir():
        return []
    ignored = {".home", ".cache", ".tmp", ".config", ".state", "codeql_dbs", "_sources", "_source"}
    found: list[Path] = []
    for path in sorted(root.rglob(pattern)):
        if path.is_file() and not any(part in ignored for part in path.parts):
            found.append(path)
    return found


def synthetic_payload(name: str) -> bytes:
    if name == "findings.json":
        return (
            json.dumps(
                {
                    "findings": [],
                    "generated_by": "kite",
                    "mode": mode,
                    "status": run_status,
                    "reason": "No findings JSON source was produced.",
                },
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode()
    if name == "report.md":
        return (
            "# Kite RAPTOR run\n\n"
            f"- Mode: {mode}\n"
            f"- Status: {run_status}\n"
            "- Note: no Markdown report source was produced.\n"
        ).encode()
    if name == "sbom.cdx.json":
        return (
            json.dumps(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.5",
                    "version": 1,
                    "metadata": {"component": {"type": "application", "name": repo or "unknown"}},
                    "components": [],
                },
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode()
    if name == "findings.sarif":
        return (
            json.dumps(
                {
                    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                    "version": "2.1.0",
                    "runs": [],
                },
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode()
    raise ValueError(f"unknown canonical artifact: {name}")


candidates = {
    "findings.json": [
        Path(json_report_path),
        out / "findings.json",
        sca / "findings.json",
        *glob_existing(out, "findings*.json"),
        *glob_existing(sca, "findings*.json"),
    ],
    "report.md": [
        Path(markdown_report_path),
        out / "report.md",
        sca / "report.md",
        *glob_existing(out, "*report*.md"),
        *glob_existing(sca, "*report*.md"),
        *glob_existing(out, "*.md"),
        *glob_existing(sca, "*.md"),
    ],
    "sbom.cdx.json": [
        out / "sbom.cdx.json",
        sca / "sbom.cdx.json",
        *glob_existing(out, "*sbom*.json"),
        *glob_existing(sca, "*sbom*.json"),
        *glob_existing(out, "*.cdx.json"),
        *glob_existing(sca, "*.cdx.json"),
    ],
    "findings.sarif": [
        out / "findings.sarif",
        sca / "findings.sarif",
        *glob_existing(out, "*.sarif"),
        *glob_existing(sca, "*.sarif"),
    ],
}

objects: list[dict[str, object]] = []
for name in ("findings.json", "report.md", "sbom.cdx.json", "findings.sarif"):
    dest = canonical / name
    source = existing(candidates[name])
    generated = source is None
    if source is None:
        dest.write_bytes(synthetic_payload(name))
    else:
        shutil.copyfile(source, dest)
    data = dest.read_bytes()
    data, redaction_counts = redact_artifact_bytes(name, data)
    dest.write_bytes(data)
    schema_validation = None
    if name == "findings.json":
        try:
            findings_document = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            schema_validation = {
                "schema": "kite.findings.v1",
                "status": "invalid_json",
                "errors": [str(exc)],
            }
        else:
            schema_errors = validate_findings_document(findings_document)
            schema_validation = {
                "schema": "kite.findings.v1",
                "status": "valid" if not schema_errors else "non_conforming",
                "errors": schema_errors[:25],
                "error_count": len(schema_errors),
            }
    objects.append(
        {
            "name": name,
            "object": f"{object_prefix}{name}",
            "source_path": str(source) if source is not None else None,
            "generated": generated,
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "redactions": redaction_counts,
            "schema_validation": schema_validation,
        }
    )

manifest_path = canonical / "manifest.json"
manifest = {
    "schema_version": "kite.artifacts.v1",
    "repo": repo,
    "mode": mode,
    "github_run_id": run_id,
    "github_run_attempt": run_attempt,
    "run_started_at": run_started_at,
    "target_git_sha": os.environ.get("GITHUB_SHA") or None,
    "workflow": {
        "name": os.environ.get("GITHUB_WORKFLOW") or None,
        "ref": os.environ.get("GITHUB_WORKFLOW_REF") or None,
        "sha": os.environ.get("GITHUB_WORKFLOW_SHA") or None,
    },
    "models": {
        "primary": os.environ.get("KITE_CLAUDE_MODEL")
        or os.environ.get("ANTHROPIC_MODEL")
        or os.environ.get("CLAUDE_MODEL")
        or None,
        "second_opinion": os.environ.get("OPENAI_SECOND_OPINION_MODEL")
        or os.environ.get("KITE_SECOND_OPINION_MODEL")
        or None,
    },
    "prefix": object_prefix,
    "status": run_status,
    "exit_code": int(run_exit_code),
    "source_paths": {
        "target_repo_path": target_repo_path,
        "raptor_source_path": raptor_source_path,
        "raptor_out_dir": out_dir,
        "sca_out_dir": sca_out_dir,
    },
    "sca": {
        "status": sca_status,
    },
    "objects": objects,
    "manifest_object": f"{object_prefix}manifest.json",
}
manifest = redact_tree(manifest)
manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
PY
}

upload_canonical_artifacts() {
  local bucket=$1
  local object_prefix=$2
  local canonical_dir=$3

  python3 - "$bucket" "$object_prefix" "$canonical_dir" <<'PY'
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

bucket, object_prefix, canonical_dir = sys.argv[1:]
canonical = Path(canonical_dir)
names = ("findings.json", "report.md", "sbom.cdx.json", "findings.sarif", "manifest.json")


def access_token() -> str:
    env_token = os.environ.get("GOOGLE_OAUTH_ACCESS_TOKEN")
    if env_token:
        return env_token
    req = urllib.request.Request(
        "http://metadata.google.internal/computeMetadata/v1/instance/"
        "service-accounts/default/token",
        headers={"Metadata-Flavor": "Google"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        payload = json.loads(resp.read().decode())
    token = str(payload.get("access_token", ""))
    if not token:
        raise RuntimeError("metadata token response did not include access_token")
    return token


token = access_token()
for name in names:
    path = canonical / name
    data = path.read_bytes()
    obj = f"{object_prefix}{name}"
    url = (
        "https://storage.googleapis.com/upload/storage/v1/b/"
        f"{urllib.parse.quote(bucket, safe='')}/o?uploadType=media&name="
        f"{urllib.parse.quote(obj, safe='')}&ifGenerationMatch=0"
    )
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/octet-stream",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            resp.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")
        raise SystemExit(f"upload failed for gs://{bucket}/{obj}: HTTP {exc.code}: {detail}")
    print(f"Uploaded gs://{bucket}/{obj}")
PY
}

run_openai_second_opinion() {
  local artifact_path=$1
  local raw_path=$2
  local prompt_path=$3
  local status_path=$4

  mkdir -p "$(dirname "$artifact_path")"
  if [[ "$second_opinion_enabled" != true ]]; then
    python3 - "$artifact_path" <<'PY'
import json
import os
import sys
from pathlib import Path

script_dir = os.environ.get("KITE_SCRIPT_DIR")
if script_dir:
    sys.path.insert(0, script_dir)
from kite_artifact_utils import redact_tree

Path(sys.argv[1]).write_text(json.dumps(redact_tree({"status": "skipped"}), indent=2) + "\n")
PY
    return 0
  fi

  cat >"$prompt_path" <<EOF
You are running Trail of Bits second-opinion methodology as a non-gating shadow review.

Review the repository at:
$target_repo_path

Use the staged Kite/RAPTOR findings at:
$findings_dir

Read the selected-skill manifest at:
$agent_context_dir/selected-skills.json

If selected-skills.json has mitre_atlas.required=true, use the local MITRE ATLAS
data file recorded in mitre_atlas.absolute_data_file when present. For AI, ML,
LLM, and agentic-system findings, map applicable findings to AML tactic and
technique IDs only when the ATLAS data supports the mapping. If no precise
mapping applies, report "ATLAS mapping: not assigned" and explain why. Do not
invent AML IDs.

Mode: $raptor_mode
Primary RAPTOR status: $status

Return concise JSON with: status, model, material_disagreements, missed_risks,
false_positive_concerns, and recommended_follow_up. Do not modify files.
EOF

  if ! command -v codex >/dev/null 2>&1; then
    python3 - "$artifact_path" "$second_opinion_model" <<'PY'
import json
import os
import sys
from pathlib import Path

script_dir = os.environ.get("KITE_SCRIPT_DIR")
if script_dir:
    sys.path.insert(0, script_dir)
from kite_artifact_utils import redact_tree

Path(sys.argv[1]).write_text(
    json.dumps(
        redact_tree(
        {
            "status": "unavailable",
            "model": sys.argv[2],
            "error": "codex CLI not found on runner",
        }
        ),
        indent=2,
        sort_keys=True,
    )
    + "\n"
)
PY
    return 0
  fi

  local codex_status=success
  local codex_exit=0
  local codex_cmd=(codex exec --sandbox read-only --ephemeral)
  if [[ -n "$second_opinion_model" ]]; then
    codex_cmd+=(-o "model=$second_opinion_model")
  fi
  local -a codex_exec=("${codex_cmd[@]}" -)
  if [[ "$second_opinion_timeout_seconds" != 0 ]]; then
    if command -v timeout >/dev/null; then
      codex_exec=(timeout "$second_opinion_timeout_seconds" "${codex_cmd[@]}" -)
    else
      printf 'warning: timeout command not available; OPENAI_SECOND_OPINION_TIMEOUT_SECONDS=%s not enforced\n' \
        "$second_opinion_timeout_seconds" >&2
    fi
  fi
  if "${codex_exec[@]}" <"$prompt_path" >"$raw_path" 2>"$status_path"; then
    codex_status=success
  else
    codex_exit=$?
    codex_status=failure
  fi
  python3 - "$artifact_path" "$raw_path" "$status_path" "$second_opinion_model" \
    "$codex_status" "$codex_exit" <<'PY'
import json
import os
import sys
from pathlib import Path

script_dir = os.environ.get("KITE_SCRIPT_DIR")
if script_dir:
    sys.path.insert(0, script_dir)
from kite_artifact_utils import redact_tree

artifact, raw, stderr, model, status, exit_code = sys.argv[1:]
raw_text = Path(raw).read_text(errors="replace") if Path(raw).is_file() else ""
err_text = Path(stderr).read_text(errors="replace") if Path(stderr).is_file() else ""
Path(artifact).write_text(
    json.dumps(
        redact_tree(
        {
            "status": status,
            "model": model,
            "exit_code": int(exit_code),
            "raw_output_path": raw,
            "stderr_path": stderr,
            "raw_output_preview": raw_text[:4000],
            "stderr_preview": err_text[:2000],
        }
        ),
        indent=2,
        sort_keys=True,
    )
    + "\n"
)
PY
}

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null && pwd -P)
repo_root=$(cd "$script_dir/../.." >/dev/null && pwd -P)
export KITE_SCRIPT_DIR="$script_dir"

target_repo_path=${TARGET_REPO_PATH:-${GITHUB_WORKSPACE:-$PWD}}
raptor_source_path=${RAPTOR_SOURCE_PATH:-$repo_root}
raptor_image=${RAPTOR_IMAGE:-}
case "$raptor_image" in
  local | source | none | null)
    raptor_image=
    ;;
esac

default_temp=${RUNNER_TEMP:-${TMPDIR:-/tmp}}
default_out_dir="${default_temp%/}/raptor-out"
out_dir=${RAPTOR_OUT_DIR:-$default_out_dir}
agent_context_dir=${RAPTOR_AGENT_CONTEXT_DIR:-/tmp/gh-aw/agent/raptor-review}

target_repo_path=$(resolve_existing_dir "$target_repo_path")
raptor_source_path=$(resolve_existing_dir "$raptor_source_path")
[[ -f "$raptor_source_path/raptor.py" ]] || die "Raptor source path lacks raptor.py: $raptor_source_path"

out_dir=$(lexical_abs_path "$out_dir")
if path_is_within "$out_dir" "$target_repo_path"; then
  die "RAPTOR_OUT_DIR must not be inside TARGET_REPO_PATH; refusing to write reports under $target_repo_path"
fi

nearest_out_parent=$(nearest_existing_dir "$out_dir")
if path_is_within "$nearest_out_parent" "$target_repo_path"; then
  die "RAPTOR_OUT_DIR resolves under TARGET_REPO_PATH; refusing to write reports under $target_repo_path"
fi

mkdir -p "$out_dir"
out_dir=$(resolve_existing_dir "$out_dir")

if path_is_within "$out_dir" "$target_repo_path"; then
  die "RAPTOR_OUT_DIR resolved inside TARGET_REPO_PATH; refusing to write reports under $target_repo_path"
fi

second_opinion_enabled=false
if bool_requested OPENAI_SECOND_OPINION_ENABLED "${OPENAI_SECOND_OPINION_ENABLED:-false}"; then
  second_opinion_enabled=true
fi
second_opinion_model=${OPENAI_SECOND_OPINION_MODEL:-}
second_opinion_timeout_seconds=${OPENAI_SECOND_OPINION_TIMEOUT_SECONDS:-600}
require_nonnegative_integer OPENAI_SECOND_OPINION_TIMEOUT_SECONDS "$second_opinion_timeout_seconds"
second_opinion_out_dir=${OPENAI_SECOND_OPINION_OUT_DIR:-$out_dir/second-opinion/openai}
second_opinion_out_dir=$(lexical_abs_path "$second_opinion_out_dir")
second_opinion_artifact_path=${OPENAI_SECOND_OPINION_ARTIFACT_PATH:-$second_opinion_out_dir/openai-second-opinion.json}
second_opinion_artifact_path=$(lexical_abs_path "$second_opinion_artifact_path")
second_opinion_artifact_parent=$(dirname "$second_opinion_artifact_path")

for candidate in "$second_opinion_out_dir" "$second_opinion_artifact_parent"; do
  nearest_candidate_parent=$(nearest_existing_dir "$candidate")
  if path_is_within "$nearest_candidate_parent" "$target_repo_path"; then
    die "OpenAI second-opinion output must not be inside TARGET_REPO_PATH: $candidate"
  fi
done
if [[ "$second_opinion_enabled" == true && -z "${OPENAI_API_KEY:-}" ]]; then
  die "OPENAI_API_KEY is required when OPENAI_SECOND_OPINION_ENABLED is true"
fi
mkdir -p "$second_opinion_out_dir" "$second_opinion_artifact_parent"

home_dir="$out_dir/.home"
cache_dir="$out_dir/.cache"
config_dir="$out_dir/.config"
state_dir="$out_dir/.state"
tmp_dir="$out_dir/.tmp"
mkdir -p "$home_dir" "$cache_dir" "$config_dir" "$state_dir" "$tmp_dir"
# Pre-create Semgrep's data dir BEFORE the container starts. RAPTOR installs its
# Landlock ruleset by opening each writable path at sandbox-init, so a directory
# that Semgrep tries to create at runtime gets no rule and is denied (kite#46: 22
# denials writing $config_dir/.semgrep). Creating it on the host means it already
# exists (visible in the container via the $out_dir mount) when the sandbox is set
# up. The scan_quality fail-loud check below surfaces any residual denials.
mkdir -p "$config_dir/.semgrep"
mkdir -p "$agent_context_dir"

log_path="$out_dir/raptor-agentic-review.log"
summary_path="$out_dir/raptor-agentic-review-summary.txt"
agent_summary_path="$agent_context_dir/raptor-summary.json"
json_report_path="$out_dir/raptor_agentic_report.json"
markdown_report_path="$out_dir/agentic-report.md"

extra_args=("$@")
reject_control_arg_overrides "${extra_args[@]}"

codeql_enabled=false
if enable_codeql_requested "${ENABLE_CODEQL:-false}"; then
  codeql_enabled=true
fi

codeql_args=()
if ! has_explicit_codeql_arg "${extra_args[@]}"; then
  if [[ "$codeql_enabled" == true ]]; then
    codeql_args+=(--codeql)
  else
    codeql_args+=(--no-codeql)
  fi
fi

raptor_mode=${RAPTOR_MODE:-pr_review}
case "$raptor_mode" in
  pr_review | baseline) ;;
  *) die "RAPTOR_MODE must be pr_review or baseline" ;;
esac

max_findings=${MAX_FINDINGS:-10}
case "$max_findings" in
  '' | *[!0-9]*) die "MAX_FINDINGS must be a positive integer" ;;
esac
# Reject zero explicitly: in baseline mode max_findings flows to `--max-findings 0`,
# which silently suppresses the entire review rather than bounding it. `*[1-9]*`
# requires at least one non-zero digit, so "0"/"00" are rejected while "10" passes.
case "$max_findings" in
  *[1-9]*) ;;
  *) die "MAX_FINDINGS must be a positive integer (0 would disable the baseline review)" ;;
esac

raptor_timeout_seconds=${RAPTOR_TIMEOUT_SECONDS:-7200}
require_nonnegative_integer RAPTOR_TIMEOUT_SECONDS "$raptor_timeout_seconds"

# Baseline scans the whole repository: run the understand prepass and bound the
# finding count. PR review keeps the diff-focused default and adds no mode args.
mode_args=()
if [[ "$raptor_mode" == baseline ]]; then
  mode_args+=(--understand --max-findings "$max_findings")
fi

# Optional dry-run: print the resolved RAPTOR and SCA commands, then exit without
# executing. Tests assert command construction through this seam, and an operator can
# preview exactly what a privileged run will invoke. Commands pass credentials to the
# container by env-var NAME (docker --env NAME), never by value, so the printed plan
# never contains secret material.
dry_run=false
case "${RAPTOR_DRY_RUN:-}" in
  1 | true | yes) dry_run=true ;;
esac

run_started_at=${KITE_RUN_STARTED_AT:-$(date -u '+%Y%m%dT%H%M%SZ')}
case "$run_started_at" in
  [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]T[0-9][0-9][0-9][0-9][0-9][0-9]Z)
    ;;
  *)
    die "KITE_RUN_STARTED_AT must be formatted as YYYYMMDDTHHMMSSZ"
    ;;
esac
run_year=${run_started_at:0:4}
run_month=${run_started_at:4:2}
run_day=${run_started_at:6:2}
github_run_id=${GITHUB_RUN_ID:-local}
github_run_attempt=${GITHUB_RUN_ATTEMPT:-0}
github_repository=${GITHUB_REPOSITORY:-local/unknown}
github_sha=${GITHUB_SHA:-local}
repo_slug=$(printf '%s' "$github_repository" | tr '[:upper:]/' '[:lower:]-' | tr -c 'a-z0-9._-' '-')
sha_slug=$(printf '%s' "$github_sha" | tr -c 'A-Za-z0-9._-' '-')
artifact_bucket=${KITE_ARTIFACT_BUCKET:-}
artifact_upload_required=false
if bool_requested KITE_REQUIRE_ARTIFACT_UPLOAD "${KITE_REQUIRE_ARTIFACT_UPLOAD:-true}"; then
  artifact_upload_required=true
fi
artifact_upload_dry_run=false
if bool_requested KITE_ARTIFACT_DRY_RUN "${KITE_ARTIFACT_DRY_RUN:-false}"; then
  artifact_upload_dry_run=true
fi
if [[ "$dry_run" == false && "$artifact_upload_required" == true && -z "$artifact_bucket" ]]; then
  die "KITE_ARTIFACT_BUCKET is required when KITE_REQUIRE_ARTIFACT_UPLOAD is true"
fi
artifact_prefix="repo=${repo_slug}/sha=${sha_slug}/"
artifact_prefix+="year=${run_year}/month=${run_month}/day=${run_day}/"
artifact_prefix+="run_started_at=${run_started_at}/github_run_id=${github_run_id}/"
artifact_prefix+="attempt=${github_run_attempt}/mode=${raptor_mode}/"
canonical_artifact_dir="$out_dir/artifacts"

export GIT_TERMINAL_PROMPT=0
export HOME="$home_dir"
# SCA's agent.py is invoked directly (not via the libexec dispatcher), so set the
# trust marker that the dispatcher would otherwise set; harmless for the agentic run.
export _RAPTOR_TRUSTED=1
export PYTHONDONTWRITEBYTECODE=1
export PYTHONUNBUFFERED=1
export RAPTOR_OUT_DIR="$out_dir"
export TMPDIR="$tmp_dir"
export XDG_CACHE_HOME="$cache_dir"
export XDG_CONFIG_HOME="$config_dir"
export XDG_STATE_HOME="$state_dir"
# Pin Semgrep's settings file inside the pre-created, Landlock-writable .semgrep
# dir so its version-check and scan-config writes land in the allowlist instead of
# a path created at runtime (kite#46). SEMGREP_SETTINGS_FILE is the documented
# override; XDG_CONFIG_HOME already routes the rest of Semgrep's state under it.
export SEMGREP_SETTINGS_FILE="$config_dir/.semgrep/settings.yml"
if [[ -z "${ANTHROPIC_MODEL:-}" && -n "${CLAUDE_MODEL:-}" ]]; then
  export ANTHROPIC_MODEL="$CLAUDE_MODEL"
fi
if [[ -z "${CLAUDE_MODEL:-}" && -n "${ANTHROPIC_MODEL:-}" ]]; then
  export CLAUDE_MODEL="$ANTHROPIC_MODEL"
fi
export OPENAI_SECOND_OPINION_ENABLED="$second_opinion_enabled"
export OPENAI_SECOND_OPINION_OUT_DIR="$second_opinion_out_dir"
export OPENAI_SECOND_OPINION_ARTIFACT_PATH="$second_opinion_artifact_path"
export OPENAI_SECOND_OPINION_TIMEOUT_SECONDS="$second_opinion_timeout_seconds"

runner="local"
cmd=()

if [[ -n "$raptor_image" ]]; then
  command -v docker >/dev/null || die "RAPTOR_IMAGE is set but docker is not available"

  # Ensure the nested bind-mount target exists inside the (read-write, runner-owned)
  # source tree so docker does not have to create it under the parent mount.
  mkdir -p "$raptor_source_path/out"

  runner="docker"
  # Mount the output dir at RAPTOR's own REPO_ROOT/out. RAPTOR's logger writes to
  # BASE_OUT_DIR (= REPO_ROOT/out) unconditionally, and its sandbox derives the
  # Landlock-writable allowlist from the run's output dir. Stock RAPTOR keeps those
  # the same path; pointing the output elsewhere makes every sandboxed subprocess's
  # log write land outside the allowlist (observed: 24 Landlock denials, semgrep
  # produced 0 findings). Aligning container_out with REPO_ROOT/out restores the
  # invariant. Safe now that the source mount is read-write and runner-owned.
  container_out=/workspaces/raptor/out
  container_home="$container_out/.home"
  container_tmp="$container_out/.tmp"
  container_cache="$container_out/.cache"
  container_config="$container_out/.config"
  container_state="$container_out/.state"
  container_second_opinion_out_dir="$container_out/second-opinion/openai"
  container_second_opinion_artifact_path="$container_second_opinion_out_dir/openai-second-opinion.json"

  docker_args=(
    run
    --rm
    --privileged
    --user "$(id -u):$(id -g)"
    --workdir /workspaces/raptor
    # RAPTOR source is mounted read-write: at import RaptorConfig.ensure_directories()
    # unconditionally mkdirs out/, out/jobs, out/logs, and codeql_dbs/ under its own
    # REPO_ROOT (all gitignored, absent after a fresh clone), so a read-only source
    # bind aborts before argparse ever sees --out. The source is ephemeral (fresh
    # clone per boot, VM self-deletes after one job) and the container is already
    # --privileged for rr, so an RO source bind is integrity hygiene, not a boundary.
    # Reports still land in the separate --out mount below; the untrusted analysis
    # target stays read-only.
    --volume "$raptor_source_path:/workspaces/raptor"
    --volume "$target_repo_path:/workspaces/target:ro"
    --volume "$out_dir:$container_out"
    --env GIT_TERMINAL_PROMPT=0
    --env HOME="$container_home"
    --env PYTHONDONTWRITEBYTECODE=1
    --env PYTHONUNBUFFERED=1
    --env RAPTOR_OUT_DIR="$container_out"
    --env TMPDIR="$container_tmp"
    --env XDG_CACHE_HOME="$container_cache"
    --env XDG_CONFIG_HOME="$container_config"
    --env XDG_STATE_HOME="$container_state"
    --env SEMGREP_SETTINGS_FILE="$container_config/.semgrep/settings.yml"
    --env OPENAI_SECOND_OPINION_OUT_DIR="$container_second_opinion_out_dir"
    --env OPENAI_SECOND_OPINION_ARTIFACT_PATH="$container_second_opinion_artifact_path"
  )
  for name in \
    ANTHROPIC_API_KEY \
    ANTHROPIC_MODEL \
    CLAUDE_MODEL \
    OPENAI_API_KEY \
    OPENAI_SECOND_OPINION_ENABLED \
    OPENAI_SECOND_OPINION_MODEL \
    GEMINI_API_KEY \
    GOOGLE_API_KEY \
    NVD_API_KEY \
    LLM_PROVIDER \
    GITHUB_TOKEN \
    CODEQL_CLI \
    _RAPTOR_TRUSTED
  do
    if [[ -n "${!name:-}" ]]; then
      docker_args+=(--env "$name")
    fi
  done

  cmd=(
    docker
    "${docker_args[@]}"
    "$raptor_image"
    python3
    /workspaces/raptor/raptor.py
    agentic
    --repo
    /workspaces/target
    --out
    "$container_out"
    "${codeql_args[@]}"
    "${mode_args[@]}"
    "${extra_args[@]}"
  )
else
  cmd=(
    python3
    "$raptor_source_path/raptor.py"
    agentic
    --repo
    "$target_repo_path"
    --out
    "$out_dir"
    "${codeql_args[@]}"
    "${mode_args[@]}"
    "${extra_args[@]}"
  )
fi

printf 'Raptor runner: %s\n' "$runner"
printf 'Target repo: %s\n' "$target_repo_path"
printf 'Raptor source: %s\n' "$raptor_source_path"
printf 'Raptor output: %s\n' "$out_dir"
printf 'Raptor log: %s\n' "$log_path"
printf 'Raptor run started at: %s\n' "$run_started_at"
printf 'Raptor artifact prefix: %s\n' "$artifact_prefix"
printf 'Raptor timeout seconds: %s\n' "$raptor_timeout_seconds"
printf 'OpenAI second-opinion shadow: %s\n' "$second_opinion_enabled"
if [[ "$second_opinion_enabled" == true ]]; then
  printf 'OpenAI second-opinion output: %s\n' "$second_opinion_out_dir"
  printf 'OpenAI second-opinion artifact: %s\n' "$second_opinion_artifact_path"
  printf 'OpenAI second-opinion timeout seconds: %s\n' "$second_opinion_timeout_seconds"
  if [[ -n "$second_opinion_model" ]]; then
    printf 'OpenAI second-opinion model: %s\n' "$second_opinion_model"
  fi
fi

# Stage the CodeQL query packs baked into the golden host image into the per-run
# CodeQL cache so in-container analysis resolves them with zero registry calls.
# CodeQL reads packs from $HOME/.codeql/packages; HOME is $home_dir locally and
# $container_home (= $home_dir through the $out_dir mount) in the container, so one
# host-side copy serves both runners. The registry download 504'd during the baseline
# (kite#46: codeql/python-queries resolved 0 queries), so baking removes the
# analysis-time network dependency. Best-effort: a missing or unreadable bake warns
# rather than aborting, and the scan_quality check below fails loud if CodeQL still
# runs no queries.
if [[ "$dry_run" == false && "$codeql_enabled" == true ]]; then
  baked_codeql_packs=/opt/codeql-packs/.codeql/packages
  if [[ -d "$baked_codeql_packs" ]] && compgen -G "$baked_codeql_packs/*" >/dev/null; then
    mkdir -p "$home_dir/.codeql/packages"
    if cp -a "$baked_codeql_packs/." "$home_dir/.codeql/packages/"; then
      printf 'Staged baked CodeQL packs from %s into %s\n' \
        "$baked_codeql_packs" "$home_dir/.codeql/packages"
    else
      printf 'warning: failed to stage baked CodeQL packs from %s; CodeQL may attempt a registry download\n' \
        "$baked_codeql_packs" >&2
    fi
  else
    printf 'warning: CodeQL enabled but no baked packs at %s; CodeQL may attempt a registry download\n' \
      "$baked_codeql_packs" >&2
  fi
fi

exit_code=0
raptor_phase_start=$(date +%s)
raptor_exec=("${cmd[@]}")
if [[ "$raptor_timeout_seconds" != 0 ]]; then
  if [[ "$dry_run" == true ]] || command -v timeout >/dev/null; then
    raptor_exec=(timeout "$raptor_timeout_seconds" "${cmd[@]}")
  else
    printf 'warning: timeout command not available; RAPTOR_TIMEOUT_SECONDS=%s not enforced\n' \
      "$raptor_timeout_seconds" >&2
  fi
fi
if [[ "$dry_run" == true ]]; then
  printf 'RAPTOR_PLAN: %s\n' "${raptor_exec[*]}"
elif run_and_log "$log_path" "${raptor_exec[@]}"; then
  exit_code=0
else
  exit_code=$?
fi
raptor_duration=$(phase_seconds "$raptor_phase_start")
print_phase_timing raptor "$raptor_duration" "$([[ "$exit_code" -eq 0 ]] && printf success || printf failure)"

status=success
if [[ "$exit_code" -ne 0 ]]; then
  status=failure
fi

# Baseline mode adds a software-composition-analysis pass. SCA's agent.py writes
# findings.json + SARIF + report.md into its --out and self-restricts egress to
# RAPTOR's SCA_ALLOWED_HOSTS (it does not call the LLM). PR review skips it.
#
# Online enrichment (OSV / NVD / registry metadata) is gated on NVD_API_KEY: NVD's
# keyless quota is 5 requests / 30s and SCA enriches every dependency, so without a
# key the aggregate enrichment runs unbounded and wedges the whole job (observed in
# E2E). With no key SCA runs --offline: deterministic mechanical analysis
# (manifest/lockfile inventory, install-hook review) with online feeds skipped
# gracefully. Set the NVD_API_KEY secret to enable full online enrichment — the key
# lifts the quota so the pass completes in bounded time.
sca_status=skipped
sca_exit_code=0
sca_out_dir="$out_dir/sca"
sca_log_path="$out_dir/raptor-sca.log"

# Wall-clock bound so no enrichment path can hang the job. 0 disables the limit
# (timeout(1) semantics); the bound applies even with a key as a backstop.
sca_timeout_seconds=${SCA_TIMEOUT_SECONDS:-1800}
require_nonnegative_integer SCA_TIMEOUT_SECONDS "$sca_timeout_seconds"

if [[ "$raptor_mode" == baseline ]]; then
  mkdir -p "$sca_out_dir"
  sca_mode_args=()
  if [[ -z "${NVD_API_KEY:-}" ]]; then
    sca_mode_args+=(--offline)
  fi
  if [[ -n "$raptor_image" ]]; then
    sca_cmd=(
      docker
      "${docker_args[@]}"
      "$raptor_image"
      python3
      /workspaces/raptor/packages/sca/agent.py
      --repo
      /workspaces/target
      --out
      "$container_out/sca"
      "${sca_mode_args[@]}"
    )
  else
    sca_cmd=(
      python3
      "$raptor_source_path/packages/sca/agent.py"
      --repo
      "$target_repo_path"
      --out
      "$sca_out_dir"
      "${sca_mode_args[@]}"
    )
  fi
  sca_exec=("${sca_cmd[@]}")
  if [[ "$sca_timeout_seconds" != 0 ]]; then
    if [[ "$dry_run" == true ]] || command -v timeout >/dev/null; then
      sca_exec=(timeout "$sca_timeout_seconds" "${sca_cmd[@]}")
    else
      printf 'warning: timeout command not available; SCA_TIMEOUT_SECONDS=%s not enforced\n' \
        "$sca_timeout_seconds" >&2
    fi
  fi
  printf 'Raptor SCA: software composition analysis -> %s\n' "$sca_out_dir"
  sca_phase_start=$(date +%s)
  if [[ "$dry_run" == true ]]; then
    printf 'SCA_PLAN: %s\n' "${sca_exec[*]}"
    sca_status=dry-run
  elif run_and_log "$sca_log_path" "${sca_exec[@]}"; then
    sca_status=success
  else
    sca_exit_code=$?
    sca_status=failure
  fi
  sca_duration=$(phase_seconds "$sca_phase_start")
  print_phase_timing sca "$sca_duration" "$sca_status"
else
  sca_duration=0
  print_phase_timing sca 0 skipped
fi

second_opinion_raw_path="$second_opinion_out_dir/openai-second-opinion.raw.txt"
second_opinion_prompt_path="$second_opinion_out_dir/openai-second-opinion.prompt.txt"
second_opinion_stderr_path="$second_opinion_out_dir/openai-second-opinion.stderr.txt"
if [[ "$dry_run" == true ]]; then
  if [[ "$second_opinion_enabled" == true ]]; then
    if [[ "$second_opinion_timeout_seconds" == 0 ]]; then
      printf 'SECOND_OPINION_PLAN: codex exec --sandbox read-only --ephemeral -o model=%s\n' \
        "${second_opinion_model:-default}"
    else
      printf 'SECOND_OPINION_PLAN: timeout %s codex exec --sandbox read-only --ephemeral -o model=%s\n' \
        "$second_opinion_timeout_seconds" "${second_opinion_model:-default}"
    fi
  fi
fi

if [[ "$dry_run" == true ]]; then
  if [[ -n "$artifact_bucket" ]]; then
    for name in findings.json report.md sbom.cdx.json findings.sarif manifest.json; do
      printf 'ARTIFACT_PLAN: gs://%s/%s%s\n' "$artifact_bucket" "$artifact_prefix" "$name"
    done
  fi
  exit 0
fi

# Stage human-readable findings into the agent context dir. The awf agent sandbox
# can read the context dir under /tmp/gh-aw but NOT $out_dir or the SCA out dir, so
# copy report/SARIF/findings files (pruning large scratch, CodeQL DB, and source
# caches) where the agent can actually open them.
findings_dir="$agent_context_dir/findings"
mkdir -p "$findings_dir"
stage_findings() {
  local src=$1
  local label=$2

  [[ -d "$src" ]] || return 0
  find "$src" \
    \( -path '*/.home' -o -path '*/.cache' -o -path '*/.tmp' \
    -o -path '*/.config' -o -path '*/.state' -o -path '*/codeql_dbs' \
    -o -path '*/_sources' -o -path '*/_source' \) -prune -o \
    -type f \( -name '*.md' -o -name '*.sarif' -o -name 'findings*.json' \
    -o -name '*report*.json' -o -name '*summary*.json' \
    -o -name '*second-opinion*.json' -o -name '*second_opinion*.json' \) \
    -size -2M -print0 2>/dev/null |
    while IFS= read -r -d '' found; do
      cp -f "$found" "$findings_dir/${label}-$(basename "$found")" 2>/dev/null || true
    done
}
stage_findings "$out_dir" raptor
stage_findings "$sca_out_dir" sca

second_opinion_phase_start=$(date +%s)
run_openai_second_opinion \
  "$second_opinion_artifact_path" \
  "$second_opinion_raw_path" \
  "$second_opinion_prompt_path" \
  "$second_opinion_stderr_path"
second_opinion_duration=$(phase_seconds "$second_opinion_phase_start")
if [[ "$second_opinion_enabled" == true ]]; then
  print_phase_timing openai_second_opinion "$second_opinion_duration" enabled
else
  print_phase_timing openai_second_opinion "$second_opinion_duration" skipped
fi
stage_findings "$second_opinion_out_dir" openai-second-opinion

artifact_upload_status=skipped
artifact_upload_exit_code=0
artifact_upload_duration=0
if [[ -n "$artifact_bucket" ]]; then
  artifact_phase_start=$(date +%s)
  if ! prepare_canonical_artifacts "$canonical_artifact_dir" \
    "${GITHUB_REPOSITORY:-}" "$raptor_mode" "$github_run_id" "$github_run_attempt" \
    "$run_started_at" "$artifact_prefix" "$status" "$exit_code" \
    "$target_repo_path" "$raptor_source_path" "$out_dir" "$json_report_path" \
    "$markdown_report_path" "$sca_out_dir" "$sca_status"; then
    artifact_upload_status=failure
    artifact_upload_exit_code=1
  elif [[ "$artifact_upload_dry_run" == true ]]; then
    python3 - "$artifact_bucket" "$artifact_prefix" "$canonical_artifact_dir" <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path

bucket, prefix, canonical_dir = sys.argv[1:]
manifest = json.loads((Path(canonical_dir) / "manifest.json").read_text())
for entry in manifest["objects"]:
    print(
        "ARTIFACT_PLAN: "
        f"gs://{bucket}/{prefix}{entry['name']} "
        f"bytes={entry['bytes']} sha256={entry['sha256']}"
    )
print(f"ARTIFACT_PLAN: gs://{bucket}/{prefix}manifest.json")
PY
    artifact_upload_status=dry-run
  elif upload_canonical_artifacts "$artifact_bucket" "$artifact_prefix" "$canonical_artifact_dir"; then
    artifact_upload_status=success
  else
    artifact_upload_status=failure
    artifact_upload_exit_code=1
  fi
  artifact_upload_duration=$(phase_seconds "$artifact_phase_start")
  print_phase_timing artifact_upload "$artifact_upload_duration" "$artifact_upload_status"
else
  print_phase_timing artifact_upload 0 skipped
fi

{
  printf 'status=%s\n' "$status"
  printf 'exit_code=%s\n' "$exit_code"
  printf 'runner=%s\n' "$runner"
  printf 'raptor_mode=%s\n' "$raptor_mode"
  printf 'target_repo_path=%s\n' "$target_repo_path"
  printf 'raptor_source_path=%s\n' "$raptor_source_path"
  printf 'raptor_out_dir=%s\n' "$out_dir"
  printf 'log_path=%s\n' "$log_path"
  printf 'json_report_path=%s\n' "$json_report_path"
  printf 'markdown_report_path=%s\n' "$markdown_report_path"
  printf 'agent_summary_path=%s\n' "$agent_summary_path"
  printf 'sca_status=%s\n' "$sca_status"
  printf 'sca_exit_code=%s\n' "$sca_exit_code"
  printf 'sca_out_dir=%s\n' "$sca_out_dir"
  printf 'sca_log_path=%s\n' "$sca_log_path"
  printf 'run_started_at=%s\n' "$run_started_at"
  printf 'artifact_bucket=%s\n' "$artifact_bucket"
  printf 'artifact_prefix=%s\n' "$artifact_prefix"
  printf 'artifact_upload_required=%s\n' "$artifact_upload_required"
  printf 'artifact_upload_status=%s\n' "$artifact_upload_status"
  printf 'artifact_upload_exit_code=%s\n' "$artifact_upload_exit_code"
  printf 'artifact_manifest_path=%s\n' "$canonical_artifact_dir/manifest.json"
  printf 'openai_second_opinion_enabled=%s\n' "$second_opinion_enabled"
  printf 'openai_second_opinion_model=%s\n' "$second_opinion_model"
  printf 'openai_second_opinion_out_dir=%s\n' "$second_opinion_out_dir"
  printf 'openai_second_opinion_artifact_path=%s\n' "$second_opinion_artifact_path"
  printf 'openai_second_opinion_timeout_seconds=%s\n' "$second_opinion_timeout_seconds"
  printf 'raptor_timeout_seconds=%s\n' "$raptor_timeout_seconds"
} >"$summary_path"

python3 - "$agent_summary_path" "$status" "$exit_code" "$runner" \
  "$target_repo_path" "$raptor_source_path" "$out_dir" "$log_path" \
  "$summary_path" "$json_report_path" "$markdown_report_path" \
  "$raptor_mode" "$sca_status" "$sca_exit_code" "$sca_out_dir" "$sca_log_path" \
  "$run_started_at" "$artifact_bucket" "$artifact_prefix" "$artifact_upload_required" \
  "$artifact_upload_status" "$artifact_upload_exit_code" "$canonical_artifact_dir/manifest.json" \
  "$raptor_duration" "$sca_duration" "$artifact_upload_duration" \
  "$findings_dir" "$codeql_enabled" "$second_opinion_enabled" "$second_opinion_model" \
  "$second_opinion_out_dir" "$second_opinion_artifact_path" \
  "$second_opinion_timeout_seconds" "$raptor_timeout_seconds" "$max_findings" <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path

(
    out_path,
    status,
    exit_code,
    runner,
    target_repo_path,
    raptor_source_path,
    out_dir,
    log_path,
    text_summary_path,
    json_report_path,
    markdown_report_path,
    raptor_mode,
    sca_status,
    sca_exit_code,
    sca_out_dir,
    sca_log_path,
    run_started_at,
    artifact_bucket,
    artifact_prefix,
    artifact_upload_required,
    artifact_upload_status,
    artifact_upload_exit_code,
    artifact_manifest_path,
    raptor_duration,
    sca_duration,
    artifact_upload_duration,
    findings_dir,
    codeql_enabled,
    second_opinion_enabled,
    second_opinion_model,
    second_opinion_out_dir,
    second_opinion_artifact_path,
    second_opinion_timeout_seconds,
    raptor_timeout_seconds,
    max_findings,
) = sys.argv[1:]

paths = {
    "raptor_out_dir": out_dir,
    "log_path": log_path,
    "text_summary_path": text_summary_path,
    "json_report_path": json_report_path,
    "markdown_report_path": markdown_report_path,
    "sca_out_dir": sca_out_dir,
    "sca_log_path": sca_log_path,
    "artifact_manifest_path": artifact_manifest_path,
    "openai_second_opinion_out_dir": second_opinion_out_dir,
    "openai_second_opinion_artifact_path": second_opinion_artifact_path,
}


def _read_json(path):
    """Best-effort JSON load; returns None on any read/parse failure."""
    if path is None:
        return None
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return None


def _find(directory, pattern):
    """First file in `directory` matching `pattern` (sorted), or None."""
    for found in sorted(Path(directory).glob(pattern)):
        return found
    return None


def _codeql_queries_executed(report):
    """Total CodeQL queries executed; tolerant of upstream report-shape drift."""
    if not isinstance(report, dict):
        return None
    if isinstance(report.get("queries_executed"), int):
        return report["queries_executed"]
    analyses = report.get("analyses_completed")
    if not isinstance(analyses, dict):
        return None
    total, seen = 0, False
    for entry in analyses.values():
        count = entry.get("queries_executed") if isinstance(entry, dict) else None
        if isinstance(count, int):
            total, seen = total + count, True
    return total if seen else None


def _denial_count(summary):
    """RAPTOR sandbox denial count; tolerant of field-name drift."""
    if not isinstance(summary, dict):
        return None
    for key in ("total_denials", "denial_count", "denials_total"):
        if isinstance(summary.get(key), int):
            return summary[key]
    denials = summary.get("denials")
    return len(denials) if isinstance(denials, list) else None


# Propagate per-engine scan quality so the triage agent never reports a clean
# verdict from a degraded scan (kite#46): CodeQL building a DB but executing 0
# queries (pack-download 504) and Semgrep being Landlock-denied both previously
# surfaced as "0 findings". Reports are read from the staged, flat findings dir;
# the glob patterns match the `raptor-` prefix stage_findings adds.
codeql_requested = codeql_enabled == "true"
codeql_report = _read_json(_find(findings_dir, "*codeql*report*.json"))
codeql_success = codeql_report.get("success") if isinstance(codeql_report, dict) else None
codeql_queries_executed = _codeql_queries_executed(codeql_report)
codeql_degraded = bool(
    codeql_requested
    and (
        codeql_report is None
        or codeql_success is False
        or (codeql_queries_executed is not None and codeql_queries_executed == 0)
    )
)
denial_count = _denial_count(_read_json(_find(findings_dir, "*sandbox*summary*.json")))
sandbox_degraded = bool(denial_count is not None and denial_count > 0)
scan_quality = {
    "degraded": bool(codeql_degraded or sandbox_degraded),
    "codeql": {
        "requested": codeql_requested,
        "report_present": codeql_report is not None,
        "success": codeql_success,
        "queries_executed": codeql_queries_executed,
        "degraded": codeql_degraded,
    },
    "sandbox": {
        "denial_count": denial_count,
        "degraded": sandbox_degraded,
    },
}

payload = {
    "status": status,
    "exit_code": int(exit_code),
    "runner": runner,
    "raptor_mode": raptor_mode,
    "run_started_at": run_started_at,
    "target_repo_path": target_repo_path,
    "raptor_source_path": raptor_source_path,
    "paths": paths,
    "sca": {
        "status": sca_status,
        "exit_code": int(sca_exit_code),
        "ran": sca_status != "skipped",
        "out_dir": sca_out_dir,
        "log_path": sca_log_path,
    },
    "artifact_upload": {
        "bucket": artifact_bucket,
        "prefix": artifact_prefix,
        "required": artifact_upload_required == "true",
        "status": artifact_upload_status,
        "exit_code": int(artifact_upload_exit_code),
        "manifest_path": artifact_manifest_path,
    },
    "openai_second_opinion": {
        "enabled": second_opinion_enabled == "true",
        "model": second_opinion_model,
        "out_dir": second_opinion_out_dir,
        "artifact_path": second_opinion_artifact_path,
        "artifact_present": Path(second_opinion_artifact_path).is_file(),
    },
    "budgets": {
        "max_findings": int(max_findings),
        "openai_second_opinion_timeout_seconds": int(second_opinion_timeout_seconds),
        "raptor_timeout_seconds": int(raptor_timeout_seconds),
    },
    "phase_timings_seconds": {
        "startup": None,
        "skill_clone": None,
        "skill_selection": None,
        "raptor": int(raptor_duration),
        "sca": int(sca_duration),
        "artifact_upload": int(artifact_upload_duration),
        "agent_execution": None,
        "detection": None,
        "safe_outputs": None,
    },
    "available_outputs": {
        key: Path(value).is_file() if key.endswith("_path") else Path(value).is_dir()
        for key, value in paths.items()
    },
    "scan_quality": scan_quality,
}

Path(out_path).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
PY

printf 'RAPTOR_AGENTIC_REVIEW_SUMMARY=%s\n' "$summary_path"
final_exit_code=$exit_code
if [[ "$artifact_upload_status" == failure && "$artifact_upload_required" == true ]]; then
  final_exit_code=1
fi
exit "$final_exit_code"
