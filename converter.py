#!/usr/bin/env python3
import argparse
import json
import os
from pathlib import Path
from typing import Any, Dict, List

SARIF_SCHEMA_URI = (
    "https://raw.githubusercontent.com/"
    "oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)


def load_pip_audit_json(path: Path) -> List[Dict[str, Any]]:
    """Load pip-audit JSON and normalize to a list of dependencies."""
    if not path.is_file():
        raise FileNotFoundError(f"Input file not found: {path}")

    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    # Format A: { "dependencies": [ ... ] }
    if isinstance(data, dict) and "dependencies" in data:
        deps = data["dependencies"]
    # Format B: [ { "name": ..., "version": ..., "vulns": [...] }, ... ]
    elif isinstance(data, list):
        deps = data
    else:
        raise ValueError(
            "Unsupported pip-audit JSON format. Expected a list or "
            'an object with a "dependencies" key.'
        )

    if not isinstance(deps, list):
        raise ValueError('"dependencies" must be a list')

    return deps


def make_rule(vuln_id: str, vuln: Dict[str, Any]) -> Dict[str, Any]:
    description = vuln.get("description") or f"Vulnerability {vuln_id}"
    aliases = vuln.get("aliases") or []

    # Prefer first alias (often a CVE) as a nicer human-facing name
    name = aliases[0] if aliases else vuln_id

    rule: Dict[str, Any] = {
        "id": vuln_id,
        "name": name,
        "shortDescription": {"text": name},
        "fullDescription": {"text": description},
        "help": {
            "text": description
        },
        "properties": {
            "tags": ["security", "dependency", "pip-audit"],
            "precision": "high",
            # We do NOT get CVSS scores in pip-audit JSON, so we pick a
            # constant value that maps to "Medium" in GitHub:
            # 4.0–6.9 -> Medium
            "security-severity": "5.0",
            "aliases": aliases,
        },
    }

    fix_versions = vuln.get("fix_versions") or []
    if fix_versions:
        rule["properties"]["fix-versions"] = fix_versions

    return rule


def make_result(
    vuln_id: str,
    vuln: Dict[str, Any],
    package_name: str,
    package_version: str,
    artifact_path: str,
) -> Dict[str, Any]:
    description = vuln.get("description") or ""
    fix_versions = vuln.get("fix_versions") or []

    fix_text = (
        f"Known fixed versions: {', '.join(fix_versions)}"
        if fix_versions
        else "No known fixed version."
    )

    message = (
        f"Package '{package_name}=={package_version}' is affected by {vuln_id}. "
        f"{description} {fix_text}"
    ).strip()

    result: Dict[str, Any] = {
        "ruleId": vuln_id,
        "level": "warning",  # all treated as Medium; documented in README
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        # Path must be repo-relative for GH Code Scanning
                        "uri": artifact_path
                    },
                    "region": {
                        # No real line info; we just flag the file
                        "startLine": 1,
                        "startColumn": 1,
                    },
                }
            }
        ],
        "properties": {
            "package": package_name,
            "package_version": package_version,
        },
    }

    if fix_versions:
        result["properties"]["fix_versions"] = fix_versions

    aliases = vuln.get("aliases") or []
    if aliases:
        result["properties"]["aliases"] = aliases

    return result


def build_sarif(
    deps: List[Dict[str, Any]],
    artifact_path: str,
    tool_version: str,
) -> Dict[str, Any]:
    rules: List[Dict[str, Any]] = []
    rule_index_by_id: Dict[str, int] = {}
    results: List[Dict[str, Any]] = []

    for dep in deps:
        name = dep.get("name", "<unknown>")
        version = dep.get("version", "<unknown>")
        vulns = dep.get("vulns") or []

        if not vulns:
            continue

        for vuln in vulns:
            vuln_id = vuln.get("id")
            if not vuln_id:
                # Skip malformed entries
                continue

            if vuln_id not in rule_index_by_id:
                rule = make_rule(vuln_id, vuln)
                rule_index_by_id[vuln_id] = len(rules)
                rules.append(rule)

            result = make_result(
                vuln_id=vuln_id,
                vuln=vuln,
                package_name=name,
                package_version=version,
                artifact_path=artifact_path,
            )
            results.append(result)

    run = {
        "tool": {
            "driver": {
                "name": "pip-audit",
                "version": tool_version or "unknown",
                "informationUri": "https://github.com/pypa/pip-audit",
                "rules": rules,
            }
        },
        "results": results,
    }

    sarif: Dict[str, Any] = {
        "$schema": SARIF_SCHEMA_URI,
        "version": "2.1.0",
        "runs": [run],
    }

    return sarif


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convert pip-audit JSON output to SARIF 2.1.0"
    )
    parser.add_argument(
        "--input",
        "-i",
        required=True,
        help="Path to pip-audit JSON output file",
    )
    parser.add_argument(
        "--output",
        "-o",
        required=True,
        help="Path to write SARIF JSON output",
    )
    parser.add_argument(
        "--artifact-path",
        "-a",
        default="requirements.txt",
        help="Repo-relative path to dependency manifest (for locations[].uri)",
    )
    parser.add_argument(
        "--tool-version",
        "-t",
        default="",
        help="pip-audit version (optional, for SARIF metadata)",
    )

    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)

    deps = load_pip_audit_json(input_path)
    sarif = build_sarif(
        deps=deps,
        artifact_path=args.artifact_path,
        tool_version=args.tool_version,
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2)

    finding_count = len(sarif["runs"][0]["results"])
    print(f"Wrote {finding_count} findings to {output_path}")

    # Expose outputs to GitHub Actions (for composite action)
    gh_out = os.getenv("GITHUB_OUTPUT")
    if gh_out:
        with open(gh_out, "a", encoding="utf-8") as f:
            print(f"finding-count={finding_count}", file=f)
            print(f"sarif-file={output_path.as_posix()}", file=f)


if __name__ == "__main__":
    main()
