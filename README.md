# pip-audit-sarif-action

This repository contains a custom GitHub Action that converts
[`pip-audit`](https://github.com/pypa/pip-audit) JSON output into
[SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)  
so the results can be uploaded to GitHub Advanced Security Code Scanning.

This action is part of a course project for an Intermediate Software Testing class.

---

## What This Action Does

- Runs a Python script (`converter.py`) that:
  - Reads pip-audit’s JSON output (`--format json`)
  - Builds a valid SARIF v2.1.0 document
  - Creates one rule per vulnerability ID (e.g., CVE or PYSEC)
  - Creates one result per vulnerable dependency
  - Maps all findings to **Medium severity**  
    (because pip-audit JSON does not currently provide CVSS scores)
  - Points SARIF locations to your dependency file (e.g. `requirements.txt`)

- Exposes two outputs:
  - `sarif-file`: the path to the generated SARIF file  
  - `finding-count`: number of vulnerability findings

---

## Inputs

| Name           | Required | Description |
|----------------|----------|-------------|
| `input-file`   | yes      | Path to pip-audit JSON output file |
| `output-file`  | yes      | Path where the SARIF file will be written |
| `artifact-path`| no       | Repo-relative path to the dependency file (default: `requirements.txt`) |
| `tool-version` | no       | Optional pip-audit version to record in SARIF metadata |

---

## Outputs

| Name            | Description |
|-----------------|-------------|
| `sarif-file`    | Path to the generated SARIF results file |
| `finding-count` | Number of vulnerability findings in the SARIF |

---

## Example Usage

```yaml
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install pip-audit
        run: |
          python -m pip install --upgrade pip
          python -m pip install pip-audit

      - name: Run pip-audit
        run: |
          pip-audit -r vulnerable-app/requirements.txt \
            --format json \
            --output pip-audit.json

      - name: Convert pip-audit JSON to SARIF
        uses: courtneybodily/pip-audit-sarif-action@v1
        with:
          input-file: pip-audit.json
          output-file: results.sarif
          artifact-path: vulnerable-app/requirements.txt

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
