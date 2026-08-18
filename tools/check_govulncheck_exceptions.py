#!/usr/bin/env python3
"""Cross-checks govulncheck's "your code is affected by" findings against a
reviewed exceptions list, mirroring check_pnpm_audit_exceptions.py's design
for the frontend's pnpm audit. govulncheck's own reachability analysis
already separates call-reachable findings (the "Vulnerability #N" section)
from merely-imported-but-not-called ones (the trailing summary); this only
parses the former, since the latter were never actionable to begin with.
"""
import argparse
import re
import sys
from datetime import date


REQUIRED_FIELDS = {"package", "advisory", "severity", "mitigation", "expires_on"}

VULN_HEADER_RE = re.compile(r"^Vulnerability #\d+:\s*(\S+)\s*$")
MODULE_RE = re.compile(r"^\s*Module:\s*(\S+)\s*$")
AFFECTED_SUMMARY_RE = re.compile(r"^Your code is affected by \d+ vulnerabilit")


def split_kv(line: str) -> tuple[str, str]:
    key, value = line.split(":", 1)
    value = value.strip()
    if (value.startswith('"') and value.endswith('"')) or (
        value.startswith("'") and value.endswith("'")
    ):
        value = value[1:-1]
    return key.strip(), value


def parse_exceptions(path: str) -> list[dict]:
    exceptions = []
    current = None
    with open(path, "r", encoding="utf-8") as handle:
        for raw in handle:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("version:") or line.startswith("exceptions:"):
                continue
            if line.startswith("- "):
                if current:
                    exceptions.append(current)
                current = {}
                line = line[2:].strip()
                if line:
                    key, value = split_kv(line)
                    current[key] = value
                continue
            if current is not None and ":" in line:
                key, value = split_kv(line)
                current[key] = value
    if current:
        exceptions.append(current)
    return exceptions


def parse_govulncheck_findings(path: str) -> list[tuple[str, str]]:
    """Returns [(module, osv_id), ...] for the call-reachable section only."""
    findings = []
    pending_osv = None
    with open(path, "r", encoding="utf-8") as handle:
        for raw in handle:
            line = raw.rstrip("\n")
            if AFFECTED_SUMMARY_RE.match(line.strip()):
                break
            header = VULN_HEADER_RE.match(line)
            if header:
                pending_osv = header.group(1)
                continue
            module = MODULE_RE.match(line)
            if module and pending_osv:
                findings.append((module.group(1), pending_osv))
                pending_osv = None
    return findings


def normalize(value: str) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def parse_date(value: str) -> date | None:
    try:
        return date.fromisoformat(value)
    except (ValueError, TypeError):
        return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--govulncheck-output", required=True)
    parser.add_argument("--exceptions", required=True)
    args = parser.parse_args()

    exceptions = parse_exceptions(args.exceptions)
    exception_index = {}
    errors = []

    for exc in exceptions:
        missing = [field for field in REQUIRED_FIELDS if not exc.get(field)]
        if missing:
            errors.append(
                f"Exception missing required fields {missing}: {exc.get('package', '<unknown>')}"
            )
            continue
        exc_package = normalize(exc.get("package"))
        exc_advisory = normalize(exc.get("advisory"))
        exc_date = parse_date(exc.get("expires_on"))
        if exc_date is None:
            errors.append(
                f"Exception has invalid expires_on date: {exc.get('package', '<unknown>')} {exc.get('advisory', '')}"
            )
            continue
        if not exc_package or not exc_advisory:
            errors.append("Exception missing package or advisory value")
            continue
        key = (exc_package, exc_advisory)
        if key in exception_index:
            errors.append(f"Duplicate exception for {exc_package} advisory {exc.get('advisory')}")
            continue
        exception_index[key] = {"raw": exc, "expires_on": exc_date}

    findings = parse_govulncheck_findings(args.govulncheck_output)

    today = date.today()
    missing_exceptions = []
    expired_exceptions = []
    seen = set()

    for module, osv_id in findings:
        key = (normalize(module), normalize(osv_id))
        if key in seen:
            continue
        seen.add(key)
        exc = exception_index.get(key)
        if exc is None:
            missing_exceptions.append((module, osv_id))
            continue
        if exc["expires_on"] < today:
            expired_exceptions.append((module, osv_id, exc["expires_on"].isoformat()))

    if not findings and not errors:
        # No parseable "Vulnerability #N" section at all: either govulncheck
        # found nothing reachable, or its output format changed underneath
        # us. Distinguish the two so a format change fails loudly instead of
        # silently passing.
        with open(args.govulncheck_output, "r", encoding="utf-8") as handle:
            raw_output = handle.read()
        if "No vulnerabilities found" not in raw_output and "affected by" in raw_output:
            errors.append(
                "govulncheck output mentions 'affected by' but no findings were parsed -- "
                "output format may have changed; check_govulncheck_exceptions.py needs updating"
            )

    if missing_exceptions:
        errors.append("Vulnerabilities missing exceptions:")
        for module, osv_id in missing_exceptions:
            errors.append(f"- {module} [{osv_id}]")

    if expired_exceptions:
        errors.append("Exceptions expired:")
        for module, osv_id, expires_on in expired_exceptions:
            errors.append(f"- {module} [{osv_id}] expired on {expires_on}")

    if errors:
        sys.stderr.write("\n".join(errors) + "\n")
        return 1

    if findings:
        print(f"govulncheck exceptions validated ({len(seen)} finding(s) covered).")
    else:
        print("govulncheck: no reachable vulnerabilities found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
