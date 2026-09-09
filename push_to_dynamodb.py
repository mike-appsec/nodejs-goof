"""
push_to_dynamodb.py

Reads a Snyk `snyk test --json` results file, computes severity counts,
and writes one summary item into the SnykScans_Results DynamoDB table.

Usage:
    python push_to_dynamodb.py results.json nodejs-goof npm

Arguments:
    results.json   - path to the JSON file produced by `snyk test --json`
    nodejs-goof    - project name (used as a GSI key so Grafana can filter by project)
    npm            - scan_type label (npm, container, iac, etc.) - lets you
                     track multiple scan types for the same project over time

Relies on boto3's default credential chain (same as setup_snyk_infra.py) -
in GitHub Actions, aws-actions/configure-aws-credentials sets this up for us
via environment variables, so no extra config needed here.
"""

import sys
import json
import uuid
from datetime import datetime, timezone

import boto3

AWS_REGION = "us-east-1"
TABLE_NAME = "SnykScans_Results"


def count_severities(vulnerabilities):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for vuln in vulnerabilities:
        sev = vuln.get("severity", "").lower()
        if sev in counts:
            counts[sev] += 1
    return counts


def main():
    if len(sys.argv) != 4:
        print("Usage: python push_to_dynamodb.py <results.json> <project_name> <scan_type>")
        sys.exit(1)

    results_path, project_name, scan_type = sys.argv[1], sys.argv[2], sys.argv[3]

    with open(results_path, "r") as f:
        data = json.load(f)

    # `snyk test --json` puts findings in a top-level "vulnerabilities" list
    # for standard SCA scans. (Container scans nest this slightly differently -
    # fine for tonight since we're starting with the npm/SCA scan.)
    vulnerabilities = data.get("vulnerabilities", [])
    counts = count_severities(vulnerabilities)
    total_issues = len(vulnerabilities)
    total_dependencies = data.get("dependencyCount", 0)

    now = datetime.now(timezone.utc).isoformat(timespec="milliseconds")

    item = {
        "scan_id": {"S": str(uuid.uuid4())},
        "project_name": {"S": project_name},
        "scan_timestamp": {"S": now},
        "scan_type": {"S": scan_type},
        "total_dependencies": {"N": str(total_dependencies)},
        "total_issues": {"N": str(total_issues)},
        "critical_count": {"N": str(counts["critical"])},
        "high_count": {"N": str(counts["high"])},
        "medium_count": {"N": str(counts["medium"])},
        "low_count": {"N": str(counts["low"])},
    }

    dynamodb = boto3.client("dynamodb", region_name=AWS_REGION)
    dynamodb.put_item(TableName=TABLE_NAME, Item=item)

    print(f"[done] Wrote scan summary for '{project_name}' ({scan_type}) to {TABLE_NAME}")
    print(f"       total_issues={total_issues}  critical={counts['critical']}  "
          f"high={counts['high']}  medium={counts['medium']}  low={counts['low']}")


if __name__ == "__main__":
    main()
