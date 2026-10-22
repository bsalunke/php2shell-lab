#!/usr/bin/env python3
"""Find PHP vulnerabilities in the images running on a Kubernetes cluster.

The script enumerates every unique image used by running pods, scans each image
with Qualys qscanner, and reports which workloads use an image with a PHP
vulnerability (including CVE-2026-109618 / CVE-2026-109619, "PHP2Shell").

qscanner credentials are read from its usual environment variables or config
file, so they never appear on this script's command line:

    export QUALYS_CLIENT_ID=...
    export QUALYS_CLIENT_SECRET=...
    ./scripts/scan_cluster_php.py --pod US2

Exit codes:
    0  no PHP vulnerabilities found
    1  at least one PHP vulnerability found
    2  no PHP vulnerability found, but at least one image could not be scanned
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PHP2SHELL_CVES = {"CVE-2026-109618", "CVE-2026-109619"}
SEVERITY_LABELS = {1: "Info", 2: "Low", 3: "Medium", 4: "High", 5: "Critical"}


@dataclass
class ImageTarget:
    image: str
    workloads: list[str] = field(default_factory=list)


@dataclass
class ScanOutcome:
    target: ImageTarget
    status: str = "scanned"
    error: str | None = None
    php_findings: list[dict[str, Any]] = field(default_factory=list)
    other_vulnerabilities: int = 0
    report_status: str | None = None

    @property
    def php2shell(self) -> bool:
        return any(finding["php2shell"] for finding in self.php_findings)


def normalize_image(reference: str) -> str:
    """Collapse 'nginx' and 'nginx:latest' to the same key."""
    reference = reference.strip()
    if "@" in reference:
        return reference
    last = reference.rsplit("/", 1)[-1]
    return reference if ":" in last else f"{reference}:latest"


def collect_images(pods: list[dict[str, Any]], running_only: bool) -> list[ImageTarget]:
    targets: dict[str, ImageTarget] = {}
    for pod in pods:
        if running_only and pod.get("status", {}).get("phase") != "Running":
            continue

        namespace = pod["metadata"]["namespace"]
        name = pod["metadata"]["name"]
        for container_type in ("initContainers", "containers", "ephemeralContainers"):
            for container in pod["spec"].get(container_type) or []:
                image = container.get("image")
                if not image:
                    continue

                key = normalize_image(image)
                target = targets.setdefault(key, ImageTarget(image=key))
                suffix = " [init]" if container_type == "initContainers" else ""
                if container_type == "ephemeralContainers":
                    suffix = " [ephemeral]"
                workload = f"{namespace}/{name} ({container.get('name', '?')}){suffix}"
                if workload not in target.workloads:
                    target.workloads.append(workload)

    for target in targets.values():
        target.workloads.sort()
    return [targets[key] for key in sorted(targets)]


def kubectl_json(kubectl: str, extra: list[str], args: list[str]) -> Any:
    command = [kubectl, *extra, *args]
    proc = subprocess.run(command, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip()
        raise SystemExit(f"error: {' '.join(command)} failed:\n{detail}")
    return json.loads(proc.stdout)


def kubectl_text(kubectl: str, extra: list[str], args: list[str]) -> str:
    proc = subprocess.run([kubectl, *extra, *args], capture_output=True, text=True, check=False)
    return proc.stdout.strip() if proc.returncode == 0 else ""


def is_php_vulnerability(vulnerability: dict[str, Any]) -> bool:
    cves = {str(cve).upper() for cve in vulnerability.get("cveids") or []}
    if cves & PHP2SHELL_CVES:
        return True
    if "php" in str(vulnerability.get("title", "")).lower():
        return True
    if "php" in str(vulnerability.get("category", "")).lower():
        return True
    return any("php" in str(pkg.get("name", "")).lower()
               for pkg in vulnerability.get("software") or [])


def parse_report(report: dict[str, Any]) -> tuple[list[dict[str, Any]], int, str | None]:
    vulnerability_report = report.get("VulnerabilityReport") or {}
    details = vulnerability_report.get("details") or []

    php_findings: list[dict[str, Any]] = []
    for vulnerability in details:
        if not is_php_vulnerability(vulnerability):
            continue

        cves = [str(cve) for cve in vulnerability.get("cveids") or []]
        packages = vulnerability.get("software") or []
        php_packages = [pkg for pkg in packages
                        if "php" in str(pkg.get("name", "")).lower()]

        severity = vulnerability.get("severity")
        php_findings.append({
            "qid": vulnerability.get("qid"),
            "title": vulnerability.get("title"),
            "cves": cves,
            "php2shell": bool({cve.upper() for cve in cves} & PHP2SHELL_CVES),
            "severity": severity,
            "severity_label": SEVERITY_LABELS.get(
                severity, "Unknown" if severity is None else str(severity)
            ),
            "qds_score": vulnerability.get("qdsScore"),
            "type": vulnerability.get("typeDetected"),
            "packages": php_packages or packages,
        })

    return php_findings, len(details) - len(php_findings), vulnerability_report.get("Status")


def summarize_error(output: str, returncode: int) -> str:
    """Keep the useful part of qscanner's output, not its banner and progress logs."""
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    errors = [re.sub(r"^\d{4}-\d{2}-\d{2}T\S+\s+", "", line)
              for line in lines if "ERROR" in line]
    if errors:
        return "\n".join(errors[-5:])
    return "\n".join(lines[-5:]) or f"qscanner exited with {returncode}"


def scan_image(target: ImageTarget, args: argparse.Namespace, reports_root: Path) -> ScanOutcome:
    outcome = ScanOutcome(target=target)
    digest = hashlib.sha1(target.image.encode()).hexdigest()[:10]
    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", target.image)[:80]
    output_dir = reports_root / f"{safe_name}-{digest}"
    output_dir.mkdir(parents=True, exist_ok=True)
    existing_reports = set(output_dir.rglob("*-Report.json"))

    command = [
        args.qscanner,
        "--pod", args.pod,
        "--report-format", "json",
        "--output-dir", str(output_dir),
        "--scan-timeout", f"{args.timeout}s",
        *args.qscanner_arg,
        "image", target.image,
    ]

    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=args.timeout + 300,
            env=os.environ.copy(),
            check=False,
        )
    except subprocess.TimeoutExpired:
        outcome.status = "error"
        outcome.error = f"qscanner timed out after {args.timeout + 300}s"
        return outcome

    if proc.returncode != 0:
        output = (proc.stderr or proc.stdout).strip()
        outcome.status = "error"
        outcome.error = summarize_error(output, proc.returncode)
        return outcome

    reports = sorted(
        (path for path in output_dir.rglob("*-Report.json")
         if path not in existing_reports),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    if not reports:
        outcome.status = "error"
        outcome.error = "qscanner succeeded but produced no new *-Report.json"
        return outcome

    try:
        report = json.loads(reports[0].read_text())
    except (OSError, json.JSONDecodeError) as exc:
        outcome.status = "error"
        outcome.error = f"could not read {reports[0]}: {exc}"
        return outcome

    outcome.php_findings, outcome.other_vulnerabilities, outcome.report_status = parse_report(report)
    return outcome


def finding_lines(finding: dict[str, Any]) -> list[str]:
    cves = ", ".join(finding["cves"]) or "no CVE"
    kind = f" ({finding['type']})" if finding.get("type") else ""
    lines = [
        f"- QID {finding['qid']} [{finding['severity_label']}] {cves}"
        + (" [PHP2Shell]" if finding["php2shell"] else "") + kind,
        f"  {finding['title']}",
    ]
    packages = finding.get("packages") or []
    for package in packages[:4]:
        installed = package.get("version") or "?"
        fixed = package.get("fixVersion") or "no fix"
        lines.append(f"  {package.get('name', '?')} {installed} -> {fixed}")
    if len(packages) > 4:
        lines.append(f"  ... and {len(packages) - 4} more package(s)")
    return lines


def cluster_label(cluster: dict[str, Any]) -> str:
    return (f"{cluster.get('context') or '(unknown)'} "
            f"({cluster.get('server') or '(unknown)'})")


def render_text(cluster: dict[str, Any], outcomes: list[ScanOutcome]) -> str:
    vulnerable = [o for o in outcomes if o.php_findings]
    php2shell = [o for o in outcomes if o.php2shell]
    failed = [o for o in outcomes if o.status == "error"]

    lines = [
        f"Cluster: {cluster_label(cluster)}",
        "",
        "PHP vulnerability scan of Kubernetes cluster",
        f"  pods:    {cluster['pods']} {'running' if cluster['running_only'] else 'total'}",
        f"  images:  {cluster['unique_images']} unique",
        "",
        f"Scanned: {len(outcomes) - len(failed)}/{len(outcomes)} images",
        f"Images with PHP findings: {len(vulnerable)}",
        f"Images with PHP2Shell findings: {len(php2shell)}",
        f"Images that could not be scanned: {len(failed)}",
    ]

    if vulnerable:
        lines += ["", "PHP-VULNERABLE IMAGES", "=" * 22]
        for outcome in vulnerable:
            lines += ["", outcome.target.image]
            lines.append("  workloads:")
            lines += [f"    - {workload}" for workload in outcome.target.workloads]
            lines.append(f"  php2shell: {'YES' if outcome.php2shell else 'no'}")
            lines.append("  PHP findings:")
            for finding in outcome.php_findings:
                lines += [f"  {line}" for line in finding_lines(finding)]
            if outcome.other_vulnerabilities:
                lines.append(f"  ({outcome.other_vulnerabilities} other non-PHP finding(s))")
    elif failed:
        lines += ["", "No PHP vulnerabilities found in the images that were scanned."]
    else:
        lines += ["", "No PHP vulnerabilities found in the scanned images."]

    if failed:
        lines += ["", "SCAN ERRORS", "=" * 11]
        for outcome in failed:
            lines += ["", outcome.target.image]
            lines += [f"  workload: {workload}" for workload in outcome.target.workloads]
            error = textwrap.indent(outcome.error or "", "    ")
            lines.append("  error:")
            lines.append(error.rstrip())

    if any(o.php_findings for o in outcomes):
        verdict = "PHP-VULNERABLE"
    elif failed:
        verdict = "INCONCLUSIVE (some images could not be scanned)"
    else:
        verdict = "NO PHP VULNERABILITIES FOUND"

    lines += ["", f"VERDICT: {verdict}"]
    if not vulnerable:
        lines += [
            "",
            "Note: qscanner only sees PHP installed as an OS/SCA package. Source-built PHP",
            "      (for example the official php:* images) may not appear in its inventory.",
        ]
    return "\n".join(lines)


def build_json(cluster: dict[str, Any], outcomes: list[ScanOutcome]) -> dict[str, Any]:
    if any(o.php_findings for o in outcomes):
        verdict = "php-vulnerable"
    elif any(o.status == "error" for o in outcomes):
        verdict = "inconclusive"
    else:
        verdict = "no-php-vulnerabilities"

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "cluster": cluster,
        "verdict": verdict,
        "summary": {
            "unique_images": cluster["unique_images"],
            "scanned": sum(1 for o in outcomes if o.status == "scanned"),
            "failed": sum(1 for o in outcomes if o.status == "error"),
            "php_vulnerable_images": sum(1 for o in outcomes if o.php_findings),
            "php2shell_images": sum(1 for o in outcomes if o.php2shell),
        },
        "images": [
            {
                "image": outcome.target.image,
                "workloads": outcome.target.workloads,
                "status": outcome.status,
                "error": outcome.error,
                "report_status": outcome.report_status,
                "php2shell": outcome.php2shell,
                "php_vulnerabilities": outcome.php_findings,
                "other_vulnerabilities": outcome.other_vulnerabilities,
            }
            for outcome in outcomes
        ],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan every unique image running on a Kubernetes cluster with qscanner "
                    "and report PHP vulnerabilities.",
    )
    parser.add_argument("--context", help="kubectl context to use")
    parser.add_argument("--kubeconfig", help="path to a kubeconfig file")
    parser.add_argument("-n", "--namespace", help="only scan this namespace (default: all)")
    parser.add_argument("--all-pods", action="store_true",
                        help="include pods that are not in the Running phase")
    parser.add_argument("--pod", default=os.environ.get("QSCANNER_POD", "US2"),
                        help="Qualys POD for qscanner (default: QSCANNER_POD or US2)")
    parser.add_argument("--jobs", type=int, default=2,
                        help="number of images to scan in parallel (default: 2)")
    parser.add_argument("--timeout", type=int, default=600,
                        help="per-image scan timeout in seconds (default: 600)")
    parser.add_argument("--qscanner", default="qscanner", help="qscanner executable")
    parser.add_argument("--kubectl", default="kubectl", help="kubectl executable")
    parser.add_argument("--qscanner-arg", action="append", default=[], metavar="ARG",
                        help="extra argument passed to qscanner (repeatable)")
    parser.add_argument("--output-dir", type=Path,
                        help="keep qscanner reports in this directory")
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    parser.add_argument("--dry-run", action="store_true",
                        help="list images and workloads without scanning")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    for executable in (args.kubectl, args.qscanner):
        if shutil.which(executable) is None:
            print(f"error: {executable} not found in PATH", file=sys.stderr)
            return 2

    kube_args = []
    if args.kubeconfig:
        kube_args += ["--kubeconfig", args.kubeconfig]
    if args.context:
        kube_args += ["--context", args.context]

    pods_args = ["get", "pods"]
    if args.namespace:
        pods_args += ["--namespace", args.namespace]
    else:
        pods_args += ["--all-namespaces"]
    pods_args += ["-o", "json"]

    pods = kubectl_json(args.kubectl, kube_args, pods_args)["items"]
    running_only = not args.all_pods
    targets = collect_images(pods, running_only=running_only)
    selected_pods = sum(
        1 for pod in pods
        if not running_only or pod.get("status", {}).get("phase") == "Running"
    )

    cluster = {
        "context": args.context or kubectl_text(args.kubectl, kube_args, ["config", "current-context"]),
        "server": kubectl_text(args.kubectl, kube_args,
                               ["config", "view", "--minify", "-o",
                                "jsonpath={.clusters[0].cluster.server}"]),
        "namespace": args.namespace or "all",
        "pods": selected_pods,
        "pods_total": len(pods),
        "running_only": running_only,
        "unique_images": len(targets),
    }

    if args.dry_run:
        if args.json:
            print(json.dumps({
                "cluster": cluster,
                "images": [{"image": t.image, "workloads": t.workloads} for t in targets],
            }, indent=2))
        else:
            pod_label = (f"{cluster['pods']} running pod(s)" if running_only
                         else f"{cluster['pods']} pod(s)")
            print(f"Cluster: {cluster_label(cluster)}")
            print()
            print(f"{len(targets)} unique image(s) across {pod_label}:")
            for target in targets:
                print(f"\n{target.image}")
                for workload in target.workloads:
                    print(f"  - {workload}")
        return 0

    if not targets:
        print("No running pods with images found.", file=sys.stderr)
        return 0

    temporary_dir: tempfile.TemporaryDirectory[str] | None = None
    if args.output_dir:
        reports_root = args.output_dir
        reports_root.mkdir(parents=True, exist_ok=True)
    else:
        temporary_dir = tempfile.TemporaryDirectory(prefix="php-cluster-scan-")
        reports_root = Path(temporary_dir.name)

    outcomes: list[ScanOutcome] = []
    print(f"Scanning {len(targets)} unique image(s) with qscanner "
          f"(jobs={max(1, args.jobs)})...", file=sys.stderr)
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
            futures = {
                pool.submit(scan_image, target, args, reports_root): target
                for target in targets
            }
            for index, future in enumerate(concurrent.futures.as_completed(futures), start=1):
                try:
                    outcome = future.result()
                except Exception as exc:  # noqa: BLE001 - keep one bad image from aborting the run
                    outcome = ScanOutcome(
                        target=futures[future],
                        status="error",
                        error=f"unexpected error: {exc}",
                    )
                outcomes.append(outcome)
                detail = (f"{len(outcome.php_findings)} PHP finding(s)"
                          if outcome.status == "scanned" else "scan failed")
                print(f"[{index}/{len(targets)}] {outcome.target.image}: {detail}",
                      file=sys.stderr)
    finally:
        outcomes.sort(key=lambda outcome: outcome.target.image)
        if temporary_dir is not None:
            temporary_dir.cleanup()

    if args.json:
        print(json.dumps(build_json(cluster, outcomes), indent=2))
    else:
        print(render_text(cluster, outcomes))

    if any(outcome.php_findings for outcome in outcomes):
        return 1
    if any(outcome.status == "error" for outcome in outcomes):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
