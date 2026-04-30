"""
nuclei_scanner.py — wrap ProjectDiscovery's `nuclei` and feed findings into
the same vulnerability_summary.csv the nmap NSE scanner writes to. KEV/CVSS
enrichment happens in the existing pipeline because the output column is the
same: each finding line ends up as a `; `-joined entry under the host's row.

Toggled by config['enable_nuclei']. Off by default.

Standalone module — orchestrator imports + invokes per-host.
"""

import csv
import json
import logging
import os
import shutil
import subprocess
import time

from logger import Logger
from shared import SharedData
from timeout_utils import subprocess_with_timeout

logger = Logger(name="nuclei_scanner.py", level=logging.INFO)

b_class = "NucleiScanner"
b_module = "nuclei_scanner"
b_status = "nuclei_scan"
b_port = None


class NucleiScanner:
    """Run nuclei against discovered HTTP/HTTPS ports for templated vuln coverage."""

    HTTP_PORTS = {80, 8080, 8000, 8888, 8008, 5000, 9000, 8443}
    HTTPS_PORTS = {443, 8443, 9443}

    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.b_class = b_class
        self.b_module = b_module
        self.b_status = b_status
        self.nuclei_path = shutil.which('nuclei')
        if not self.nuclei_path:
            logger.info("nuclei binary not found on $PATH; NucleiScanner disabled at runtime")

    def _is_enabled(self) -> bool:
        return bool((self.shared_data.config or {}).get('enable_nuclei', False))

    def _build_targets(self, ip: str, ports: list[int]) -> list[str]:
        targets = []
        for port in ports:
            if port in self.HTTPS_PORTS:
                targets.append(f"https://{ip}:{port}")
            elif port in self.HTTP_PORTS:
                targets.append(f"http://{ip}:{port}")
        return targets

    def execute(self, ip: str, ports, row, status_key: str):
        """Orchestrator entrypoint. Returns 'success', 'failed', or 'skipped'."""
        if not self._is_enabled():
            return 'skipped'
        if not self.nuclei_path:
            logger.warning("nuclei not installed; install with: apt or download binary")
            return 'failed'

        # Coerce port list — orchestrator may pass int/list/csv string.
        if isinstance(ports, str):
            port_ints = [int(p) for p in ports.replace(',', ' ').split() if p.strip().isdigit()]
        elif isinstance(ports, int):
            port_ints = [ports]
        else:
            port_ints = [int(p) for p in (ports or [])]
        targets = self._build_targets(ip, port_ints)
        if not targets:
            logger.debug(f"No HTTP/HTTPS ports for {ip}; nuclei skipped")
            return 'skipped'

        cfg = self.shared_data.config or {}
        severity = cfg.get('nuclei_severity', 'medium,high,critical')
        rate_limit = int(cfg.get('nuclei_rate_limit', 50))
        templates_dir = cfg.get('nuclei_templates_dir', '')

        cmd = [
            self.nuclei_path,
            '-jsonl',                        # streaming JSON-Lines output
            '-silent',
            '-rate-limit', str(rate_limit),
            '-severity', severity,
            '-disable-update-check',
            '-no-interactsh',                # avoid OOB callbacks
            '-timeout', '10',
        ]
        if templates_dir and os.path.isdir(templates_dir):
            cmd.extend(['-t', templates_dir])
        cmd.append('-target')
        cmd.extend(targets)

        self.shared_data.lokiorch_status = "NucleiScanner"
        self.shared_data.lokistatustext2 = f"{ip} ({len(targets)} URL{'s' if len(targets) > 1 else ''})"
        logger.lifecycle_start(b_class, ip, port_ints[0] if port_ints else 0)
        start = time.time()
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=900,
            )
        except subprocess.TimeoutExpired:
            logger.lifecycle_timeout(b_class, "nuclei scan", 900, ip)
            return 'failed'
        except Exception as e:
            logger.error(f"Nuclei error on {ip}: {e}")
            return 'failed'

        findings = []
        for line in (proc.stdout or '').splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            template = rec.get('template-id') or rec.get('templateID') or 'unknown'
            sev = (rec.get('info') or {}).get('severity', 'info')
            matched = rec.get('matched-at') or rec.get('matched') or ''
            cves = ((rec.get('info') or {}).get('classification') or {}).get('cve-id') or []
            if isinstance(cves, str):
                cves = [cves]
            label = f"{template} [{sev}]"
            if cves:
                label += f" ({', '.join(cves)})"
            if matched:
                label += f" @ {matched}"
            findings.append(label)

        elapsed = time.time() - start
        if not findings:
            logger.lifecycle_end(b_class, 'no findings', elapsed, ip)
            return 'success'

        # Append to vuln_summary CSV alongside nmap NSE findings so the KEV
        # enrichment + UI surface treats them uniformly.
        try:
            self._append_findings(ip, row, findings)
        except Exception as e:
            logger.error(f"Could not write nuclei findings for {ip}: {e}")
            return 'failed'

        logger.lifecycle_end(b_class, f"{len(findings)} findings", elapsed, ip)
        return 'success'

    def _append_findings(self, ip: str, row: dict, findings: list[str]):
        """Merge findings into vulnerability_summary.csv.

        Appends to the existing per-IP row if one exists (so Nuclei findings
        show up alongside nmap NSE findings under the same host in the UI).
        Falls back to creating a new row only if this IP has never been seen.
        """
        path = self.shared_data.vuln_summary_file
        os.makedirs(os.path.dirname(path), exist_ok=True)
        rows: list[dict] = []
        if os.path.exists(path):
            with open(path, 'r', newline='', encoding='utf-8') as f:
                rows = list(csv.DictReader(f))
        headers = ["IP", "Hostname", "MAC Address", "Port", "Vulnerabilities"]
        joined = '; '.join(findings)

        # Find the FIRST row matching this IP and append to it. The UI groups
        # by IP, so adding to a sibling row would render as a duplicate host.
        target_row = next((r for r in rows if r.get('IP') == ip), None)
        if target_row is not None:
            current = (target_row.get('Vulnerabilities') or '').strip()
            target_row['Vulnerabilities'] = (current + '; ' + joined) if current else joined
        else:
            rows.append({
                'IP': ip,
                'Hostname': row.get('Hostnames', '') if isinstance(row, dict) else '',
                'MAC Address': row.get('MAC Address', '') if isinstance(row, dict) else '',
                'Port': '',
                'Vulnerabilities': joined,
            })

        with open(path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            for r in rows:
                writer.writerow({k: r.get(k, '') for k in headers})


if __name__ == "__main__":
    s = SharedData()
    NucleiScanner(s)
