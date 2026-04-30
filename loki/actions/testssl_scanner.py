"""
testssl_scanner.py — wrap drwetter/testssl.sh and feed TLS/SSL findings into
vulnerability_summary.csv next to NSE / Nuclei findings.

Targets discovered HTTPS ports (443, 8443, 9443 by default; configurable).
Uses testssl.sh's `--jsonfile-pretty` output and extracts findings flagged
HIGH or CRITICAL by default. Lower-severity issues can be included via
config['testssl_severity'].

Toggled by config['enable_testssl']. Off by default — testssl is thorough
but slow (~2-5 minutes per host).
"""

import csv
import json
import logging
import os
import shutil
import subprocess
import tempfile
import time

from logger import Logger
from shared import SharedData

logger = Logger(name="testssl_scanner.py", level=logging.INFO)

b_class = "TestSSLScanner"
b_module = "testssl_scanner"
b_status = "tls_audit"
b_port = None


class TestSSLScanner:
    """Run testssl.sh against HTTPS ports for deep TLS audit."""

    DEFAULT_TLS_PORTS = (443, 8443, 9443)
    SEVERITY_RANK = {'INFO': 0, 'OK': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4, 'WARN': 1}

    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.b_class = b_class
        self.b_module = b_module
        self.b_status = b_status
        self.testssl_path = shutil.which('testssl.sh')
        if not self.testssl_path:
            logger.info("testssl.sh not on $PATH; TestSSLScanner disabled at runtime")

    def _is_enabled(self) -> bool:
        return bool((self.shared_data.config or {}).get('enable_testssl', False))

    def _min_severity(self) -> int:
        cfg = (self.shared_data.config or {}).get('testssl_severity', 'HIGH')
        return self.SEVERITY_RANK.get(cfg.upper(), 3)

    def execute(self, ip: str, ports, row, status_key: str):
        if not self._is_enabled():
            return 'skipped'
        if not self.testssl_path:
            return 'failed'

        if isinstance(ports, str):
            port_ints = [int(p) for p in ports.replace(',', ' ').split() if p.strip().isdigit()]
        elif isinstance(ports, int):
            port_ints = [ports]
        else:
            port_ints = [int(p) for p in (ports or [])]
        tls_ports = [p for p in port_ints if p in self.DEFAULT_TLS_PORTS]
        if not tls_ports:
            return 'skipped'

        min_rank = self._min_severity()
        all_findings: list[str] = []
        self.shared_data.lokiorch_status = "TestSSLScanner"

        for port in tls_ports:
            self.shared_data.lokistatustext2 = f"{ip}:{port}"
            findings = self._scan_one(ip, port, min_rank)
            all_findings.extend(findings)

        if not all_findings:
            return 'success'

        try:
            self._merge_into_csv(ip, row, all_findings)
        except Exception as e:
            logger.error(f"testssl merge failed for {ip}: {e}")
            return 'failed'
        return 'success'

    def _scan_one(self, ip: str, port: int, min_rank: int) -> list[str]:
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as tf:
            json_out = tf.name
        try:
            cmd = [
                self.testssl_path,
                '--jsonfile-pretty', json_out,
                '--quiet',
                '--color', '0',
                '--fast',                       # skip cert-chain verification (faster)
                '--ip', 'one',                  # don't iterate all DNS A records
                f'{ip}:{port}',
            ]
            logger.lifecycle_start(b_class, ip, port)
            start = time.time()
            try:
                subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            except subprocess.TimeoutExpired:
                logger.lifecycle_timeout(b_class, "testssl.sh", 600, ip)
                return []
            elapsed = time.time() - start

            if not os.path.exists(json_out) or os.path.getsize(json_out) == 0:
                logger.lifecycle_end(b_class, "no output", elapsed, ip)
                return []
            with open(json_out, 'r', encoding='utf-8') as f:
                results = json.load(f)
            findings = []
            for entry in results if isinstance(results, list) else results.get('scanResult', []):
                # testssl.sh output schemas differ between versions; tolerate both.
                items = entry.get('vulnerabilities', []) if isinstance(entry, dict) else []
                for item in items:
                    sev = (item.get('severity') or 'INFO').upper()
                    if self.SEVERITY_RANK.get(sev, 0) < min_rank:
                        continue
                    name = item.get('id') or item.get('finding') or 'unknown'
                    cve = item.get('cve', '')
                    label = f"testssl:{name} [{sev.lower()}]"
                    if cve:
                        label += f" ({cve})"
                    label += f" @ {ip}:{port}"
                    findings.append(label)
            logger.lifecycle_end(b_class, f"{len(findings)} findings", elapsed, ip)
            return findings
        finally:
            try:
                os.unlink(json_out)
            except Exception:
                pass

    def _merge_into_csv(self, ip: str, row: dict, findings: list[str]):
        """Append findings to the per-IP row in vulnerability_summary.csv."""
        path = self.shared_data.vuln_summary_file
        os.makedirs(os.path.dirname(path), exist_ok=True)
        rows: list[dict] = []
        if os.path.exists(path):
            with open(path, 'r', newline='', encoding='utf-8') as f:
                rows = list(csv.DictReader(f))
        headers = ["IP", "Hostname", "MAC Address", "Port", "Vulnerabilities"]
        joined = '; '.join(findings)
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
    TestSSLScanner(s)
