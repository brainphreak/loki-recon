"""
searchsploit_enricher.py — post-process existing vulnerability findings and
annotate CVEs that have public Exploit-DB modules.

Runs after NSE / Nuclei have populated vulnerability_summary.csv. For each
CVE in the findings string, calls `searchsploit -j --cve <CVE>` and appends
"[exploit-db: N modules]" to the finding line.

Toggled by config['enable_searchsploit']. Off by default.
"""

import csv
import json
import logging
import os
import re
import shutil
import subprocess
import time

from logger import Logger
from shared import SharedData

logger = Logger(name="searchsploit_enricher.py", level=logging.INFO)

b_class = "SearchSploitEnricher"
b_module = "searchsploit_enricher"
b_status = "exploit_lookup"
b_port = None

CVE_RE = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)


class SearchSploitEnricher:
    """Annotate CVEs in vulnerability_summary.csv with Exploit-DB matches."""

    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.b_class = b_class
        self.b_module = b_module
        self.b_status = b_status
        self.searchsploit_path = shutil.which('searchsploit')
        if not self.searchsploit_path:
            logger.info("searchsploit not on $PATH; SearchSploitEnricher disabled at runtime")

    def _is_enabled(self) -> bool:
        return bool((self.shared_data.config or {}).get('enable_searchsploit', False))

    def _lookup_cve(self, cve: str) -> int:
        """Return the count of Exploit-DB modules referencing the given CVE."""
        try:
            result = subprocess.run(
                [self.searchsploit_path, '-j', '--cve', cve],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                return 0
            data = json.loads(result.stdout or '{}')
            return len(data.get('RESULTS_EXPLOIT', []))
        except Exception as e:
            logger.debug(f"searchsploit lookup {cve}: {e}")
            return 0

    def execute(self, ip: str, ports, row, status_key: str):
        """Orchestrator entrypoint. Annotates the row's findings in place."""
        if not self._is_enabled():
            return 'skipped'
        if not self.searchsploit_path:
            return 'failed'

        path = self.shared_data.vuln_summary_file
        if not os.path.exists(path):
            return 'skipped'

        with open(path, 'r', newline='', encoding='utf-8') as f:
            rows = list(csv.DictReader(f))
        target = next((r for r in rows if r.get('IP') == ip), None)
        if target is None:
            return 'skipped'

        findings_str = (target.get('Vulnerabilities') or '').strip()
        if not findings_str:
            return 'skipped'

        self.shared_data.lokiorch_status = "SearchSploitEnricher"
        self.shared_data.lokistatustext2 = ip
        logger.lifecycle_start(b_class, ip, 0)
        start = time.time()

        cves = sorted(set(m.group(0).upper() for m in CVE_RE.finditer(findings_str)))
        if not cves:
            logger.lifecycle_end(b_class, "no CVEs", time.time() - start, ip)
            return 'success'

        annotations = {}
        for cve in cves:
            n = self._lookup_cve(cve)
            if n > 0:
                annotations[cve] = n

        if not annotations:
            logger.lifecycle_end(b_class, f"{len(cves)} CVEs / 0 with exploits", time.time() - start, ip)
            return 'success'

        # Replace each occurrence of `CVE-X-Y` (preserving original casing) with
        # `CVE-X-Y [exploit-db: N]`. Skip if already annotated.
        new_findings = findings_str
        for cve, count in annotations.items():
            tag = f" [exploit-db: {count}]"
            pattern = re.compile(re.escape(cve), re.IGNORECASE)
            def _replace(match, _tag=tag, _cve=cve):
                # Don't double-tag if already annotated.
                offset = match.end()
                if new_findings[offset:offset + len(_tag)] == _tag:
                    return match.group(0)
                return match.group(0) + _tag
            new_findings = pattern.sub(_replace, new_findings)

        target['Vulnerabilities'] = new_findings
        headers = ["IP", "Hostname", "MAC Address", "Port", "Vulnerabilities"]
        with open(path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            for r in rows:
                writer.writerow({k: r.get(k, '') for k in headers})

        logger.lifecycle_end(
            b_class,
            f"{len(annotations)}/{len(cves)} CVEs have public exploits",
            time.time() - start, ip,
        )
        return 'success'


if __name__ == "__main__":
    s = SharedData()
    SearchSploitEnricher(s)
