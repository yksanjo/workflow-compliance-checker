#!/usr/bin/env python3
"""workflow-compliance-checker: Check workflow compliance"""

import re, json, argparse
from pathlib import Path
from enum import Enum

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

COMPLIANCE = {
    'status:': (r'status:\s*disabled', Severity.CRITICAL, 'Workflow disabled'),
    'timeout:': (r'timeout-minutes:\s*0', Severity.HIGH, 'No timeout set'),
    'concurrency:': (r'concurrency:', Severity.LOW, 'Concurrency control'),
    'on:': (r'on:\s*push', Severity.LOW, 'Push trigger'),
    'pull_request_target': (r'pull_request_target', Severity.CRITICAL, 'Security risk'),
    'untrusted': (r'with:\s+ref:.*pull_request', Severity.CRITICAL, 'Untrusted checkout'),
}

STANDARDS = {
    'GDPR': [r'personal', r'pii', r'email', r'phone'],
    'SOC2': [r'encrypt', r'secure', r'logging'],
    'PCI': [r'credit', r'payment', r'card'],
}

def check(path):
    findings = []
    for f in Path(path).rglob('*.yml'):
        try:
            with open(f) as fp:
                c = fp.read()
                for name, (pat, sev, desc) in COMPLIANCE.items():
                    if re.search(pat, c):
                        findings.append((str(f), name, sev.value, desc))
        except: pass
    return findings

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('path', default='.')
    p.add_argument('--json', action='store_true')
    a = p.parse_args()
    r = check(a.path)
    if a.json:
        print(json.dumps({'compliance': len(r), 'findings': [{'file': f, 'check': n, 'severity': s, 'desc': d} for f,n,s,d in r]}, indent=2))
    else:
        print(f"\n📋 Compliance Check: {len(r)} findings\n")
        for f, n, s, d in r:
            print(f"  [{s}] {d}: {f}")
