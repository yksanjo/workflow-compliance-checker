# workflow-compliance-checker

Check GitHub Actions workflow compliance.

## Usage

```bash
python3 check.py .github/workflows/
python3 check.py . --json
```

## Checks

- Disabled workflows
- Timeout settings
- Concurrency control
- Security risks
- GDPR/SOC2/PCI compliance
