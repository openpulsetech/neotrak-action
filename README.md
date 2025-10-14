# NeoTrak Action

A comprehensive security scanning GitHub Action that integrates multiple security tools to provide thorough vulnerability and configuration analysis.

## Features

- **Trivy Scanner**: Container and filesystem vulnerability scanning
- **Grype Scanner**: Fast vulnerability scanning for container images and filesystems
- **Snyk Scanner**: Developer-first security scanning (planned)
- **Semgrep Scanner**: Static analysis security scanning (planned)

## Usage

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: NeoTrack Security Scan
        uses: your-org/neotrack-action@v1
        with:
          scan-type: 'all'
          severity: 'medium,high,critical'
          format: 'sarif'
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `scan-type` | Type of scan to perform | No | `all` |
| `severity` | Severity levels to report | No | `high,critical` |
| `format` | Output format | No | `sarif` |

## Outputs

- `sarif-file`: Path to the generated SARIF file
- `scan-results`: JSON summary of scan results

## License

MIT
# neotrak-action
# neotrak-action
# neotrak-action
