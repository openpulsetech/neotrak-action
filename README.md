# NeoTrack Security Scanner GitHub Action

A comprehensive security scanning GitHub Action that performs vulnerability scanning, configuration analysis, secret detection, and SBOM (Software Bill of Materials) generation for your projects.

## Features

- **Vulnerability Scanning**: Detect security vulnerabilities in dependencies and packages
- **Configuration Analysis**: Identify misconfigurations in your infrastructure and application files
- **Secret Detection**: Scan for exposed secrets, API keys, and credentials
- **SBOM Generation**: Generate Software Bill of Materials for dependency tracking
- **Automated Reporting**: Upload scan results to NeoTrack platform for centralized security management
- **PR Comments**: Automatically post security scan results as comments on pull requests

## Prerequisites

Before using this action, you need to:

1. **Sign up for NeoTrack**: Create an account at [NeoTrack Platform](https://beta.neoTrak.io)
2. **Obtain API Credentials**: Get your `NT_API_KEY` and `NT_SECRET_KEY` from the NeoTrack dashboard
3. **Configure GitHub Secrets**: Add the required credentials to your repository's secrets
4. **(Optional) Get Project ID**: Obtain your `PROJECT_ID` from the NeoTrack dashboard to associate scans with a specific project

## Quick Start

### Step 1: Add GitHub Secrets

Navigate to your repository settings and add the following secrets:

1. Go to **Settings** → **Secrets and variables** → **Actions**
2. Click **New repository secret**
3. Add the following environment variables as secrets:

| Environment Variable | Description | Required |
|---------------------|-------------|----------|
| `PROJECT_ID` | Your NeoTrack project identifier | No |
| `NT_API_KEY` | API key for authentication | Yes |
| `NT_SECRET_KEY` | Secret key for authentication | Yes |
| `DEBUG_MODE` | Enable debug logging (set to `true` or `false`) | No |

### Step 2: Create Workflow File

Create a new file in your repository at `.github/workflows/example.yml`:

```yaml
name: NeoTrack Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]
  schedule:
    # Run daily at 2 AM UTC
    - cron: '0 2 * * *'

jobs:
  security-scan:
    name: Run Security Scan
    runs-on: ubuntu-latest

    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: NeoTrack Security Scan
        uses: openpulsetech/neotrak-action@main
        with:
          fail-on-vulnerability: 'false'
          fail-on-misconfiguration: 'false'
          fail-on-secret: 'false'
        env:
          PROJECT_ID: ${{ secrets.PROJECT_ID }}
          NT_API_KEY: ${{ secrets.NT_API_KEY }}
          NT_SECRET_KEY: ${{ secrets.NT_SECRET_KEY }}
          DEBUG_MODE: ${{ secrets.DEBUG_MODE }}
```

### Step 3: Adding to Existing Workflow (Optional)

If you already have a `.github/workflows/*.yml` file in your project, you can add the NeoTrack Security Scan as an additional step:

**Option 1: Add as a separate job**

```yaml
# Your existing workflow file
name: CI/CD Pipeline

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  # Your existing jobs
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build
        run: npm run build
      # ... other build steps

  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Tests
        run: npm test
      # ... other test steps

  # Add NeoTrack security scan as a new job
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: NeoTrack Security Scan
        uses: openpulsetech/neotrak-action@main
        with:
          fail-on-vulnerability: 'false'
          fail-on-misconfiguration: 'false'
          fail-on-secret: 'false'
        env:
          PROJECT_ID: ${{ secrets.PROJECT_ID }}
          NT_API_KEY: ${{ secrets.NT_API_KEY }}
          NT_SECRET_KEY: ${{ secrets.NT_SECRET_KEY }}
          DEBUG_MODE: ${{ secrets.DEBUG_MODE }}
```

**Option 2: Add as a step in existing job**

```yaml
# Your existing workflow file
name: CI/CD Pipeline

on:
  push:
    branches: [ main ]

jobs:
  build-and-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Your existing steps
      - name: Setup Node
        uses: actions/setup-node@v4
        with:
          node-version: '18'

      - name: Install Dependencies
        run: npm install

      - name: Build
        run: npm run build

      # Add NeoTrack scan as an additional step
      - name: NeoTrack Security Scan
        uses: openpulsetech/neotrak-action@main
        with:
          fail-on-vulnerability: 'false'
          fail-on-misconfiguration: 'false'
          fail-on-secret: 'false'
        env:
          PROJECT_ID: ${{ secrets.PROJECT_ID }}
          NT_API_KEY: ${{ secrets.NT_API_KEY }}
          NT_SECRET_KEY: ${{ secrets.NT_SECRET_KEY }}
          DEBUG_MODE: ${{ secrets.DEBUG_MODE }}

      # Continue with other steps
      - name: Run Tests
        run: npm test
```

**Option 3: Run scan before deployment**

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Run security scan before deployment
      - name: Security Check Before Deploy
        uses: openpulsetech/neotrak-action@main
        with:
          fail-on-vulnerability: 'true'  # Fail deployment if vulnerabilities found
          fail-on-misconfiguration: 'true'
          fail-on-secret: 'true'
        env:
          PROJECT_ID: ${{ secrets.PROJECT_ID }}
          NT_API_KEY: ${{ secrets.NT_API_KEY }}
          NT_SECRET_KEY: ${{ secrets.NT_SECRET_KEY }}

      # Only deploy if security scan passes
      - name: Deploy to Production
        run: npm run deploy
```

**Best Practices for Existing Workflows:**

1. **Separate Job** - Run security scans in parallel with other jobs for faster feedback
2. **Before Deployment** - Always scan before deploying to production
3. **Fail on Critical** - Set `fail-on-vulnerability: 'true'` for production branches
4. **Report Only for PRs** - Set to `'false'` for pull requests to avoid blocking development

## Configuration Options

### Input Parameters

| Parameter | Description | Default | Required |
|-----------|-------------|---------|----------|
| `severity` | Severity levels to report (comma-separated: CRITICAL, HIGH, MEDIUM, LOW) | `CRITICAL,HIGH,MEDIUM,LOW` | No |
| `fail-on-vulnerability` | Fail the build if vulnerabilities are found | `true` | No |
| `fail-on-misconfiguration` | Fail the build if misconfigurations are found | `true` | No |
| `fail-on-secret` | Fail the build if secrets are detected | `true` | No |

### Environment Variables

The following environment variables must be set using GitHub Secrets:

#### Required Variables

- **`NT_API_KEY`**: Your NeoTrack API authentication key
  - **Why needed**: Authenticates your requests to the NeoTrack API
  - **How to get**: Generated in your NeoTrack account settings

- **`NT_SECRET_KEY`**: Your NeoTrack secret key
  - **Why needed**: Provides additional security layer for API authentication
  - **How to get**: Generated alongside your API key in NeoTrack account settings

#### Optional Variables

- **`PROJECT_ID`**: Your unique project identifier from NeoTrack
  - **Why needed**: Associates scan results with your specific project on the NeoTrack platform for better organization and tracking
  - **How to get**: Available in your NeoTrack dashboard after creating a project
  - **Note**: If not provided, scans will still be uploaded but won't be associated with a specific project

- **`DEBUG_MODE`**: Enable detailed debug logging (`true` or `false`)
  - **Why needed**: Helps troubleshoot issues by providing verbose logging
  - **Default**: `false`

## Usage Examples

### Example 1: Basic Security Scan

Scan your repository with default settings:

```yaml
- name: NeoTrack Security Scan
  uses: openpulsetech/neotrak-action@main
  env:
    PROJECT_ID: ${{ secrets.PROJECT_ID }}
    NT_API_KEY: ${{ secrets.NT_API_KEY }}
    NT_SECRET_KEY: ${{ secrets.NT_SECRET_KEY }}
```

### Example 2: Scan with Custom Severity Filter

Only report critical and high severity issues:

```yaml
- name: NeoTrack Security Scan
  uses: openpulsetech/neotrak-action@main
  with:
    severity: 'CRITICAL,HIGH'
    fail-on-vulnerability: 'true'
  env:
    PROJECT_ID: ${{ secrets.PROJECT_ID }}
    NT_API_KEY: ${{ secrets.NT_API_KEY }}
    NT_SECRET_KEY: ${{ secrets.NT_SECRET_KEY }}
```

### Example 3: Scan Specific Directory

Scan only a specific directory in your repository:

```yaml
- name: NeoTrack Security Scan
  uses: openpulsetech/neotrak-action@main
  with:
    scan-target: './src'
  env:
    PROJECT_ID: ${{ secrets.PROJECT_ID }}
    NT_API_KEY: ${{ secrets.NT_API_KEY }}
    NT_SECRET_KEY: ${{ secrets.NT_SECRET_KEY }}
```

### Example 4: Non-blocking Scan (Report Only)

Run scans without failing the build:

```yaml
- name: NeoTrack Security Scan
  uses: openpulsetech/neotrak-action@main
  with:
    fail-on-vulnerability: 'false'
    fail-on-misconfiguration: 'false'
    fail-on-secret: 'false'
  env:
    PROJECT_ID: ${{ secrets.PROJECT_ID }}
    NT_API_KEY: ${{ secrets.NT_API_KEY }}
    NT_SECRET_KEY: ${{ secrets.NT_SECRET_KEY }}
```

### Example 5: Debug Mode Enabled

Enable debug logging for troubleshooting:

```yaml
- name: NeoTrack Security Scan
  uses: openpulsetech/neotrak-action@main
  env:
    PROJECT_ID: ${{ secrets.PROJECT_ID }}
    NT_API_KEY: ${{ secrets.NT_API_KEY }}
    NT_SECRET_KEY: ${{ secrets.NT_SECRET_KEY }}
    DEBUG_MODE: 'true'
```

### Example 6: Complete Production Workflow

A comprehensive setup for production environments:

```yaml
name: Production Security Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 2 * * *'

jobs:
  security-scan:
    name: NeoTrack Security Analysis
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write

    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run NeoTrack Security Scan
        uses: openpulsetech/neotrak-action@main
        with:
          scan-target: '.'
          severity: 'CRITICAL,HIGH,MEDIUM,LOW'
          fail-on-vulnerability: 'true'
          fail-on-misconfiguration: 'true'
          fail-on-secret: 'true'
        env:
          PROJECT_ID: ${{ secrets.PROJECT_ID }}
          NT_API_KEY: ${{ secrets.NT_API_KEY }}
          NT_SECRET_KEY: ${{ secrets.NT_SECRET_KEY }}
          DEBUG_MODE: ${{ secrets.DEBUG_MODE }}

      - name: Upload Security Report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: neotrak-security-report
          path: neotrak-report.json
          retention-days: 30
```

## How to Add Environment Variables

### Method 1: Repository Secrets (Recommended)

1. Navigate to your GitHub repository
2. Click on **Settings** tab
3. In the left sidebar, click **Secrets and variables** → **Actions**
4. Click **New repository secret** button
5. For each required secret:
   - **Name**: Enter the secret name exactly as shown (e.g., `PROJECT_ID`)
   - **Value**: Paste the value from your NeoTrack dashboard
   - Click **Add secret**

### Method 2: Environment Secrets (For Organization-wide use)

1. Go to your Organization settings
2. Click **Secrets and variables** → **Actions**
3. Click **New organization secret**
4. Add the secrets and select which repositories can access them

### Method 3: Environment-specific Secrets

1. In your repository, go to **Settings** → **Environments**
2. Create or select an environment (e.g., "production", "staging")
3. Add environment-specific secrets
4. Update your workflow to reference the environment:

```yaml
jobs:
  security-scan:
    runs-on: ubuntu-latest
    environment: production  # Add this line
    steps:
      # ... rest of your workflow
```

## Understanding the Scan Results

The action generates comprehensive security reports including:

### Vulnerability Report
- Lists all detected vulnerabilities with severity levels
- Shows affected packages and available fixes
- Provides CVE identifiers for tracking

### Misconfiguration Report
- Identifies security misconfigurations in:
  - Docker files
  - Kubernetes manifests
  - Terraform files
  - Cloud configuration files
  - Application configuration

### Secret Detection Report
- Detects exposed secrets including:
  - API keys
  - Access tokens
  - Private keys
  - Database credentials
  - Cloud provider credentials

### SBOM (Software Bill of Materials)
- Complete inventory of software components
- Dependency relationships
- License information
- Version tracking

## Viewing Results

Scan results are available in multiple locations:

1. **GitHub Actions Log**: View detailed results in the workflow run logs
2. **Pull Request Comments**: Automated comments on PRs with security findings
3. **NeoTrack Dashboard**: Centralized view of all scans at [https://beta.neoTrak.io](https://beta.neoTrak.io)
4. **Artifacts**: Download detailed reports from the Actions artifacts

## Troubleshooting

### Common Issues

#### 1. Authentication Failures
**Error**: `Upload failed: 401 Unauthorized`

**Solution**:
- Verify that `PROJECT_ID`, `NT_API_KEY`, and `NT_SECRET_KEY` are correctly set in GitHub Secrets
- Ensure the secrets are not expired
- Check that you're using the correct project ID

#### 2. Timeout Issues
**Error**: `ETIMEDOUT` or `ECONNABORTED`

**Solution**:
- The action automatically retries up to 3 times
- Check your network connectivity
- Verify the NeoTrack API endpoint is accessible

#### 3. SBOM File Not Found
**Error**: `SBOM file not found — skipping upload`

**Solution**:
- Ensure your project has dependencies to scan
- Check that the scan-target path is correct
- Verify the project contains recognizable package files (package.json, requirements.txt, etc.)

#### 4. Missing Environment Variables
**Error**: Variables not found or undefined

**Solution**:
- Double-check the secret names match exactly (case-sensitive)
- Ensure secrets are added to the correct repository
- Verify the workflow has permission to access the secrets

### Debug Mode

Enable debug mode to get detailed logs:

```yaml
env:
  DEBUG_MODE: 'true'
```

This will output:
- Detailed request/response information
- File processing details
- Scanner execution logs
- API communication details

## Security Best Practices

1. **Never commit secrets**: Always use GitHub Secrets for sensitive data
2. **Use branch protection**: Require security scans to pass before merging
3. **Schedule regular scans**: Set up cron jobs to scan daily or weekly
4. **Review findings promptly**: Address critical and high severity issues quickly
5. **Keep dependencies updated**: Regularly update to patch vulnerabilities

## Why Use NeoTrack Action?

### Centralized Security Management
- All scan results are uploaded to your NeoTrack dashboard
- Track security trends over time
- Compare security posture across multiple projects

### Comprehensive Coverage
- Multiple scanning engines in one action
- Covers vulnerabilities, misconfigurations, and secrets
- Generates SBOM for compliance requirements

### Flexible Configuration
- Choose which types of issues should fail the build
- Configure severity thresholds
- Scan specific directories or entire repository

### Automated Workflow
- Integrates seamlessly with GitHub Actions
- Automatic PR comments for security findings
- Schedule regular security scans

## Support

- **Documentation**: [NeoTrack Documentation](https://beta.neoTrak.io/docs)
- **Issues**: [GitHub Issues](https://github.com/openpulsetech/neotrak-action/issues)
- **Email**: support@neotrak.io

## License

MIT License - see LICENSE file for details

## Contributing

Contributions are welcome! Please read our contributing guidelines before submitting pull requests.

---

**Made with care by the NeoTrack Security Team**    