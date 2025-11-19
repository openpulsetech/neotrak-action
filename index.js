const core = require('@actions/core');
const github = require('@actions/github');
const trivyScanner = require('./scanners/trivy');
const cdxgenScanner = require('./scanners/sbom');
const secretDetectorScanner = require('./scanners/secret-detector');
const configScanner = require('./scanners/config');
const path = require('path');

const axios = require('axios');
const FormData = require('form-data');
const fs = require('fs');

class SecurityOrchestrator {
  constructor() {
    this.scanners = [];
    this.results = {
      total: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      scannerResults: []
    };
    this.debugMode = process.env.DEBUG_MODE === 'true';
  }

  /**
   * Log message only if debug mode is enabled
   */
  debugLog(message) {
    if (this.debugMode) {
      core.info(message);
    }
  }

  /**
  * Get the workspace directory (the calling project's directory)
  */
  getWorkspaceDirectory() {
    // GitHub Actions sets GITHUB_WORKSPACE to the repository directory
    const workspace = process.env.GITHUB_WORKSPACE || process.cwd();
    core.info(`🏠 Workspace directory: ${workspace}`);
    return workspace;
  }

  /**
   * Register a scanner module
   */
  registerScanner(scanner) {
    this.scanners.push(scanner);
    core.info(`📦 Registered scanner: ${scanner.name}`);
  }

  /**
   * Initialize all scanners
   */
  async initializeScanners() {
    core.startGroup('🔧 neotrak Scanner Setup');

    for (const scanner of this.scanners) {
      try {
        core.info(`Installing ${scanner.name}...`);
        await scanner.install();
        core.info(`✅ ${scanner.name} installed successfully`);
      } catch (error) {
        core.warning(`Failed to install ${scanner.name}: ${error.message}`);
      }
    }

    core.endGroup();
  }

  /**
   * Run all registered scanners
   */
  async runScans() {
    core.startGroup('🔍 neotrak Scan');

    const scanType = core.getInput('scan-type') || 'fs';
    const scanTarget = core.getInput('scan-target') || '.';
    const severity = core.getInput('severity') || 'CRITICAL,HIGH,MEDIUM,LOW';  // Include all severities
    const ignoreUnfixed = core.getInput('ignore-unfixed') === 'true';


    // Get the workspace directory and resolve the scan target relative to it
    const workspaceDir = this.getWorkspaceDirectory();
    const resolvedTarget = path.isAbsolute(scanTarget)
      ? scanTarget
      : path.resolve(workspaceDir, scanTarget);

    core.info(`📍 Target: ${scanTarget}`);
    core.info(`🎯 Scan Type: ${scanType}`);
    core.info(`⚠️  Severity Filter: ${severity}`);

    const scanConfig = {
      scanType,
      scanTarget,
      severity,
      ignoreUnfixed,
      format: core.getInput('format') || 'table',
      exitCode: core.getInput('exit-code') || '1',
      workspaceDir
    };

    for (const scanner of this.scanners) {
      try {
        core.info(`\n▶️  Running ${scanner.name}...`);
        const result = await scanner.scan(scanConfig);

        if (result) {
          this.aggregateResults(result);
          this.results.scannerResults.push({
            scanner: scanner.name,
            ...result
          });
        }
      } catch (error) {
        core.warning(`${scanner.name} scan failed: ${error.message}`);
      }
    }

    core.endGroup();
  }

  /**
   * Aggregate results from multiple scanners
   */
  aggregateResults(scanResult) {
    this.results.total += scanResult.total || 0;
    this.results.critical += scanResult.critical || 0;
    this.results.high += scanResult.high || 0;
    this.results.medium += scanResult.medium || 0;
    this.results.low += scanResult.low || 0;
  }

    /**
   * Upload combined scan results (config + secrets) + SBOM file
   */
  async uploadCombinedResults(projectId, configResult, secretResult) {
    const maxRetries = 3;
    const retryDelay = 5000; // 5 seconds base delay
    let lastError = null;

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        const apiEndpoint = core.getInput('api_endpoint');
        const apiUrl = projectId
          ? `${apiEndpoint}/open-pulse/project/upload-all/${projectId}`
          : `${apiEndpoint}/open-pulse/project/upload-all`;
        core.info(`📤 Preparing upload to: ${apiUrl} (Attempt ${attempt}/${maxRetries})`);

        if (attempt > 1) {
          const delay = retryDelay * attempt;
          core.info(`⏳ Retry attempt ${attempt}/${maxRetries} after ${delay/1000}s delay...`);
          await new Promise(resolve => setTimeout(resolve, delay));
        }

        // ✅ 1. Build CombinedScanRequest JSON structure matching API DTOs
        const combinedScanRequest = {
          configScanResponseDto: configResult?.configScanResponseDto || {
            ArtifactName: '',
            ArtifactType: '',
            Results: []
          },
          scannerSecretResponse: (secretResult?.secrets || []).map(item => ({
            RuleID: item.RuleID || '',
            Description: item.Description || '',
            File: item.File || '',
            Match: item.Match || '',
            Secret: item.Secret || '',
            StartLine: item.StartLine || '',
            EndLine: item.EndLine || '',
            StartColumn: item.StartColumn || '',
            EndColumn: item.EndColumn || ''
          }))
        };

        // ✅ 2. Get SBOM file from Trivy/CDXGen result
        const sbomPath = this.getTrivySbomResult()?.sbomPath;
        if (!sbomPath || !fs.existsSync(sbomPath)) {
          core.warning('⚠️ SBOM file not found — skipping upload.');
          return;
        }

        // ✅ 3. Prepare multipart form-data
        const formData = new FormData();
        formData.append('combinedScanRequest', JSON.stringify(combinedScanRequest), {
          contentType: 'application/json'
        });
        formData.append('sbomFile', fs.createReadStream(sbomPath));
        formData.append('displayName', process.env.DISPLAY_NAME || 'sbom');

        // Get branch name from GitHub context
        // For pull requests, use the head branch; otherwise use ref
        const branchName = github.context.payload.pull_request?.head?.ref
          || github.context.ref.replace('refs/heads/', '').replace('refs/tags/', '')
          || process.env.BRANCH_NAME
          || 'main';

        // Get repository name from GitHub context
        const repoName = github.context.payload.repository?.name
          || github.context.repo.repo
          || process.env.GITHUB_REPOSITORY?.split('/')[1]
          || 'unknown-repo';

        core.info(`🌿 Running action on branch: ${branchName}`);
        core.info(`📦 Repository name: ${repoName}`);
        formData.append('branchName', branchName);
        formData.append('repoName', repoName);
        if (process.env.CICD_SOURCE) formData.append('source', process.env.CICD_SOURCE || 'github');
        if (process.env.JOB_ID) formData.append('jobId', process.env.JOB_ID);

        // ✅ 4. Headers (if authentication is used)
        const headers = {
          ...formData.getHeaders(),
          'x-api-key': process.env.X_API_KEY || '',
          'x-secret-key': process.env.X_SECRET_KEY || '',
          'x-tenant-key': process.env.X_TENANT_KEY || ''
        };

        // ✅ 5. Print request details (only on first attempt)
        if (attempt === 1) {
          this.debugLog('📋 Request Details:');
          this.debugLog(`URL: ${apiUrl}`);
          this.debugLog(`Headers: ${JSON.stringify(headers, null, 2)}`);
          this.debugLog(`FormData fields: ${JSON.stringify({
            combinedScanRequest: 'JSON string (see below)',
            sbomFile: sbomPath,
            displayName: process.env.DISPLAY_NAME || 'sbom',
            branchName: branchName,
            repoName: repoName,
            source: 'github' || 'not set',
            jobId: process.env.JOB_ID || 'not set'

          }, null, 2)}`);
          this.debugLog(`\n📦 CombinedScanRequest Structure:`);
          this.debugLog(`  - configScanResponseDto:`);
          this.debugLog(`      ArtifactName: ${combinedScanRequest.configScanResponseDto.ArtifactName}`);
          this.debugLog(`      ArtifactType: ${combinedScanRequest.configScanResponseDto.ArtifactType}`);
          this.debugLog(`      Results count: ${combinedScanRequest.configScanResponseDto.Results?.length || 0}`);

          // Count total misconfigurations across all results
          const totalMisconfigs = combinedScanRequest.configScanResponseDto.Results?.reduce((sum, result) => {
            return sum + (result.Misconfigurations?.length || 0);
          }, 0) || 0;
          this.debugLog(`      Total Misconfigurations: ${totalMisconfigs}`);

          // Log each result file and its misconfiguration count
          combinedScanRequest.configScanResponseDto.Results?.forEach((result, idx) => {
            this.debugLog(`      Result ${idx + 1}: ${result.Target} (${result.Misconfigurations?.length || 0} issues)`);
          });

          this.debugLog(`  - scannerSecretResponse count: ${combinedScanRequest.scannerSecretResponse?.length || 0}`);
          this.debugLog(`\n📋 Full CombinedScanRequest JSON:`);
          this.debugLog(JSON.stringify(combinedScanRequest, null, 2));
        }

        // ✅ 6. Send POST request with extended timeout
        core.info('⏳ Sending request to API (this may take a few minutes)...');
        const response = await axios.post(apiUrl, formData, {
          headers,
          maxBodyLength: Infinity,
          timeout: 300000  // Increased to 5 minutes (300 seconds)
        });

        core.info(`✅ Upload successful: ${response.status} ${response.statusText}`);
        core.info(`Response Data: ${JSON.stringify(response.data)}`);
        return; // Success - exit the retry loop

      } catch (error) {
        lastError = error;
        const isRetryable = error.code === 'ETIMEDOUT' ||
                           error.code === 'ECONNABORTED' ||
                           error.code === 'ECONNRESET' ||
                           error.code === 'ENOTFOUND';

        core.error(`❌ Upload failed (Attempt ${attempt}/${maxRetries}): ${error.message}`);

        if (error.code === 'ETIMEDOUT') {
          core.error('🔌 Connection timed out. The server at 174.138.122.245:443 is not responding.');
          core.error('💡 Possible causes:');
          core.error('   - Server is down or unreachable');
          core.error('   - Firewall blocking GitHub Actions IP addresses');
          core.error('   - Network connectivity issues');
        } else if (error.code === 'ECONNABORTED') {
          core.error('⏱️  The request timed out. The API server may be processing a large SBOM file.');
        }

        if (error.response) {
          core.error(`Response Status: ${error.response.status}`);
          core.error(`Response Data: ${JSON.stringify(error.response.data)}`);
        } else if (error.request) {
          core.error('No response received from server. The request was made but no response was received.');
        }

        // If this is the last attempt or error is not retryable, break
        if (attempt >= maxRetries || !isRetryable) {
          core.error('❌ All retry attempts exhausted or non-retryable error occurred.');
          break;
        }

        core.info(`🔄 Will retry in ${(retryDelay * (attempt + 1)) / 1000}s...`);
      }
    }

    // If we get here, all retries failed
    core.warning('⚠️ Upload failed but continuing workflow...');
    if (lastError) {
      core.error(`Final error: ${lastError.message}`);
    }
  }

  getTrivySbomResult() {
    return this.results.scannerResults.find(
      r => r.scanner && r.scanner.toLowerCase().includes('sbom') 
      && !r.scanner.toLowerCase().includes('config')
    );
  }

   getConfigResult() {
    return this.results.scannerResults.find(
      r => r.scanner && r.scanner.toLowerCase().includes('config')
    );
  }

  getSecretResult() {
    return this.results.scannerResults.find(
      r => r.scanner && r.scanner.toLowerCase().includes('secret')
    );
  }

  /**
   * Wrap text to fit within a column width
   * Keeps content on first line if it fits, splits at comma or space for overflow
   */
  wrapText(text, width) {
    if (!text || text.length <= width) {
      return [text || ''];
    }

    const lines = [];

    // If text contains commas (like version lists), split by comma
    if (text.includes(',')) {
      let currentLine = '';
      const parts = text.split(',').map(p => p.trim());

      for (let i = 0; i < parts.length; i++) {
        const part = parts[i] + (i < parts.length - 1 ? ',' : '');
        const testLine = currentLine ? currentLine + ' ' + part : part;

        if (testLine.length <= width) {
          currentLine = testLine;
        } else {
          if (currentLine) {
            lines.push(currentLine);
            currentLine = part;
          } else {
            // Part is too long, truncate it
            lines.push(part.substring(0, width));
            currentLine = '';
          }
        }
      }

      if (currentLine) {
        lines.push(currentLine);
      }
    } else {
      // Split by words for non-comma separated text
      let currentLine = '';
      const words = text.split(' ');

      for (const word of words) {
        const testLine = currentLine ? currentLine + ' ' + word : word;

        if (testLine.length <= width) {
          currentLine = testLine;
        } else {
          if (currentLine) {
            lines.push(currentLine);
            currentLine = word;
          } else {
            // Word is too long, truncate it
            lines.push(word.substring(0, width));
            currentLine = word.substring(width);
          }
        }
      }

      if (currentLine) {
        lines.push(currentLine);
      }
    }

    return lines.length > 0 ? lines : [''];
  }

  createTableBorder(colWidths) {
    const top = '┌' + Object.values(colWidths).map(w => '─'.repeat(w)).join('┬') + '┐';
    const middle = '├' + Object.values(colWidths).map(w => '─'.repeat(w)).join('┼') + '┤';
    const bottom = '└' + Object.values(colWidths).map(w => '─'.repeat(w)).join('┴') + '┘';
    return { top, middle, bottom };
  }

  displayVulnerabilityTable(trivySbomResult) {
    if (!trivySbomResult || !trivySbomResult.vulnerabilities || trivySbomResult.vulnerabilities.length === 0) {
      return;
    }

    core.info('\n📋 Vulnerability Details:\n');
    
    const colWidths = {
      package: 45,
      vuln: 22,
      severity: 14,
      fixed: 25
    };
    
    const borders = this.createTableBorder(colWidths);
    
    // Table header
    core.info(borders.top);
    const header = '│ ' + 'Package'.padEnd(colWidths.package - 2) + ' │ ' +
                  'Vulnerability'.padEnd(colWidths.vuln - 2) + ' │ ' +
                  'Severity'.padEnd(colWidths.severity - 2) + ' │ ' +
                  'Fixed Version'.padEnd(colWidths.fixed - 2) + ' │';
    core.info(header);
    core.info(borders.middle);

    const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
    const severityEmojis = {
      'CRITICAL': '🔴',
      'HIGH': '🟠',
      'MEDIUM': '🟡',
      'LOW': '🟢'
    };
    
    severities.forEach(severity => {
      const vulnsOfSeverity = trivySbomResult.vulnerabilities.filter(
        v => (v.Severity || '').toUpperCase() === severity
      );

      vulnsOfSeverity.forEach(vuln => {
        const emoji = severityEmojis[severity] || '';

        // Wrap text for each column
        const pkgLines = this.wrapText(vuln.PkgName || 'Unknown', colWidths.package - 2);
        const vulnLines = this.wrapText(vuln.VulnerabilityID || 'N/A', colWidths.vuln - 2);
        const sevLines = this.wrapText(emoji + ' ' + severity, colWidths.severity - 2);
        const fixedLines = this.wrapText(vuln.FixedVersion || 'N/A', colWidths.fixed - 2);

        // Find the maximum number of lines needed
        const maxLines = Math.max(pkgLines.length, vulnLines.length, sevLines.length, fixedLines.length);

        // Print each line of the row
        for (let i = 0; i < maxLines; i++) {
          const pkg = (pkgLines[i] || '').padEnd(colWidths.package - 2);
          const vulnId = (vulnLines[i] || '').padEnd(colWidths.vuln - 2);
          const sev = (sevLines[i] || '').padEnd(colWidths.severity - 2);
          const fixed = (fixedLines[i] || '').padEnd(colWidths.fixed - 2);

          const row = '│ ' + pkg + ' │ ' + vulnId + ' │ ' + sev + ' │ ' + fixed + ' │';
          core.info(row);
        }
      });
    });
    
    core.info(borders.bottom);
  }

  displayConfigTable(configResult) {
    if (!configResult || !configResult.misconfigurations || configResult.misconfigurations.length === 0) {
      return;
    }

    core.info('\n📋 Misconfiguration Details:\n');
    
    const colWidths = {
      file: 50,
      issue: 35,
      severity: 12,
      line: 10
    };
    
    const borders = this.createTableBorder(colWidths);
    
    // Table header
    core.info(borders.top);
    const header = '│ ' + 'File'.padEnd(colWidths.file - 2) + ' │ ' +
                  'Issue'.padEnd(colWidths.issue - 2) + ' │ ' +
                  'Severity'.padEnd(colWidths.severity - 2) + ' │ ' +
                  'Line'.padEnd(colWidths.line - 2) + ' │';
    core.info(header);
    core.info(borders.middle);

    const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
    const severityEmojis = {
      'CRITICAL': '🔴',
      'HIGH': '🟠',
      'MEDIUM': '🟡',
      'LOW': '🟢'
    };
    severities.forEach(severity => {
      const configsOfSeverity = configResult.misconfigurations.filter(
        c => (c.Severity || '').toUpperCase() === severity
      );

      configsOfSeverity.forEach(config => {
        const emoji = severityEmojis[severity] || '';

        // Wrap text for each column
        const fileLines = this.wrapText(config.File || 'Unknown', colWidths.file - 2);
        const issueLines = this.wrapText(config.Issue || config.Title || 'N/A', colWidths.issue - 2);
        const sevLines = this.wrapText(emoji + ' ' + severity, colWidths.severity - 2);
        const lineLines = this.wrapText((config.Line || 'N/A').toString(), colWidths.line - 2);

        // Find the maximum number of lines needed
        const maxLines = Math.max(fileLines.length, issueLines.length, sevLines.length, lineLines.length);

        // Print each line of the row
        for (let i = 0; i < maxLines; i++) {
          const file = (fileLines[i] || '').padEnd(colWidths.file - 2);
          const issue = (issueLines[i] || '').padEnd(colWidths.issue - 2);
          const sev = (sevLines[i] || '').padEnd(colWidths.severity - 2);
          const line = (lineLines[i] || '').padEnd(colWidths.line - 2);

          const row = '│ ' + file + ' │ ' + issue + ' │ ' + sev + ' │ ' + line + ' │';
          core.info(row);
        }
      });
    });
    
    core.info(borders.bottom);
  }

  displaySecretTable(secretResult) {
    if (!secretResult || !secretResult.secrets || secretResult.secrets.length === 0) {
      return;
    }

    core.info('\n📋 Secret Details:\n');
    
    const colWidths = {
      file: 70,
      line: 10,
      matched: 25
    };
    
    const borders = this.createTableBorder(colWidths);
    
    // Table header
    core.info(borders.top);
    const header = '│ ' + 'File'.padEnd(colWidths.file - 2) + ' │ ' +
                  'Line'.padEnd(colWidths.line - 2) + ' │ ' +
                  'Matched Secret'.padEnd(colWidths.matched - 2) + ' │';
    core.info(header);
    core.info(borders.middle);

    secretResult.secrets.forEach(secret => {
      const cleanFile = (secret.File || 'Unknown').replace(/^\/+/, '');
      const file = cleanFile.substring(0, colWidths.file - 3);
      const line = (secret.StartLine || secret.Line || 'N/A').toString().substring(0, colWidths.line - 3);
      const matched = (secret.Match || 'N/A').substring(0, colWidths.matched - 3);
      
      const row = '│ ' + file.padEnd(colWidths.file - 2) + ' │ ' +
                 line.padEnd(colWidths.line - 2) + ' │ ' +
                 matched.padEnd(colWidths.matched - 2) + ' │';
      core.info(row);
    });
    
    core.info(borders.bottom);
  }

  /**
   * Display consolidated results
   */
  displayResults() {
    core.startGroup('📊 neotrak Scan Results');

    core.info('='.repeat(50));
    core.info('CONSOLIDATED VULNERABILITY REPORT');
    core.info('='.repeat(50));
  
    // Find Trivy scanner result
    const trivySbomResult = this.getTrivySbomResult();

    if (trivySbomResult) {
      core.info(`   Total Vulnerabilities: ${trivySbomResult.total}`);
      core.info(`   🔴 Critical: ${trivySbomResult.critical}`);
      core.info(`   🟠 High: ${trivySbomResult.high}`);
      core.info(`   🟡 Medium: ${trivySbomResult.medium}`);
      core.info(`   🟢 Low: ${trivySbomResult.low}`);

      // Display vulnerability details in pretty table format
      this.displayVulnerabilityTable(trivySbomResult);
    } else {
      core.info('   ⚠️ No vulnerability scan results found.');
    }

    core.info('='.repeat(50));

    // Find Config scanner result
    const configResult = this.getConfigResult();
    if (configResult) {
      core.info('📋 CONFIG SCANNER RESULTS');
      core.info(`   Total Misconfigurations: ${configResult.total}`);
      core.info(`   🔴 Critical: ${configResult.critical}`);
      core.info(`   🟠 High: ${configResult.high}`);
      core.info(`   🟡 Medium: ${configResult.medium}`);
      core.info(`   🟢 Low: ${configResult.low}`);
      core.info(`   Total Config Files Scanned: ${configResult.totalFiles}`);
  
      this.displayConfigTable(configResult);
    } else {
      core.info('   ⚠️ No Config scan results found.');
    }

    core.info('='.repeat(50));

    // Find Secret scanner result
    const secretResult = this.getSecretResult();
    if (secretResult) {
      core.info('🔐 SECRET SCANNER RESULTS');
      core.info(`   Total Secrets Detected: ${secretResult.total}`);
      this.displaySecretTable(secretResult);
    } else {
      core.info('   ⚠️ No Secret scan results found.');
    }

    core.info('='.repeat(50));

    core.endGroup();
  }

  /**
   * Set GitHub Action outputs
   */
  setOutputs() {
    core.setOutput('vulnerabilities-found', this.results.total);
    core.setOutput('critical-count', this.results.critical);
    core.setOutput('high-count', this.results.high);
    core.setOutput('scan-result',
      `Found ${this.results.total} vulnerabilities: ` +
      `${this.results.critical} Critical, ${this.results.high} High, ` +
      `${this.results.medium} Medium, ${this.results.low} Low`
    );
  }

  /**
   * Post results to PR if applicable
   */
  async postPRComment() {
    const githubToken = core.getInput('github-token');

    if (!githubToken || github.context.eventName !== 'pull_request') {
      return;
    }

    try {
      const octokit = github.getOctokit(githubToken);
      const context = github.context;

      const status = (this.results.critical > 0 || this.results.high > 0)
        ? '🔴 VULNERABILITIES DETECTED'
        : '✅ NO CRITICAL ISSUES';
      const emoji = (this.results.critical > 0 || this.results.high > 0) ? '⚠️' : '✅';

      let scannerBreakdown = '';
      if (this.results.scannerResults.length > 1) {
        scannerBreakdown = '\n### Scanner Breakdown\n\n';
        this.results.scannerResults.forEach(result => {
          scannerBreakdown += `**${result.scanner}**: ${result.total} issues ` +
            `(${result.critical} Critical, ${result.high} High)\n`;
        });
      }

      const comment = `## ${emoji} Security Scan Report

**Status:** ${status}

### Consolidated Vulnerability Summary
| Severity | Count |
|----------|-------|
| 🔴 Critical | ${this.results.critical} |
| 🟠 High | ${this.results.high} |
| 🟡 Medium | ${this.results.medium} |
| 🟢 Low | ${this.results.low} |
| **Total** | **${this.results.total}** |
${scannerBreakdown}
${this.results.total > 0 ?
          '⚠️ Please review and address the security vulnerabilities found.' :
          '✨ No security vulnerabilities detected!'}

---
*Security Scan Complete*`;

      await octokit.rest.issues.createComment({
        ...context.repo,
        issue_number: context.issue.number,
        body: comment
      });

      core.info('💬 Posted scan results to PR comment');
    } catch (error) {
      core.warning(`Failed to post PR comment: ${error.message}`);
    }
  }

  /**
   * Determine if workflow should fail
   */
  shouldFail() {
    const failOnVulneribilityInput = core.getInput('fail_on_vulneribility');
    
    // If fail_on_vulneribility is explicitly set to 'false', never fail the build
    if (failOnVulneribilityInput === 'false') {
      return false;
    }

    const exitCode = core.getInput('exit-code') || '1';

    if (exitCode === '0') {
      return false;
    }

    // Get fail-on configuration (default: true for all)
    const failOnVulnerability = core.getInput('fail-on-vulnerability') !== 'false';
    const failOnMisconfiguration = core.getInput('fail-on-misconfiguration') !== 'false';
    const failOnSecret = core.getInput('fail-on-secret') !== 'false';

    // Check each scanner type
    const trivySbomResult = this.getTrivySbomResult();
    const configResult = this.getConfigResult();
    const secretResult = this.getSecretResult();

    let shouldFail = false;
    const failReasons = [];

    // Check vulnerabilities
    if (failOnVulnerability && trivySbomResult && trivySbomResult.total > 0) {
      shouldFail = true;
      failReasons.push(`${trivySbomResult.total} vulnerabilities (${trivySbomResult.critical} Critical, ${trivySbomResult.high} High)`);
    }

    // Check misconfigurations
    if (failOnMisconfiguration && configResult && configResult.total > 0) {
      shouldFail = true;
      failReasons.push(`${configResult.total} misconfigurations (${configResult.critical} Critical, ${configResult.high} High)`);
    }

    // Check secrets
    if (failOnSecret && secretResult && secretResult.total > 0) {
      shouldFail = true;
      failReasons.push(`${secretResult.total} secrets detected`);
    }

    // Store fail reasons for use in error message
    this.failReasons = failReasons;

    return shouldFail;
  }
}

async function run() {
  try {
    const orchestrator = new SecurityOrchestrator();

    // Register scanners
    orchestrator.registerScanner(trivyScanner);
    orchestrator.registerScanner(cdxgenScanner);
    orchestrator.registerScanner(secretDetectorScanner);
    orchestrator.registerScanner(configScanner);
    // Add more scanners here as needed:
    // orchestrator.registerScanner(grypeScanner);
    // orchestrator.registerScanner(snykScanner);

    // Initialize all scanners
    await orchestrator.initializeScanners();

    // Run all scans
    await orchestrator.runScans();

    // Display results
    orchestrator.displayResults();

    // Set outputs
    orchestrator.setOutputs();

    // ✅ Upload results to your backend
    const projectId = process.env.PROJECT_ID;
    const configResult = orchestrator.getConfigResult();
    const secretResult = orchestrator.getSecretResult();

    await orchestrator.uploadCombinedResults(projectId, configResult, secretResult);

    // Post PR comment
    await orchestrator.postPRComment();

    // Check if should fail
    const failOnVulneribilityInput = core.getInput('fail_on_vulneribility');
    const failOnVulneribilityDisabled = failOnVulneribilityInput === 'false';
    
    if (orchestrator.shouldFail()) {
      const failMessage = `Security Scanner found issues:\n  - ${orchestrator.failReasons.join('\n  - ')}`;
      core.setFailed(failMessage);
    } else {
      core.info('✅ Security scan completed successfully');
    }

  } catch (error) {
    core.setFailed(`Security scan failed: ${error.message}`);
  }
}

run();