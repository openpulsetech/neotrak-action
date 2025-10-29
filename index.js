const core = require('@actions/core');
const github = require('@actions/github');
const trivyScanner = require('./scanners/trivy');
const cdxgenScanner = require('./scanners/sbom');
const secretDetectorScanner = require('./scanners/secret-detector');
const configScanner = require('./scanners/config');
const path = require('path');
// Future scanners can be imported here
// const grypeScanner = require('./scanners/grype');
// const snykScanner = require('./scanners/snyk');

class NTUSecurityOrchestrator {
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
    core.startGroup('🔧 NTU Security Scanner Setup');

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
    core.startGroup('🔍 NTU Security Scan');

    const scanType = core.getInput('scan-type') || 'fs';
    const scanTarget = core.getInput('scan-target') || '.';
    const severity = core.getInput('severity') || 'HIGH,CRITICAL';
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
      package: 35,
      vuln: 22,
      severity: 12,
      fixed: 18
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
        const pkg = (vuln.PkgName || 'Unknown').substring(0, colWidths.package - 3);
        const vulnId = (vuln.VulnerabilityID || 'N/A').substring(0, colWidths.vuln - 3);
        const emoji = severityEmojis[severity] || '';
        const sev = (emoji + ' ' + severity).substring(0, colWidths.severity - 3);
        const fixed = (vuln.FixedVersion || 'N/A').substring(0, colWidths.fixed - 3);
        
        const row = '│ ' + pkg.padEnd(colWidths.package - 2) + ' │ ' +
                   vulnId.padEnd(colWidths.vuln - 2) + ' │ ' +
                   sev.padEnd(colWidths.severity - 2) + ' │ ' +
                   fixed.padEnd(colWidths.fixed - 2) + ' │';
        core.info(row);
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
      file: 30,
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
        const file = (config.File || 'Unknown').substring(0, colWidths.file - 3);
        const issue = (config.Issue || config.Title || 'N/A').substring(0, colWidths.issue - 3);
        const emoji = severityEmojis[severity] || '';
        const sev = (emoji + ' ' + severity).substring(0, colWidths.severity - 3);
        const line = (config.Line || 'N/A').toString().substring(0, colWidths.line - 3);
        
        const row = '│ ' + file.padEnd(colWidths.file - 2) + ' │ ' +
                   issue.padEnd(colWidths.issue - 2) + ' │ ' +
                   sev.padEnd(colWidths.severity - 2) + ' │ ' +
                   line.padEnd(colWidths.line - 2) + ' │';
        core.info(row);
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
      file: 55,
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
    core.startGroup('📊 NTU Security Scan Results');

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
      core.info('   ⚠️ No Trivy results found.');
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

      const comment = `## ${emoji} NTU Security Scan Report

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
*Powered by NTU Security Scanner*`;

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
    const exitCode = core.getInput('exit-code') || '1';

    if (exitCode === '0') {
      return false;
    }

    return this.results.total > 0;
  }
}

async function run() {
  try {
    const orchestrator = new NTUSecurityOrchestrator();

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

    // Post PR comment
    await orchestrator.postPRComment();

    // Check if should fail
    if (orchestrator.shouldFail()) {
      const trivySbomResult = orchestrator.getTrivySbomResult();
     if (trivySbomResult) {
        core.setFailed(
          `NTU Security Scanner found ${trivySbomResult.total} vulnerabilities ` +
          `(${trivySbomResult.critical} Critical, ${trivySbomResult.high} High)`
        );
      } else {
        core.setFailed(
          `NTU Security Scanner found ${orchestrator.results.total} vulnerabilities ` +
          `(${orchestrator.results.critical} Critical, ${orchestrator.results.high} High)`
        );
      }
    } else {
      core.info('✅ Security scan completed successfully');
    }

  } catch (error) {
    core.setFailed(`NTU Security scan failed: ${error.message}`);
  }
}

run();