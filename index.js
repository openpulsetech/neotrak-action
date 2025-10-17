const core = require('@actions/core');
const github = require('@actions/github');
const trivyScanner = require('./scanners/trivy');
const cdxgenScanner = require('./scanners/sbom');
const secretDetectorScanner = require('./scanners/secret-detector');
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

  /**
   * Display consolidated results
   */
  displayResults() {
    core.startGroup('📊 NTU Security Scan Results');
    
    core.info('='.repeat(50));
    core.info('CONSOLIDATED VULNERABILITY REPORT');
    core.info('='.repeat(50));
    core.info(`   Total Vulnerabilities: ${this.results.total}`);
    core.info(`   🔴 Critical: ${this.results.critical}`);
    core.info(`   🟠 High: ${this.results.high}`);
    core.info(`   🟡 Medium: ${this.results.medium}`);
    core.info(`   🟢 Low: ${this.results.low}`);
    core.info('='.repeat(50));
    
    // Display per-scanner breakdown
    if (this.results.scannerResults.length > 1) {
      core.info('\n📋 Scanner Breakdown:');
      this.results.scannerResults.forEach(result => {
        core.info(`\n   ${result.scanner}:`);
        core.info(`      Total: ${result.total}`);
        core.info(`      Critical: ${result.critical}, High: ${result.high}`);
      });
    }
    
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
      core.setFailed(
        `NTU Security Scanner found ${orchestrator.results.total} vulnerabilities ` +
        `(${orchestrator.results.critical} Critical, ${orchestrator.results.high} High)`
      );
    } else {
      core.info('✅ Security scan completed successfully');
    }
    
  } catch (error) {
    core.setFailed(`NTU Security scan failed: ${error.message}`);
  }
}

run();