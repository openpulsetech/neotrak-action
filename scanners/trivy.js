const core = require('@actions/core');
const exec = require('@actions/exec');
const tc = require('@actions/tool-cache');
const fs = require('fs');
const os = require('os');
const path = require('path');

// Trivy scanner configuration
const TRIVY_VERSION = 'v0.48.0';
const SCANNER_BINARY = 'ntu-scanner-trivy';

class TrivyScanner {
  constructor() {
    this.name = 'Trivy Vulnerability Scanner';
    this.binaryPath = null;
  }

  /**
   * Install Trivy scanner
   */
  async install() {
    try {
      // Set up GitHub Actions environment variables for local testing
      this.setupLocalEnvironment();
      
      const platform = os.platform();
      const arch = os.arch() === 'x64' ? 'amd64' : os.arch();
      
      let downloadUrl;
      
      if (platform === 'linux') {
        downloadUrl = `https://github.com/aquasecurity/trivy/releases/download/${TRIVY_VERSION}/trivy_${TRIVY_VERSION.replace('v', '')}_Linux-${arch === 'amd64' ? '64bit' : 'ARM64'}.tar.gz`;
      } else if (platform === 'darwin') {
        downloadUrl = `https://github.com/aquasecurity/trivy/releases/download/${TRIVY_VERSION}/trivy_${TRIVY_VERSION.replace('v', '')}_macOS-${arch === 'amd64' ? '64bit' : 'ARM64'}.tar.gz`;
      } else if (platform === 'win32') {
        downloadUrl = `https://github.com/aquasecurity/trivy/releases/download/${TRIVY_VERSION}/trivy_${TRIVY_VERSION.replace('v', '')}_windows-${arch === 'amd64' ? '64bit' : 'ARM64'}.zip`;
      }
      
      core.debug(`Downloading from: ${downloadUrl}`);
      const downloadPath = await tc.downloadTool(downloadUrl);
      
      let extractedPath;
      if (platform === 'win32') {
        extractedPath = await tc.extractZip(downloadPath);
      } else {
        extractedPath = await tc.extractTar(downloadPath);
      }
      
      // Rename binary to hide Trivy branding
      const originalBinary = platform === 'win32' ? 'trivy.exe' : 'trivy';
      const newBinary = platform === 'win32' ? `${SCANNER_BINARY}.exe` : SCANNER_BINARY;
      
      const trivyPath = path.join(extractedPath, originalBinary);
      const scannerPath = path.join(extractedPath, newBinary);
      
      if (fs.existsSync(trivyPath)) {
        fs.renameSync(trivyPath, scannerPath);
      }
      
      // Make executable on Unix systems
      if (platform !== 'win32') {
        fs.chmodSync(scannerPath, '755');
      }
      
      // Add to PATH
      const cachedPath = await tc.cacheDir(
        path.dirname(scannerPath), 
        'ntu-scanner-trivy', 
        TRIVY_VERSION
      );
      core.addPath(cachedPath);
      
      this.binaryPath = path.join(cachedPath, newBinary);
      
      return this.binaryPath;
      
    } catch (error) {
      throw new Error(`Failed to install Trivy: ${error.message}`);
    }
  }

  /**
   * Set up local environment for testing
   */
  setupLocalEnvironment() {
    // Set required GitHub Actions environment variables for local testing
    if (!process.env.RUNNER_TEMP) {
      process.env.RUNNER_TEMP = os.tmpdir();
    }
    if (!process.env.RUNNER_TOOL_CACHE) {
      process.env.RUNNER_TOOL_CACHE = path.join(os.homedir(), '.cache', 'actions');
    }
    if (!process.env.RUNNER_WORKSPACE) {
      process.env.RUNNER_WORKSPACE = process.cwd();
    }
    if (!process.env.GITHUB_WORKSPACE) {
      process.env.GITHUB_WORKSPACE = process.cwd();
    }
    
    // Ensure cache directory exists
    if (!fs.existsSync(process.env.RUNNER_TOOL_CACHE)) {
      fs.mkdirSync(process.env.RUNNER_TOOL_CACHE, { recursive: true });
    }
    
    core.debug(`Local environment setup: RUNNER_TEMP=${process.env.RUNNER_TEMP}`);
    core.debug(`Local environment setup: RUNNER_TOOL_CACHE=${process.env.RUNNER_TOOL_CACHE}`);
  }

  /**
   * Run Trivy scan
   */
  async scan(config) {
    try {
      const {
        scanType,
        scanTarget,
        severity,
        ignoreUnfixed
      } = config;
      
      // Validate scan target exists
      if (!fs.existsSync(scanTarget)) {
        throw new Error(`Scan target does not exist: ${scanTarget}`);
      }
      
      // Convert severity to uppercase (Trivy expects uppercase)
      const severityUpper = severity.toUpperCase();
      
      core.info(`🔍 Scanning: ${scanTarget}`);
      core.info(`🎯 Scan Type: ${scanType}`);
      core.info(`⚠️  Severity: ${severityUpper}`);
      
      // Create temporary output file for JSON results
      const jsonOutputPath = path.join(os.tmpdir(), `trivy-scan-results-${Date.now()}.json`);
      
      // Build command arguments
      const args = [
        scanType,
        '--severity', severityUpper,
        '--format', 'json',
        '--output', jsonOutputPath,
        '--exit-code', '0', // Always return 0, we handle failures in orchestrator
        '--quiet' // Reduce noise
      ];
      
      if (ignoreUnfixed) {
        args.push('--ignore-unfixed');
      }
      
      // Add skip dirs to avoid scanning action's own files
      args.push('--skip-dirs', 'node_modules,.git,.github');
      
      args.push(scanTarget);
      
      core.info(`📝 Running: ${SCANNER_BINARY} ${args.join(' ')}`);
      
      // Execute scan
      let stdoutOutput = '';
      let stderrOutput = '';
      
      const options = {
        listeners: {
          stdout: (data) => {
            stdoutOutput += data.toString();
          },
          stderr: (data) => {
            stderrOutput += data.toString();
          }
        },
        ignoreReturnCode: true,
        cwd: path.dirname(scanTarget)
      };
      
      const exitCode = await exec.exec(SCANNER_BINARY, args, options);
      
      core.info(`✅ Scan completed with exit code: ${exitCode}`);
      
      // Log any stderr (but not as error if exit code is 0)
      if (stderrOutput && exitCode !== 0) {
        core.warning(`Stderr output: ${stderrOutput}`);
      }
      
      // Parse results
      core.info(`📄 Reading results from: ${jsonOutputPath}`);
      
      // Check if file was created
      if (!fs.existsSync(jsonOutputPath)) {
        core.error(`❌ Output file was not created: ${jsonOutputPath}`);
        core.error(`Stdout: ${stdoutOutput}`);
        core.error(`Stderr: ${stderrOutput}`);
        throw new Error('Trivy did not produce output file');
      }
      
      const results = this.parseResults(jsonOutputPath);
      
      // Clean up
      try {
        if (fs.existsSync(jsonOutputPath)) {
          fs.unlinkSync(jsonOutputPath);
        }
      } catch (cleanupError) {
        core.debug(`Failed to cleanup temp file: ${cleanupError.message}`);
      }
      
      return results;
      
    } catch (error) {
      core.error(`❌ Trivy scan failed: ${error.message}`);
      core.debug(`Stack: ${error.stack}`);
      throw error;
    }
  }

  /**
   * Parse Trivy JSON output
   */
  parseResults(jsonPath) {
    try {
      if (!fs.existsSync(jsonPath)) {
        core.warning(`⚠️ JSON output file not found: ${jsonPath}`);
        return {
          total: 0,
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          vulnerabilities: []
        };
      }
      
      const stats = fs.statSync(jsonPath);
      core.info(`📊 JSON file size: ${stats.size} bytes`);
      
      const jsonContent = fs.readFileSync(jsonPath, 'utf8');
      
      if (!jsonContent || jsonContent.trim() === '') {
        core.warning('⚠️ JSON output file is empty');
        return {
          total: 0,
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          vulnerabilities: []
        };
      }
      
      core.debug(`First 200 chars of JSON: ${jsonContent.substring(0, 200)}`);
      
      const data = JSON.parse(jsonContent);
      
      let criticalCount = 0;
      let highCount = 0;
      let mediumCount = 0;
      let lowCount = 0;
      const vulnerabilities = [];
      
      // Check if Results exists and has data
      if (data.Results && Array.isArray(data.Results)) {
        core.info(`📦 Processing ${data.Results.length} result(s)`);
        
        data.Results.forEach((result, idx) => {
          core.debug(`Result ${idx + 1}: Type=${result.Type}, Target=${result.Target}`);
          
          if (result.Vulnerabilities && Array.isArray(result.Vulnerabilities)) {
            core.info(`   📋 Result ${idx + 1} (${result.Type || 'unknown'}): ${result.Vulnerabilities.length} vulnerabilities`);
            
            result.Vulnerabilities.forEach(vuln => {
              vulnerabilities.push({
                id: vuln.VulnerabilityID,
                severity: vuln.Severity,
                package: vuln.PkgName,
                version: vuln.InstalledVersion,
                fixedVersion: vuln.FixedVersion,
                title: vuln.Title
              });
              
              switch (vuln.Severity) {
                case 'CRITICAL':
                  criticalCount++;
                  break;
                case 'HIGH':
                  highCount++;
                  break;
                case 'MEDIUM':
                  mediumCount++;
                  break;
                case 'LOW':
                  lowCount++;
                  break;
              }
            });
          } else {
            core.info(`   ✅ Result ${idx + 1} (${result.Type || 'unknown'}): No vulnerabilities`);
          }
        });
      } else {
        core.warning('⚠️ No Results array found in JSON output');
        if (data) {
          core.debug(`JSON keys: ${Object.keys(data).join(', ')}`);
        }
      }
      
      const totalCount = criticalCount + highCount + mediumCount + lowCount;
      
      // Log scanner-specific results
      core.info(`\n✨ Trivy Scan Complete:`);
      core.info(`   📊 Total: ${totalCount} vulnerabilities`);
      core.info(`   🔴 Critical: ${criticalCount}`);
      core.info(`   🟠 High: ${highCount}`);
      core.info(`   🟡 Medium: ${mediumCount}`);
      core.info(`   🟢 Low: ${lowCount}`);
      
      return {
        total: totalCount,
        critical: criticalCount,
        high: highCount,
        medium: mediumCount,
        low: lowCount,
        vulnerabilities
      };
      
    } catch (error) {
      core.error(`❌ Failed to parse Trivy results: ${error.message}`);
      core.debug(`Stack: ${error.stack}`);
      return {
        total: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        vulnerabilities: []
      };
    }
  }
}

// Export singleton instance
module.exports = new TrivyScanner();