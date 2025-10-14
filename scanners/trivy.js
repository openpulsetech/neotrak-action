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
        format,
        exitCode,
        ignoreUnfixed
      } = config;
      
      // Build command arguments
      const args = [
        scanType,
        '--severity', severity,
        '--format', format,
        '--exit-code', '0' // Always return 0, we handle failures in orchestrator
      ];
      
      if (ignoreUnfixed) {
        args.push('--ignore-unfixed');
      }
      
      // Create temporary output file for JSON results
      const jsonOutputPath = path.join(os.tmpdir(), 'trivy-scan-results.json');
      args.push('--format', 'json', '--output', jsonOutputPath);
      
      args.push(scanTarget);
      
      // Execute scan
      let output = '';
      let errorOutput = '';
      
      const options = {
        listeners: {
          stdout: (data) => {
            output += data.toString();
          },
          stderr: (data) => {
            errorOutput += data.toString();
          }
        },
        ignoreReturnCode: true,
        silent: true // Suppress command output
      };
      
      await exec.exec(SCANNER_BINARY, args, options);
      
      // Parse results
      const results = this.parseResults(jsonOutputPath);
      
      // Clean up
      if (fs.existsSync(jsonOutputPath)) {
        fs.unlinkSync(jsonOutputPath);
      }
      
      return results;
      
    } catch (error) {
      throw new Error(`Trivy scan failed: ${error.message}`);
    }
  }

  /**
   * Parse Trivy JSON output
   */
  parseResults(jsonPath) {
    try {
      if (!fs.existsSync(jsonPath)) {
        return {
          total: 0,
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          vulnerabilities: []
        };
      }
      
      const jsonContent = fs.readFileSync(jsonPath, 'utf8');
      const data = JSON.parse(jsonContent);
      
      let criticalCount = 0;
      let highCount = 0;
      let mediumCount = 0;
      let lowCount = 0;
      const vulnerabilities = [];
      
      if (data.Results) {
        data.Results.forEach(result => {
          if (result.Vulnerabilities) {
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
          }
        });
      }
      
      const totalCount = criticalCount + highCount + mediumCount + lowCount;
      
      // Log scanner-specific results
      core.info(`   Found ${totalCount} vulnerabilities`);
      core.info(`   🔴 ${criticalCount} Critical | 🟠 ${highCount} High | 🟡 ${mediumCount} Medium | 🟢 ${lowCount} Low`);
      
      return {
        total: totalCount,
        critical: criticalCount,
        high: highCount,
        medium: mediumCount,
        low: lowCount,
        vulnerabilities
      };
      
    } catch (error) {
      core.warning(`Failed to parse Trivy results: ${error.message}`);
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
