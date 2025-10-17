const core = require('@actions/core');
const exec = require('@actions/exec');
const os = require('os');
const fs = require('fs');
const path = require('path');
//const axios = require('axios');

const GITLEAKS_VERSION = 'v8.27.2';
const GITLEAKS_BINARY = 'gitleaks';

const skipFiles = [
  'package.json',
  'package-lock.json',
  'pom.xml',
  'build.gradle',
  'requirements.txt',
  'README.md',
  '.gitignore'
];

class SecretDetectorScanner {
  constructor() {
    this.name = 'Secret Detector (Gitleaks)';
    this.binaryPath = null;
  }

  async install() {
    try {
      core.info(`📦 Installing Gitleaks ${GITLEAKS_VERSION}...`);
      
      const platform = os.platform();
      const arch = os.arch() === 'x64' ? 'x64' : 'arm64';
      
      let downloadUrl;
      let fileName;
      let binaryName;
      
      if (platform === 'linux') {
        fileName = `gitleaks_${GITLEAKS_VERSION.substring(1)}_linux_${arch}.tar.gz`;
        downloadUrl = `https://github.com/gitleaks/gitleaks/releases/download/${GITLEAKS_VERSION}/${fileName}`;
        binaryName = 'gitleaks';
      } else if (platform === 'darwin') {
        fileName = `gitleaks_${GITLEAKS_VERSION.substring(1)}_darwin_${arch}.tar.gz`;
        downloadUrl = `https://github.com/gitleaks/gitleaks/releases/download/${GITLEAKS_VERSION}/${fileName}`;
        binaryName = 'gitleaks';
      } else if (platform === 'win32') {
        fileName = `gitleaks_${GITLEAKS_VERSION.substring(1)}_windows_${arch}.zip`;
        downloadUrl = `https://github.com/gitleaks/gitleaks/releases/download/${GITLEAKS_VERSION}/${fileName}`;
        binaryName = 'gitleaks.exe';
      } else {
        throw new Error(`Unsupported platform: ${platform}`);
      }

      core.debug(`Downloading Gitleaks from: ${downloadUrl}`);

      // Use @actions/tool-cache for reliable download and extraction
      const { downloadTool, extractTar, extractZip, cacheDir } = require('@actions/tool-cache');
      
      // Download the file
      const downloadPath = await downloadTool(downloadUrl);
      core.debug(`Downloaded to: ${downloadPath}`);

      // Extract the archive
      let extractedPath;
      if (platform === 'win32') {
        extractedPath = await extractZip(downloadPath);
      } else {
        extractedPath = await extractTar(downloadPath);
      }
      core.debug(`Extracted to: ${extractedPath}`);

      // Find the binary
      const binaryPath = path.join(extractedPath, binaryName);
      if (!fs.existsSync(binaryPath)) {
        throw new Error(`Gitleaks binary not found at: ${binaryPath}`);
      }

      // Make binary executable (for Unix systems)
      if (platform !== 'win32') {
        fs.chmodSync(binaryPath, '755');
      }

      // Cache the binary for reuse
      const cachedPath = await cacheDir(path.dirname(binaryPath), 'gitleaks', GITLEAKS_VERSION);
      this.binaryPath = path.join(cachedPath, binaryName);
      
      // Add to PATH for this session
      const binDir = path.dirname(this.binaryPath);
      process.env.PATH = `${binDir}:${process.env.PATH}`;
      
      core.info(`✅ Gitleaks installed successfully at: ${this.binaryPath}`);
      return this.binaryPath;
    } catch (error) {
      throw new Error(`Failed to install Gitleaks: ${error.message}`);
    }
  }

  // ✅ Stronger regex: avoids matching dummy values like "hello", "test123"
  createCustomRules() {
    return `
[[rules]]
id = "strict-secret-detection"
description = "Detect likely passwords or secrets with high entropy"
regex = '''(?i)(password|passwd|pwd|secret|key|token|auth|access)[\\s"']*[=:][\\s"']*["']([A-Za-z0-9@#\\-_$%!]{10,})["']'''
tags = ["key", "secret", "generic", "password"]

[[rules]]
id = "aws-secret"
description = "AWS Secret Access Key"
regex = '''(?i)aws(.{0,20})?(secret|access)?(.{0,20})?['"][0-9a-zA-Z/+]{40}['"]'''
tags = ["aws", "key", "secret"]

[[rules]]
id = "aws-key"
description = "AWS Access Key ID"
regex = '''AKIA[0-9A-Z]{16}'''
tags = ["aws", "key"]

[[rules]]
id = "github-token"
description = "GitHub Personal Access Token"
regex = '''ghp_[A-Za-z0-9_]{36}'''
tags = ["github", "token"]

[[rules]]
id = "jwt"
description = "JSON Web Token"
regex = '''eyJ[A-Za-z0-9-_]+\\.eyJ[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+'''
tags = ["token", "jwt"]

[[rules]]
id = "firebase-api-key"
description = "Firebase API Key"
regex = '''AIza[0-9A-Za-z\\-_]{35}'''
tags = ["firebase", "apikey"]
`;
  }

  createTempRulesFile() {
    const rulesPath = path.join(os.tmpdir(), 'gitleaks-custom-rules.toml');
    fs.writeFileSync(rulesPath, this.createCustomRules());
    return rulesPath;
  }

  async runGitleaks(scanDir, reportPath, rulesPath) {
    const args = ['detect', '--source', scanDir, '--report-path', reportPath, '--config', rulesPath, '--no-banner'];
    core.debug(`🔍 Running Gitleaks: ${this.binaryPath} ${args.join(' ')}`);

    let stdoutOutput = '';
    let stderrOutput = '';

    const options = {
      listeners: {
        stdout: (data) => { stdoutOutput += data.toString(); },
        stderr: (data) => { stderrOutput += data.toString(); },
      },
      ignoreReturnCode: true,
    };

    const exitCode = await exec.exec(this.binaryPath, args, options);
    core.debug(`Gitleaks STDOUT: ${stdoutOutput}`);
    if (stderrOutput && stderrOutput.trim()) {
      core.warning(`Gitleaks STDERR: ${stderrOutput}`);
    }
    
    return exitCode;
  }

  async checkReport(reportPath) {
    return new Promise((resolve, reject) => {
      fs.readFile(reportPath, 'utf8', (err, data) => {
        if (err) return reject(err);

        try {
          const report = JSON.parse(data);
          resolve(report.length ? report : "No secrets detected.");
        } catch (e) {
          reject(new Error("Invalid JSON in gitleaks report."));
        }
      });
    });
  }

  mapToSBOMSecret(item) {
    const fixedFile = this.fixFilePath(item.File);
    return {
      RuleID: item.RuleID,
      Description: item.Description,
      File: fixedFile,
      Match: item.Match,
      Secret: item.Secret,
      StartLine: String(item.StartLine ?? ''),
      EndLine: String(item.EndLine ?? ''),
      StartColumn: String(item.StartColumn ?? ''),
      EndColumn: String(item.EndColumn ?? ''),
    };
  }

  // Utility to pad File path with dummy segments
  fixFilePath(filePath) {
    if (!filePath) return '///////'; // 7 slashes = 8 empty segments

    let segments = filePath.split('/');
    const requiredSegments = 8;

    // Count only actual segments; empty strings from leading/trailing slashes are valid
    const nonEmptyCount = segments.filter(Boolean).length;

    while (nonEmptyCount + segments.length - nonEmptyCount < requiredSegments) {
      segments.unshift('');
    }

    return segments.join('/');
  }

  async sendSecretsToApi(projectId, secretItems) {
    const apiUrl = `https://dev.neoTrak.io/open-pulse/project/update-secrets/${projectId}`;
    const secretsData = secretItems.map(item => this.mapToSBOMSecret(item));

    const headers = {
      'Content-Type': 'application/json',
    };

    const apiKey = process.env.X_API_KEY;
    const secretKey = process.env.X_SECRET_KEY;
    const tenantKey = process.env.X_TENANT_KEY;

    if (apiKey) headers['x-api-key'] = apiKey;
    if (secretKey) headers['x-secret-key'] = secretKey;
    if (tenantKey) headers['x-tenant-key'] = tenantKey;

    try {
      core.debug('Sending secrets:', JSON.stringify(secretsData, null, 2));

      const response = await axios.post(apiUrl, secretsData, {
        headers,
        timeout: 60000,
      });

      if (response.status >= 200 && response.status < 300) {
        core.info('✅ Secrets updated successfully in SBOM API.');
      } else {
        core.error(`❌ Failed to update secrets. Status: ${response.status}`);
        core.error('Response body:', response.data);
      }
    } catch (err) {
      core.error('❌ Error sending secrets to SBOM API:', err.message || err);
    }
  }

  /**
   * Required by orchestrator
   */
  async scan(config) {
    try {
      const startTime = Date.now();
      const scanDir = config.scanTarget || config.workspaceDir || '.';
      const reportPath = path.join(os.tmpdir(), `gitleaks_${Date.now()}_report.json`);
      const rulesPath = this.createTempRulesFile();

      core.info(`🔍 Scanning for secrets in: ${scanDir}`);

      // Set GIT safe directory for Docker/GitHub context
      try {
        await exec.exec('git', ['config', '--global', '--add', 'safe.directory', scanDir]);
      } catch (e) {
        core.warning("⚠️ Could not configure Git safe directory (not a git repo?)");
      }

      await this.runGitleaks(scanDir, reportPath, rulesPath);
      const result = await this.checkReport(reportPath);

      const endTime = Date.now();

      const filtered = Array.isArray(result)
        ? result.filter(item =>
          !skipFiles.includes(path.basename(item.File)) &&
          !item.File.includes('node_modules') &&
          !/["']?\$\{?[A-Z0-9_]+\}?["']?/.test(item.Match)
        )
        : result;

      const filteredSecrets = Array.isArray(filtered)
        ? filtered.map(item => ({
            Description: item.Description,
            File: `//////${item.File}`, // Add ////// prefix to match desired format
            Match: item.Match,
            StartLine: String(item.StartLine),
            EndLine: String(item.EndLine),
            StartColumn: String(item.StartColumn),
            EndColumn: String(item.EndColumn),
          }))
        : [];

      const durationMs = endTime - startTime;
      const durationMin = Math.floor(durationMs / 60000);
      const durationSec = Math.floor((durationMs % 60000) / 1000);
      const durationStr = `${durationMin}min ${durationSec}s`;

      core.info(`🔐 Secrets detected: ${Array.isArray(filtered) ? filtered.length : 0}`);
      core.info(`⏰ Scan duration: ${durationStr}`);

      // Send secrets to API if found and PROJECT_ID is set
      if (filtered !== "No secrets detected." && Array.isArray(filtered) && filtered.length > 0) {
        const projectId = process.env.PROJECT_ID;
        if (projectId) {
          core.debug('Raw secrets data:', JSON.stringify(filtered, null, 2));
          await this.sendSecretsToApi(projectId, filtered);
        } else {
          core.warning('PROJECT_ID environment variable not set. Skipping API upload.');
        }
      }

      // Clean up temporary files
      try {
        fs.unlinkSync(rulesPath);
        if (fs.existsSync(reportPath)) {
          fs.unlinkSync(reportPath);
        }
      } catch (e) {
        core.warning('Could not clean up temporary files');
      }

      // Return results in the format expected by orchestrator
      const secretCount = Array.isArray(filtered) ? filtered.length : 0;
      return {
        total: secretCount,
        critical: 0, // Secrets don't have severity levels like vulnerabilities
        high: 0,
        medium: 0,
        low: 0,
        vulnerabilities: filteredSecrets,
        secrets: filteredSecrets,
        duration: durationStr
      };
    } catch (error) {
      core.error(`❌ Secret detection scan failed: ${error.message}`);
      throw error;
    }
  }
}

module.exports = new SecretDetectorScanner();