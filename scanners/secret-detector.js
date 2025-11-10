const core = require('@actions/core');
const exec = require('@actions/exec');
const os = require('os');
const fs = require('fs');
const path = require('path');

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
  // ✅ Now supports both quoted and unquoted values in YAML files
  createCustomRules() {
    return `
[[rules]]
id = "strict-secret-detection-quoted"
description = "Detect likely passwords or secrets with quotes (high entropy)"
regex = '''(?i)(?:password|passwd|pwd|secret|key|token|auth|access)[\\s"']*[=:][\\s"']*["']([A-Za-z0-9@#\\-_$%!+/=]{6,})["']'''
tags = ["key", "secret", "generic", "password"]

[[rules]]
id = "strict-secret-detection-unquoted"
description = "Detect likely passwords or secrets without quotes in YAML"
regex = '''(?i)(?:password|passwd|pwd|secret|key|token|auth|access)\\s*:\\s*([A-Za-z0-9@#\\-_$%!+/=]{6,})'''
tags = ["key", "secret", "generic", "password", "yaml"]

[[rules]]
id = "aws-secret-quoted"
description = "AWS Secret Access Key (quoted)"
regex = '''(?i)aws(.{0,20})?(secret|access)?(.{0,20})?['"][0-9a-zA-Z/+]{40}['"]'''
tags = ["aws", "key", "secret"]

[[rules]]
id = "aws-secret-unquoted"
description = "AWS Secret Access Key (unquoted)"
regex = '''(?i)(?:aws[-_]?secret[-_]?access[-_]?key|secret[-_]?key|access[-_]?secret)\\s*[=:]\\s*([0-9a-zA-Z/+]{40})'''
tags = ["aws", "key", "secret"]

[[rules]]
id = "aws-key"
description = "AWS Access Key ID"
regex = '''AKIA[0-9A-Z]{16}'''
tags = ["aws", "key"]

[[rules]]
id = "digitalocean-spaces-key"
description = "DigitalOcean Spaces Access Key"
regex = '''(?i)(?:access[-_]?key|access[-_]?secret)\\s*:\\s*([A-Z0-9]{20,})'''
tags = ["digitalocean", "spaces", "key"]

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

[[rules]]
id = "generic-api-key-unquoted"
description = "Generic API keys in YAML (unquoted)"
regex = '''(?i)(?:api[-_]?key|apikey)\\s*:\\s*([A-Za-z0-9_\\-]{15,})'''
tags = ["apikey", "yaml"]

[[rules]]
id = "hex-secret-key"
description = "Hexadecimal secret keys (64+ chars)"
regex = '''(?i)(?:secret[-_]?key|secretkey)\\s*[=:]\\s*["']?([a-f0-9]{64,})["']?'''
tags = ["secret", "hex"]

[[rules]]
id = "groq-api-key"
description = "Groq API Key"
regex = '''gsk_[A-Za-z0-9]{20,}'''
tags = ["groq", "apikey"]

[[rules]]
id = "mailjet-keys"
description = "Mailjet API keys"
regex = '''(?i)(?:mailjet[-_]?(?:api|secret)[-_]?key)\\s*:\\s*["']?([A-Za-z0-9]{10,})["']?'''
tags = ["mailjet", "apikey"]
`;
  }

  createTempRulesFile() {
    const rulesPath = path.join(os.tmpdir(), 'gitleaks-custom-rules.toml');
    fs.writeFileSync(rulesPath, this.createCustomRules());
    return rulesPath;
  }

  async runGitleaks(scanDir, reportPath, rulesPath) {
    // const args = ['detect', '--source', scanDir, '--report-path', reportPath, '--config', rulesPath, '--no-banner', '--verbose'];
    const args = ['dir', scanDir, '--report-path', reportPath, '--config', rulesPath, '--no-banner'];

    // Only add verbose flag in debug mode
    if (this.debugMode) {
      args.push('--verbose');
    }

    this.debugLog(`🔍 Running Gitleaks: ${this.binaryPath} ${args.join(' ')}`);

    let stdoutOutput = '';
    let stderrOutput = '';

    const options = {
      listeners: {
        stdout: (data) => {
          stdoutOutput += data.toString();
          if (this.debugMode) {
            process.stdout.write(data);
          }
        },
        stderr: (data) => {
          stderrOutput += data.toString();
          if (this.debugMode) {
            process.stderr.write(data);
          }
        }
      },
      ignoreReturnCode: true,
      silent: !this.debugMode
    };

    const exitCode = await exec.exec(this.binaryPath, args, options);
    this.debugLog(`Gitleaks exit code: ${exitCode}`);
    this.debugLog(`Gitleaks STDOUT: ${stdoutOutput}`);
    if (stderrOutput && stderrOutput.trim()) {
      this.debugLog(`Gitleaks STDERR: ${stderrOutput}`);
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

  /**
   * Required by orchestrator
   */
  async scan(config) {
    try {
      const startTime = Date.now();
      const scanDir = config.scanTarget || config.workspaceDir || '.';
      const reportPath = path.join(os.tmpdir(), `gitleaks_${Date.now()}_report.json`);
      const rulesPath = this.createTempRulesFile();

      // Delete node_modules folder before scanning
      const nodeModulesPath = path.join(scanDir, 'node_modules');
      if (fs.existsSync(nodeModulesPath)) {
        try {
          core.info(`🗑️  Deleting node_modules folder before secret scan`);
          fs.rmSync(nodeModulesPath, { recursive: true, force: true });
          core.info('✅ node_modules deleted');
        } catch (error) {
          core.warning(`⚠️  Failed to delete node_modules: ${error.message}`);
        }
      }

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
        ? result.filter(item => {
            const shouldSkip = skipFiles.includes(path.basename(item.File));
            const hasNodeModules = item.File.includes('node_modules');
            const isEnvVar = /["']?\$\{?[A-Z0-9_]+\}?["']?/.test(item.Match);

               // ✅ Exclude common build/config directories
            const excludedDirs = ['.git/', '.github/', '.settings/', 'target/', 'build/', 'dist/', 'out/'];
            const isExcludedDir = excludedDirs.some(dir => item.File.includes(dir));

            if (shouldSkip) {
              this.debugLog(`⏭️  Skipping ${item.File} - in skipFiles list`);
            }
            if (hasNodeModules) {
              this.debugLog(`⏭️  Skipping ${item.File} - node_modules`);
            }

            if (isEnvVar) {
              this.debugLog(`⏭️  Skipping ${item.File} - env variable pattern: ${item.Match}`);
            }

          if (isExcludedDir) {
            this.debugLog(`⏭️  Skipping ${item.File} - excluded directory`);
          }
            return !shouldSkip && !hasNodeModules && !isExcludedDir && !isEnvVar;
          })
        : result;

      this.debugLog(`✅ Secrets after filtering: ${Array.isArray(filtered) ? filtered.length : 0}`);

      // ✅ Deduplicate secrets based on File + StartLine + Secret
      const deduplicated = Array.isArray(filtered)
        ? filtered.reduce((acc, item) => {
            const key = `${item.File}:${item.StartLine}:${item.Secret}`;
            if (!acc.seen.has(key)) {
              acc.seen.add(key);
              acc.results.push(item);
            } else {
              this.debugLog(`⏭️  Skipping duplicate: ${item.File}:${item.StartLine} (${item.RuleID})`);
            }
            return acc;
          }, { seen: new Set(), results: [] }).results
        : [];

      this.debugLog(`✅ Secrets after deduplication: ${deduplicated.length}`);

      const filteredSecrets = deduplicated.map(item => ({
        RuleID: item.RuleID || '',
        Description: item.Description || '',
        File: `//////${item.File}`, // Add ////// prefix to match desired format
        Match: item.Match || '',
        Secret: item.Secret || '',
        StartLine: String(item.StartLine || ''),
        EndLine: String(item.EndLine || ''),
        StartColumn: String(item.StartColumn || ''),
        EndColumn: String(item.EndColumn || ''),
      }));

      const durationMs = endTime - startTime;
      const durationMin = Math.floor(durationMs / 60000);
      const durationSec = Math.floor((durationMs % 60000) / 1000);
      const durationStr = `${durationMin}min ${durationSec}s`;

      core.info(`🔐 Unique secrets detected: ${deduplicated.length}`);
      core.info(`⏰ Scan duration: ${durationStr}`);

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
      const secretCount = deduplicated.length;
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