const core = require('@actions/core');
const exec = require('@actions/exec');
const tc = require('@actions/tool-cache');
const os = require('os');
const fs = require('fs');
const path = require('path');

const trivyScanner = require('./trivy');

const CDXGEN_PACKAGE = '@cyclonedx/cdxgen';
const CDXGEN_VERSION = '11.9.0';
const CDXGEN_BINARY = 'cdxgen';

class CdxgenScanner {
  constructor() {
    this.name = 'SBOM Generator';
    this.binaryPath = null;
    this.trivyBinaryPath = null;
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
      const installDir = path.join(os.tmpdir(), 'cdxgen-install');
      core.info(`📦 Installing ${CDXGEN_PACKAGE}@${CDXGEN_VERSION}...`);

      // Create temporary install directory
      if (!fs.existsSync(installDir)) {
        fs.mkdirSync(installDir, { recursive: true });
      }

      // Install cdxgen locally with specific version
      const exitCode = await exec.exec('npm', ['install', `${CDXGEN_PACKAGE}@${CDXGEN_VERSION}`], {
        cwd: installDir
      });

      if (exitCode !== 0) {
        throw new Error(`npm install failed with exit code: ${exitCode}`);
      }

      // Find the installed binary
      const binaryPath = path.join(installDir, 'node_modules', '.bin', CDXGEN_BINARY);

      if (!fs.existsSync(binaryPath)) {
        throw new Error(`CDXgen binary not found at: ${binaryPath}`);
      }

      // Make binary executable (for Unix systems)
      if (os.platform() !== 'win32') {
        fs.chmodSync(binaryPath, '755');
      }

      core.info(`✅ ${CDXGEN_BINARY} installed successfully at: ${binaryPath}`);
      this.binaryPath = binaryPath;
      return binaryPath;
    } catch (error) {
      throw new Error(`Failed to install ${CDXGEN_PACKAGE}: ${error.message}`);
    }
  }

  async generateSBOM(targetDirectory) {
    try {
      if (!fs.existsSync(targetDirectory)) {
        throw new Error(`Target directory does not exist: ${targetDirectory}`);
      }

      // const outputFilePath = path.join(os.tmpdir(), `sbom-${Date.now()}.json`);
      // const outputFilePath = path.join(targetDirectory, `sbom-${Date.now()}.json`);
      const outputFilePath = path.join(targetDirectory, `sbom.json`);

      const fullOutputPath = path.resolve(outputFilePath);
      core.info(`🔍 Generating SBOM for: ${targetDirectory}`);

      // const args = ['--output', outputFilePath, targetDirectory];
      const args = [
        '--spec-version', '1.6',
        // '--deep',  // ← Removed: causes cdxgen to execute Maven which hangs
        '--output', outputFilePath,
        targetDirectory
      ];
      this.debugLog(`📝 Running: ${this.binaryPath} ${args.join(' ')}`);

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
        ignoreReturnCode: false,  // ← Let it throw on failure
        cwd: targetDirectory,
        silent: !this.debugMode,
        timeout: 300000  // ← 5 minute timeout to prevent hanging
      };

      let exitCode = 0;
      try {
        exitCode = await exec.exec(this.binaryPath, args, options);
        this.debugLog(`✅ SBOM generation completed with exit code: ${exitCode}`);
      } catch (error) {
        core.error(`❌ cdxgen command failed`);
        core.error(`Stdout: ${stdoutOutput}`);
        core.error(`Stderr: ${stderrOutput}`);
        throw new Error(`SBOM generation command failed: ${error.message}`);
      }

      // Wait for file to be created (cdxgen may need time to flush)
      const maxWaitTime = 10000; // 10 seconds
      const checkInterval = 500; // 500ms
      let waited = 0;

      while (!fs.existsSync(fullOutputPath) && waited < maxWaitTime) {
        this.debugLog(`⏳ Waiting for SBOM file to be created... (${waited}ms)`);
        await new Promise(resolve => setTimeout(resolve, checkInterval));
        waited += checkInterval;
      }

      if (!fs.existsSync(fullOutputPath)) {
        core.error(`❌ Output file not created after ${waited}ms: ${fullOutputPath}`);
        core.error(`Working directory: ${process.cwd()}`);
        core.error(`Target directory: ${targetDirectory}`);
        core.error(`Expected output path: ${fullOutputPath}`);
        core.error(`Stdout: ${stdoutOutput}`);
        core.error(`Stderr: ${stderrOutput}`);

        // List files in target directory to debug
        try {
          const filesInDir = fs.readdirSync(targetDirectory);
          core.error(`📁 Files in target directory: ${filesInDir.join(', ')}`);

          // Check if sbom.json exists anywhere in the directory
          const sbomFiles = filesInDir.filter(f => f.includes('sbom') || f.includes('bom-'));
          if (sbomFiles.length > 0) {
            core.error(`🔍 Found potential SBOM files: ${sbomFiles.join(', ')}`);
          }
        } catch (err) {
          core.error(`❌ Could not list directory: ${err.message}`);
        }

        throw new Error('SBOM generator did not generate output file');
      }

      this.debugLog(`✅ SBOM file verified at: ${fullOutputPath}`);

      return fullOutputPath;
    } catch (error) {
      core.error(`❌ SBOM generation failed: ${error.message}`);
      throw error;
    }
  }

  /**
   * Required by orchestrator
   */
  async scan(config) {
    try {
      const targetDir = config.scanTarget || '.';

      // Uncomment the next line to force generateSBOM to fail
      // throw new Error('Forced error to test fallback');

      const sbomPath = await this.generateSBOM(targetDir);

      core.info(`📦 SBOM generated: ${sbomPath}`);
    
      // this.trivyBinaryPath = await this.installTrivy();

      if (!trivyScanner.binaryPath) {
        core.info('🔧 Scanner not found, installing vulnerability scanner...');
        await trivyScanner.install();
      }
      this.trivyBinaryPath = trivyScanner.binaryPath;

      let stdoutData = '';

      const trivyArgs = [
        'sbom',
        '--format', 'json',
        '--quiet',
        sbomPath
      ];

      this.debugLog(`🛠️ Using Trivy binary at: ${this.trivyBinaryPath}`);
      this.debugLog(`🧩 Running command: trivy ${trivyArgs.join(' ')}`);

      // ✅ Run trivy using full path (PATH not reliable in same process)
      await exec.exec(this.trivyBinaryPath, trivyArgs, {
        ignoreReturnCode: true,
        listeners: {
          stdout: (data) => {
            stdoutData += data.toString();
            // Only print stdout in debug mode
            if (this.debugMode) {
              process.stdout.write(data);
            }
          },
          stderr: (data) => {
            // Only print stderr in debug mode
            if (this.debugMode) {
              process.stderr.write(data);
            }
          }
        },
        silent: true  // Always silent, we handle output via listeners
      });

      if (stdoutData.trim() === '') {
        core.warning('⚠️  No vulnerabilities found');
        return {
          total: 0,
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          vulnerabilities: [],
          sbomPath
        };
      }

      const data = JSON.parse(stdoutData);
      const vulns = (data.Results || []).flatMap(r => r.Vulnerabilities || []).filter(v => v);

      const countBySeverity = {
        CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0
      };

      vulns.forEach(vuln => {
        const sev = (vuln.Severity || 'UNKNOWN').toUpperCase();
        if (countBySeverity[sev] !== undefined) {
          countBySeverity[sev]++;
        }
      });

      this.debugLog(`📊 Vulnerability Summary:`);
      this.debugLog(`   CRITICAL: ${countBySeverity.CRITICAL}`);
      this.debugLog(`   HIGH:     ${countBySeverity.HIGH}`);
      this.debugLog(`   MEDIUM:   ${countBySeverity.MEDIUM}`);
      this.debugLog(`   LOW:      ${countBySeverity.LOW}`);
      this.debugLog(`   TOTAL:    ${vulns.length}`);

      return {
        total: vulns.length,
        critical: countBySeverity.CRITICAL,
        high: countBySeverity.HIGH,
        medium: countBySeverity.MEDIUM,
        low: countBySeverity.LOW,
        vulnerabilities: vulns,
        sbomPath
      };

    } catch (error) {
      core.error(`❌ Scan failed: ${error.message}`);
      // throw error;
      core.info('➡️ Falling back to vulnerability scanner...');

      // Fallback: call trivy.js scanner directly
      return await trivyScanner.scan(config);
    }
  }

}

module.exports = new CdxgenScanner();
