const core = require('@actions/core');
const exec = require('@actions/exec');
const tc = require('@actions/tool-cache');
const os = require('os');
const fs = require('fs');
const path = require('path');

const CDXGEN_PACKAGE = '@cyclonedx/cdxgen';
const CDXGEN_VERSION = '11.9.0';
const CDXGEN_BINARY = 'cdxgen';

class CdxgenScanner {
  constructor() {
    this.name = 'CDXgen SBOM Generator';
    this.binaryPath = null;
  }

  async installTrivy() {
  try {
    const TRIVY_VERSION = 'v0.48.0';
    const SCANNER_BINARY = 'ntu-scanner-trivy';

    // Setup environment for local testing (optional, similar to your example)
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
    if (!fs.existsSync(process.env.RUNNER_TOOL_CACHE)) {
      fs.mkdirSync(process.env.RUNNER_TOOL_CACHE, { recursive: true });
    }

    const platform = os.platform();
    const arch = os.arch() === 'x64' ? 'amd64' : os.arch();

    let downloadUrl;

    if (platform === 'linux') {
      downloadUrl = `https://github.com/aquasecurity/trivy/releases/download/${TRIVY_VERSION}/trivy_${TRIVY_VERSION.replace('v', '')}_Linux-${arch === 'amd64' ? '64bit' : 'ARM64'}.tar.gz`;
    } else if (platform === 'darwin') {
      downloadUrl = `https://github.com/aquasecurity/trivy/releases/download/${TRIVY_VERSION}/trivy_${TRIVY_VERSION.replace('v', '')}_macOS-${arch === 'amd64' ? '64bit' : 'ARM64'}.tar.gz`;
    } else if (platform === 'win32') {
      downloadUrl = `https://github.com/aquasecurity/trivy/releases/download/${TRIVY_VERSION}/trivy_${TRIVY_VERSION.replace('v', '')}_windows-${arch === 'amd64' ? '64bit' : 'ARM64'}.zip`;
    } else {
      throw new Error(`Unsupported platform: ${platform}`);
    }

    core.debug(`Downloading Trivy from: ${downloadUrl}`);
    const downloadPath = await tc.downloadTool(downloadUrl);

    let extractedPath;
    if (platform === 'win32') {
      extractedPath = await tc.extractZip(downloadPath);
    } else {
      extractedPath = await tc.extractTar(downloadPath);
    }

    const originalBinary = platform === 'win32' ? 'trivy.exe' : 'trivy';
    const newBinary = platform === 'win32' ? `${SCANNER_BINARY}.exe` : SCANNER_BINARY;

    const trivyPath = path.join(extractedPath, originalBinary);
    const scannerPath = path.join(extractedPath, newBinary);

    if (fs.existsSync(trivyPath)) {
      fs.renameSync(trivyPath, scannerPath);
    }

    if (platform !== 'win32') {
      fs.chmodSync(scannerPath, '755');
    }

    const cachedPath = await tc.cacheDir(
      path.dirname(scannerPath),
      'ntu-scanner-trivy',
      TRIVY_VERSION
    );

    core.addPath(cachedPath);

    this.trivyBinaryPath = path.join(cachedPath, newBinary);
    core.info(`✅ Trivy installed at: ${this.trivyBinaryPath}`);

    return this.trivyBinaryPath;

  } catch (error) {
    throw new Error(`Failed to install Trivy: ${error.message}`);
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
      const outputFilePath = path.join(targetDirectory, `sbom-${Date.now()}.json`);
      const fullOutputPath = path.resolve(outputFilePath);
      core.info(`🔍 Generating SBOM for: ${targetDirectory}`);

      const args = ['--output', outputFilePath, targetDirectory];
      core.info(`📝 Running: ${this.binaryPath} ${args.join(' ')}`);

      let stdoutOutput = '';
      let stderrOutput = '';

      const options = {
        listeners: {
          stdout: (data) => { stdoutOutput += data.toString(); },
          stderr: (data) => { stderrOutput += data.toString(); },
        },
        ignoreReturnCode: true,
        cwd: targetDirectory,
      };

      const exitCode = await exec.exec(this.binaryPath, args, options);
      core.info(`✅ SBOM generation completed with exit code: ${exitCode}`);

      if (!fs.existsSync(fullOutputPath)) {
        core.error(`❌ Output file not created: ${fullOutputPath}`);
        core.error(`Stdout: ${stdoutOutput}`);
        core.error(`Stderr: ${stderrOutput}`);
        throw new Error('CDXgen did not generate SBOM output file');
      }

      return fullOutputPath;
    } catch (error) {
      core.error(`❌ CDXgen SBOM generation failed: ${error.message}`);
      throw error;
    }
  }

  /**
   * Required by orchestrator
   */
  async scan(config) {
    const targetDir = config.scanTarget || '.';
    const sbomPath = await this.generateSBOM(targetDir);

    core.info(`📦 SBOM generated at: ${sbomPath}`);

    await this.installTrivy();
    const severity = config.severity || 'high';

    // Log the severity to confirm
    core.info(`🔍 Scan severity: ${severity.toUpperCase()}`);

    const trivyOutputPath = path.join(os.tmpdir(), `trivy-results-${Date.now()}.json`);
    const TRIVY_BINARY = 'trivy'; // Assumes Trivy is installed and in PATH

    const trivyArgs = [
      'sbom',
      '--format', 'json',
      '--output', trivyOutputPath,
      sbomPath
    ];

    let stdoutOutput = '';
    let stderrOutput = '';

    const options = {
      listeners: {
        stdout: (data) => { stdoutOutput += data.toString(); },
        stderr: (data) => { stderrOutput += data.toString(); },
      },
      ignoreReturnCode: false,
      cwd: targetDir,
    };

    try {
      const exitCode = await exec.exec(TRIVY_BINARY, trivyArgs, options);
      core.info(`✅ Trivy scan completed with exit code: ${exitCode}`);
    } catch (error) {
      core.error(`❌ Trivy execution failed: ${error.message}`);
      throw error;
    }

    if (!fs.existsSync(trivyOutputPath)) {
      throw new Error(`Trivy output file not found: ${trivyOutputPath}`);
    }

    const trivyJson = JSON.parse(fs.readFileSync(trivyOutputPath, 'utf8'));
    const allVulns = (trivyJson.Results || []).flatMap(r => r.Vulnerabilities || []);

    const countBySeverity = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      UNKNOWN: 0,
    };

    for (const vuln of allVulns) {
      const sev = (vuln.Severity || 'UNKNOWN').toUpperCase();
      if (countBySeverity.hasOwnProperty(sev)) {
        countBySeverity[sev]++;
      } else {
        countBySeverity.UNKNOWN++;
      }
    }

    core.info(`📊 Trivy Vulnerability Summary: ${JSON.stringify(countBySeverity, null, 2)}`);

    return {
      total: allVulns.length,
      critical: countBySeverity.CRITICAL,
      high: countBySeverity.HIGH,
      medium: countBySeverity.MEDIUM,
      low: countBySeverity.LOW,
      vulnerabilities: allVulns,
      sbomPath,
    };
  } catch(error) {
    core.error(`❌ Error during scanning: ${error.message}`);
    core.debug(`Stack trace: ${error.stack}`);
    throw error;
  }
}

module.exports = new CdxgenScanner();
