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
    this.name = 'CDXgen SBOM Generator';
    this.binaryPath = null;
    this.trivyBinaryPath = null;
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
        '--spec-version', '1.4',
        '--deep',                       // ← Scan subdirectories
        '--output', outputFilePath,
        targetDirectory
      ];
      core.info(`📝 Running: ${this.binaryPath} ${args.join(' ')}`);

      let stdoutOutput = '';
      let stderrOutput = '';

      const options = {
        listeners: {
          // stdout: (data) => { stdoutOutput += data.toString(); },
          // stderr: (data) => { stderrOutput += data.toString(); },
          stdout: () => {},  // Suppress stdout
          stderr: () => {}, 
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
    try {
      const targetDir = config.scanTarget || '.';

      // Uncomment the next line to force generateSBOM to fail
      // throw new Error('Forced error to test fallback');

      const sbomPath = await this.generateSBOM(targetDir);

      core.info(`📦 SBOM generated: ${sbomPath}`);
    
      // this.trivyBinaryPath = await this.installTrivy();

      if (!trivyScanner.binaryPath) {
        core.info('🔧 Trivy not found, installing Trivy scanner in sbom...');
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

      console.log(`🛠️ Using Trivy binary at: ${this.trivyBinaryPath}`);
      // console.log(`🧩 Running command: trivy ${trivyArgs.join(' ')}`);

      // ✅ Run trivy using full path (PATH not reliable in same process)
      await exec.exec(this.trivyBinaryPath, trivyArgs, {
        ignoreReturnCode: true,
        listeners: {
          stdout: (data) => { stdoutData += data.toString(); }
        },
        stderr: 'pipe'
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

      core.info(`📊 Vulnerability Summary:`);
      core.info(`   CRITICAL: ${countBySeverity.CRITICAL}`);
      core.info(`   HIGH:     ${countBySeverity.HIGH}`);
      core.info(`   MEDIUM:   ${countBySeverity.MEDIUM}`);
      core.info(`   LOW:      ${countBySeverity.LOW}`);
      core.info(`   TOTAL:    ${vulns.length}`);

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
      core.info('➡️ Falling back to Trivy scanner...');

      // Fallback: call trivy.js scanner directly
      return await trivyScanner.scan(config);
    }
  }

}

module.exports = new CdxgenScanner();
