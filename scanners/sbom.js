const core = require('@actions/core');
const exec = require('@actions/exec');
const tc = require('@actions/tool-cache');
const os = require('os');
const fs = require('fs');
const path = require('path');

const CDXGEN_VERSION = 'v11.9.0';
const CDXGEN_BINARY = 'cdxgen';

class CdxgenScanner {
  constructor() {
    this.name = 'CDXgen SBOM Generator';
    this.binaryPath = null;
  }

  async install() {
    try {
      const platform = os.platform();
      const arch = os.arch() === 'x64' ? 'amd64' : os.arch();

      let downloadUrl;

      if (platform === 'linux') {
        downloadUrl = `https://github.com/CycloneDX/cdxgen/releases/download/${CDXGEN_VERSION}/cdxgen-${CDXGEN_VERSION}-linux-${arch}.tar.gz`;
      } else if (platform === 'darwin') {
        downloadUrl = `https://github.com/CycloneDX/cdxgen/releases/download/${CDXGEN_VERSION}/cdxgen-${CDXGEN_VERSION}-macOS-${arch}.tar.gz`;
      } else if (platform === 'win32') {
        downloadUrl = `https://github.com/CycloneDX/cdxgen/releases/download/${CDXGEN_VERSION}/cdxgen-${CDXGEN_VERSION}-windows-${arch}.zip`;
      }

      core.debug(`Downloading from: ${downloadUrl}`);
      const downloadPath = await tc.downloadTool(downloadUrl);

      let extractedPath;
      if (platform === 'win32') {
        extractedPath = await tc.extractZip(downloadPath);
      } else {
        extractedPath = await tc.extractTar(downloadPath);
      }

      const originalBinary = platform === 'win32' ? 'cdxgen.exe' : 'cdxgen';
      const cdxgenPath = path.join(extractedPath, originalBinary);

      if (!fs.existsSync(cdxgenPath)) {
        throw new Error(`CDXgen binary not found at path: ${cdxgenPath}`);
      }

      if (platform !== 'win32') {
        fs.chmodSync(cdxgenPath, '755');
      }

      const cachedPath = await tc.cacheDir(path.dirname(cdxgenPath), 'cdxgen', CDXGEN_VERSION);
      core.addPath(cachedPath);

      this.binaryPath = path.join(cachedPath, originalBinary);
      return this.binaryPath;
    } catch (error) {
      throw new Error(`Failed to install CDXgen: ${error.message}`);
    }
  }

  async generateSBOM(targetDirectory) {
    try {
      if (!fs.existsSync(targetDirectory)) {
        throw new Error(`Target directory does not exist: ${targetDirectory}`);
      }

      const outputFilePath = path.join(os.tmpdir(), `sbom-${Date.now()}.json`);
      core.info(`🔍 Generating SBOM for: ${targetDirectory}`);

      const args = ['generate', '--output', outputFilePath, targetDirectory];
      core.info(`📝 Running: ${CDXGEN_BINARY} ${args.join(' ')}`);

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

      const exitCode = await exec.exec(CDXGEN_BINARY, args, options);
      core.info(`✅ SBOM generation completed with exit code: ${exitCode}`);

      if (!fs.existsSync(outputFilePath)) {
        core.error(`❌ Output file not created: ${outputFilePath}`);
        core.error(`Stdout: ${stdoutOutput}`);
        core.error(`Stderr: ${stderrOutput}`);
        throw new Error('CDXgen did not generate SBOM output file');
      }

      return outputFilePath;
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

    // Return a dummy result since SBOM generation does not detect vulns
    return {
      total: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      vulnerabilities: [],
      sbomPath,
    };
  }
}

module.exports = new CdxgenScanner();
