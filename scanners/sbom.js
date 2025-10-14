const core = require('@actions/core');
const exec = require('@actions/exec');
const tc = require('@actions/tool-cache');
const os = require('os');
const fs = require('fs');
const path = require('path');

// CDXgen version and binary name
const CDXGEN_VERSION = 'v1.0.0'; // Update this as needed
const CDXGEN_BINARY = 'cdxgen';

class CdxgenScanner {
  constructor() {
    this.name = 'CDXgen SBOM Generator';
    this.binaryPath = null;
  }

  /**
   * Install CDXgen tool
   */
  async install() {
    try {
      const platform = os.platform();
      const arch = os.arch() === 'x64' ? 'amd64' : os.arch();

      let downloadUrl;

      // Construct download URL based on the platform
      if (platform === 'linux') {
        downloadUrl = `https://github.com/adeptlabs/cdxgen/releases/download/${CDXGEN_VERSION}/cdxgen-${CDXGEN_VERSION}-linux-${arch}.tar.gz`;
      } else if (platform === 'darwin') {
        downloadUrl = `https://github.com/adeptlabs/cdxgen/releases/download/${CDXGEN_VERSION}/cdxgen-${CDXGEN_VERSION}-macOS-${arch}.tar.gz`;
      } else if (platform === 'win32') {
        downloadUrl = `https://github.com/adeptlabs/cdxgen/releases/download/${CDXGEN_VERSION}/cdxgen-${CDXGEN_VERSION}-windows-${arch}.zip`;
      }

      core.debug(`Downloading from: ${downloadUrl}`);
      const downloadPath = await tc.downloadTool(downloadUrl);

      let extractedPath;
      if (platform === 'win32') {
        extractedPath = await tc.extractZip(downloadPath);
      } else {
        extractedPath = await tc.extractTar(downloadPath);
      }

      // Set the binary path
      const originalBinary = platform === 'win32' ? 'cdxgen.exe' : 'cdxgen';
      const cdxgenPath = path.join(extractedPath, originalBinary);

      if (!fs.existsSync(cdxgenPath)) {
        throw new Error(`CDXgen binary not found at path: ${cdxgenPath}`);
      }

      // Make executable (Unix systems)
      if (platform !== 'win32') {
        fs.chmodSync(cdxgenPath, '755');
      }

      // Cache the binary and add to PATH
      const cachedPath = await tc.cacheDir(path.dirname(cdxgenPath), 'cdxgen', CDXGEN_VERSION);
      core.addPath(cachedPath);

      this.binaryPath = path.join(cachedPath, originalBinary);

      return this.binaryPath;
    } catch (error) {
      throw new Error(`Failed to install CDXgen: ${error.message}`);
    }
  }

  /**
   * Run CDXgen to generate an SBOM (Software Bill of Materials)
   */
  async generateSBOM(targetDirectory) {
    try {
      if (!fs.existsSync(targetDirectory)) {
        throw new Error(`Target directory does not exist: ${targetDirectory}`);
      }

      const outputFilePath = path.join(os.tmpdir(), `sbom-${Date.now()}.json`);

      core.info(`🔍 Generating SBOM for: ${targetDirectory}`);

      const args = ['generate', '--output', outputFilePath, targetDirectory];

      core.info(`📝 Running: ${CDXGEN_BINARY} ${args.join(' ')}`);

      // Execute CDXgen command
      let stdoutOutput = '';
      let stderrOutput = '';

      const options = {
        listeners: {
          stdout: (data) => {
            stdoutOutput += data.toString();
          },
          stderr: (data) => {
            stderrOutput += data.toString();
          },
        },
        ignoreReturnCode: true,
        cwd: targetDirectory,
      };

      const exitCode = await exec.exec(CDXGEN_BINARY, args, options);

      core.info(`✅ SBOM generation completed with exit code: ${exitCode}`);

      // Check if the SBOM file was created
      if (!fs.existsSync(outputFilePath)) {
        core.error(`❌ Output file not created: ${outputFilePath}`);
        core.error(`Stdout: ${stdoutOutput}`);
        core.error(`Stderr: ${stderrOutput}`);
        throw new Error('CDXgen did not generate SBOM output file');
      }

      // Return the path to the generated SBOM file
      return outputFilePath;
    } catch (error) {
      core.error(`❌ CDXgen SBOM generation failed: ${error.message}`);
      throw error;
    }
  }
}

// Export an instance of the CdxgenScanner
module.exports = new CdxgenScanner();
