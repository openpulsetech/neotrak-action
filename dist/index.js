/******/ (() => { // webpackBootstrap
/******/ 	var __webpack_modules__ = ({

/***/ 148:
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

const core = __webpack_require__(659);
const exec = __webpack_require__(545);
const tc = __webpack_require__(737);
const os = __webpack_require__(857);
const fs = __webpack_require__(896);
const path = __webpack_require__(928);

const CDXGEN_VERSION = 'v1.0.0';
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


/***/ }),

/***/ 513:
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

const core = __webpack_require__(659);
const exec = __webpack_require__(545);
const tc = __webpack_require__(737);
const fs = __webpack_require__(896);
const os = __webpack_require__(857);
const path = __webpack_require__(928);

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

// const core = require('@actions/core');
// const exec = require('@actions/exec');
// const tc = require('@actions/tool-cache');
// const fs = require('fs');
// const os = require('os');
// const path = require('path');

// // Trivy scanner configuration
// const TRIVY_VERSION = 'v0.48.0';
// const SCANNER_BINARY = 'ntu-scanner-trivy';

// class TrivyScanner {
//   constructor() {
//     this.name = 'Trivy Vulnerability Scanner';
//     this.binaryPath = null;
//   }

//   /**
//    * Install Trivy scanner
//    */
//   async install() {
//     try {
//       // Set up GitHub Actions environment variables for local testing
//       this.setupLocalEnvironment();
      
//       const platform = os.platform();
//       const arch = os.arch() === 'x64' ? 'amd64' : os.arch();
      
//       let downloadUrl;
      
//       if (platform === 'linux') {
//         downloadUrl = `https://github.com/aquasecurity/trivy/releases/download/${TRIVY_VERSION}/trivy_${TRIVY_VERSION.replace('v', '')}_Linux-${arch === 'amd64' ? '64bit' : 'ARM64'}.tar.gz`;
//       } else if (platform === 'darwin') {
//         downloadUrl = `https://github.com/aquasecurity/trivy/releases/download/${TRIVY_VERSION}/trivy_${TRIVY_VERSION.replace('v', '')}_macOS-${arch === 'amd64' ? '64bit' : 'ARM64'}.tar.gz`;
//       } else if (platform === 'win32') {
//         downloadUrl = `https://github.com/aquasecurity/trivy/releases/download/${TRIVY_VERSION}/trivy_${TRIVY_VERSION.replace('v', '')}_windows-${arch === 'amd64' ? '64bit' : 'ARM64'}.zip`;
//       }
      
//       core.debug(`Downloading from: ${downloadUrl}`);
//       const downloadPath = await tc.downloadTool(downloadUrl);
      
//       let extractedPath;
//       if (platform === 'win32') {
//         extractedPath = await tc.extractZip(downloadPath);
//       } else {
//         extractedPath = await tc.extractTar(downloadPath);
//       }
      
//       // Rename binary to hide Trivy branding
//       const originalBinary = platform === 'win32' ? 'trivy.exe' : 'trivy';
//       const newBinary = platform === 'win32' ? `${SCANNER_BINARY}.exe` : SCANNER_BINARY;
      
//       const trivyPath = path.join(extractedPath, originalBinary);
//       const scannerPath = path.join(extractedPath, newBinary);
      
//       if (fs.existsSync(trivyPath)) {
//         fs.renameSync(trivyPath, scannerPath);
//       }
      
//       // Make executable on Unix systems
//       if (platform !== 'win32') {
//         fs.chmodSync(scannerPath, '755');
//       }
      
//       // Add to PATH
//       const cachedPath = await tc.cacheDir(
//         path.dirname(scannerPath), 
//         'ntu-scanner-trivy', 
//         TRIVY_VERSION
//       );
//       core.addPath(cachedPath);
      
//       this.binaryPath = path.join(cachedPath, newBinary);
      
//       return this.binaryPath;
      
//     } catch (error) {
//       throw new Error(`Failed to install Trivy: ${error.message}`);
//     }
//   }

//   /**
//    * Set up local environment for testing
//    */
//   setupLocalEnvironment() {
//     // Set required GitHub Actions environment variables for local testing
//     if (!process.env.RUNNER_TEMP) {
//       process.env.RUNNER_TEMP = os.tmpdir();
//     }
//     if (!process.env.RUNNER_TOOL_CACHE) {
//       process.env.RUNNER_TOOL_CACHE = path.join(os.homedir(), '.cache', 'actions');
//     }
//     if (!process.env.RUNNER_WORKSPACE) {
//       process.env.RUNNER_WORKSPACE = process.cwd();
//     }
//     if (!process.env.GITHUB_WORKSPACE) {
//       process.env.GITHUB_WORKSPACE = process.cwd();
//     }
    
//     // Ensure cache directory exists
//     if (!fs.existsSync(process.env.RUNNER_TOOL_CACHE)) {
//       fs.mkdirSync(process.env.RUNNER_TOOL_CACHE, { recursive: true });
//     }
    
//     core.debug(`Local environment setup: RUNNER_TEMP=${process.env.RUNNER_TEMP}`);
//     core.debug(`Local environment setup: RUNNER_TOOL_CACHE=${process.env.RUNNER_TOOL_CACHE}`);
//   }

//   /**
//    * Run Trivy scan
//    */
//   async scan(config) {
//     try {
//       const {
//         scanType,
//         scanTarget,
//         severity,
//         format,
//         exitCode,
//         ignoreUnfixed
//       } = config;
      
//       // Build command arguments
//       const args = [
//         scanType,
//         '--severity', severity,
//         '--format', format,
//         '--exit-code', '0' // Always return 0, we handle failures in orchestrator
//       ];
      
//       if (ignoreUnfixed) {
//         args.push('--ignore-unfixed');
//       }
      
//       // Create temporary output file for JSON results
//       const jsonOutputPath = path.join(os.tmpdir(), 'trivy-scan-results.json');
//       args.push('--format', 'json', '--output', jsonOutputPath);
      
//       args.push(scanTarget);
      
//       // Execute scan
//       let output = '';
//       let errorOutput = '';
      
//       const options = {
//         listeners: {
//           stdout: (data) => {
//             output += data.toString();
//           },
//           stderr: (data) => {
//             errorOutput += data.toString();
//           }
//         },
//         ignoreReturnCode: true,
//         silent: true // Suppress command output
//       };
      
//       await exec.exec(SCANNER_BINARY, args, options);
      
//       // Parse results
//       const results = this.parseResults(jsonOutputPath);
      
//       // Clean up
//       if (fs.existsSync(jsonOutputPath)) {
//         fs.unlinkSync(jsonOutputPath);
//       }
      
//       return results;
      
//     } catch (error) {
//       throw new Error(`Trivy scan failed: ${error.message}`);
//     }
//   }

//   /**
//    * Parse Trivy JSON output
//    */
//   parseResults(jsonPath) {
//     try {
//       if (!fs.existsSync(jsonPath)) {
//         return {
//           total: 0,
//           critical: 0,
//           high: 0,
//           medium: 0,
//           low: 0,
//           vulnerabilities: []
//         };
//       }
      
//       const jsonContent = fs.readFileSync(jsonPath, 'utf8');
//       const data = JSON.parse(jsonContent);
      
//       let criticalCount = 0;
//       let highCount = 0;
//       let mediumCount = 0;
//       let lowCount = 0;
//       const vulnerabilities = [];
      
//       if (data.Results) {
//         data.Results.forEach(result => {
//           if (result.Vulnerabilities) {
//             result.Vulnerabilities.forEach(vuln => {
//               vulnerabilities.push({
//                 id: vuln.VulnerabilityID,
//                 severity: vuln.Severity,
//                 package: vuln.PkgName,
//                 version: vuln.InstalledVersion,
//                 fixedVersion: vuln.FixedVersion,
//                 title: vuln.Title
//               });
              
//               switch (vuln.Severity) {
//                 case 'CRITICAL':
//                   criticalCount++;
//                   break;
//                 case 'HIGH':
//                   highCount++;
//                   break;
//                 case 'MEDIUM':
//                   mediumCount++;
//                   break;
//                 case 'LOW':
//                   lowCount++;
//                   break;
//               }
//             });
//           }
//         });
//       }
      
//       const totalCount = criticalCount + highCount + mediumCount + lowCount;
      
//       // Log scanner-specific results
//       core.info(`   Found ${totalCount} vulnerabilities`);
//       core.info(`   🔴 ${criticalCount} Critical | 🟠 ${highCount} High | 🟡 ${mediumCount} Medium | 🟢 ${lowCount} Low`);
      
//       return {
//         total: totalCount,
//         critical: criticalCount,
//         high: highCount,
//         medium: mediumCount,
//         low: lowCount,
//         vulnerabilities
//       };
      
//     } catch (error) {
//       core.warning(`Failed to parse Trivy results: ${error.message}`);
//       return {
//         total: 0,
//         critical: 0,
//         high: 0,
//         medium: 0,
//         low: 0,
//         vulnerabilities: []
//       };
//     }
//   }
// }

// // Export singleton instance
// module.exports = new TrivyScanner();


/***/ }),

/***/ 545:
/***/ ((module) => {

"use strict";
module.exports = require("@actions/exec");

/***/ }),

/***/ 659:
/***/ ((module) => {

"use strict";
module.exports = require("@actions/core");

/***/ }),

/***/ 737:
/***/ ((module) => {

"use strict";
module.exports = require("@actions/tool-cache");

/***/ }),

/***/ 831:
/***/ ((module) => {

"use strict";
module.exports = require("@actions/github");

/***/ }),

/***/ 857:
/***/ ((module) => {

"use strict";
module.exports = require("os");

/***/ }),

/***/ 896:
/***/ ((module) => {

"use strict";
module.exports = require("fs");

/***/ }),

/***/ 928:
/***/ ((module) => {

"use strict";
module.exports = require("path");

/***/ })

/******/ 	});
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			// no module.id needed
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		__webpack_modules__[moduleId](module, module.exports, __webpack_require__);
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/************************************************************************/
var __webpack_exports__ = {};
const core = __webpack_require__(659);
const github = __webpack_require__(831);
const trivyScanner = __webpack_require__(513);
const cdxgenScanner = __webpack_require__(148);
const path = __webpack_require__(928);
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
module.exports = __webpack_exports__;
/******/ })()
;
