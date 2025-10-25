const core = require('@actions/core');
const exec = require('@actions/exec');
const fs = require('fs');
const os = require('os');
const path = require('path');

class ConfigScanner {
    constructor() {
        this.name = 'Trivy config Scanner';
        this.binaryPath = null; // Path to Trivy binary
    }

    async install() {
        const trivyInstaller = require('./trivy');
        if (typeof trivyInstaller.install === 'function') {
            core.info('📦 Installing Trivy for Config Scanner using Trivy scanner installer...');
            this.binaryPath = await trivyInstaller.install(); // Should return full binary path
            core.info(`🛠️ Trivy binary path: ${this.binaryPath}`);
        } else {
            core.info('ℹ️ Skipping install — assuming Trivy is already installed.');
            this.binaryPath = 'trivy'; // fallback
        }
    }

    async scan(config) {
        try {
            const { scanTarget, severity } = config;

            if (!fs.existsSync(scanTarget)) {
                throw new Error(`Scan target does not exist: ${scanTarget}`);
            }

            const severityUpper = severity.toUpperCase();
            core.info(`🔍 Scanning: ${scanTarget}`);
            core.info(`⚠️  Severity: ${severityUpper}`);

            const reportPath = path.join(os.tmpdir(), `trivy-config-scan-${Date.now()}.json`);

            // Build args array
            const args = ['config', '--format', 'json', '--output', reportPath];
            // if (ignoreUnfixed) args.push('--ignore-unfixed');
             // Add severity filter if specified
            if (severityUpper && severityUpper !== 'ALL') {
                args.push('--severity', severityUpper);
            }
            args.push(scanTarget);

            core.info(`📝 Running: ${this.binaryPath} ${args.join(' ')}`);

            let stdoutOutput = '';
            let stderrOutput = '';

            const options = {
                listeners: {
                    stdout: (data) => { stdoutOutput += data.toString(); },
                    stderr: (data) => { stderrOutput += data.toString(); },
                },
                ignoreReturnCode: true,
                cwd: path.dirname(scanTarget),
            };

            const exitCode = await exec.exec(this.binaryPath, args, options);

            core.info(`✅ Scan completed with exit code: ${exitCode}`);
            if (stderrOutput && exitCode !== 0) {
                core.warning(`Stderr output: ${stderrOutput}`);
            }

            if (!fs.existsSync(reportPath)) {
                core.error(`❌ Output file was not created: ${reportPath}`);
                core.error(`Stdout: ${stdoutOutput}`);
                core.error(`Stderr: ${stderrOutput}`);
                throw new Error('Trivy did not produce output file');
            }

            const results = this.parseResults(reportPath);

            try { fs.unlinkSync(reportPath); } catch { }

            return results;

        } catch (error) {
            core.error(`❌ Trivy config scan failed: ${error.message}`);
            core.debug(error.stack);
            throw error;
        }
    }

    parseResults(jsonPath) {
        try {
            if (!fs.existsSync(jsonPath)) {
                return {
                    total: 0,
                    totalFiles: 0,
                    files: [],
                    critical: 0,
                    high: 0,
                    medium: 0,
                    low: 0
                };
            }

            const data = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));
            const files = [];
            let critical = 0;
            let high = 0;
            let medium = 0;
            let low = 0;
            let total = 0;

            if (Array.isArray(data.Results)) {
                data.Results.forEach(result => {
                    if (result.Target) {
                        files.push(result.Target);
                    }

             // Count misconfigurations by severity
                    if (Array.isArray(result.Misconfigurations)) {
                        result.Misconfigurations.forEach(misconfiguration => {
                            const severity = misconfiguration.Severity?.toUpperCase();
                            
                            switch(severity) {
                                case 'CRITICAL':
                                    critical++;
                                    break;
                                case 'HIGH':
                                    high++;
                                    break;
                                case 'MEDIUM':
                                    medium++;
                                    break;
                                case 'LOW':
                                    low++;
                                    break;
                            }
                            total++;
                        });
                    }
                });
            }

            const fileCount = files.length;
               // Log detected files
            if (fileCount > 0) {
                core.info(`📁 Detected config files: ${fileCount}`);
                files.forEach((file, index) => {
                    core.info(`   ${index + 1}. ${file}`);
                });
            }

            core.info(`\n📊 Vulnerability Summary:`);
            core.info(`   🔴 Critical: ${critical}`);
            core.info(`   🟠 High: ${high}`);
            core.info(`   🟡 Medium: ${medium}`);
            core.info(`   🟢 Low: ${low}`);
            core.info(`   📝 Total: ${total}`);

            return {
                total: fileCount,
                totalFiles: fileCount,
                files,
                critical: 0,
                high: 0,
                medium: 0,
                low: 0
            };

        } catch (err) {
            core.error(`❌ Failed to parse Trivy results: ${err.message}`);
            return {
                total: 0,
                totalFiles: 0,
                files: [],
                critical: 0,
                high: 0,
                medium: 0,
                low: 0
            };
        }
    }
}

module.exports = new ConfigScanner();
