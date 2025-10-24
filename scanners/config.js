const core = require('@actions/core');
const exec = require('@actions/exec');
const fs = require('fs');
const os = require('os');
const path = require('path');

class ConfigScanner {
    constructor() {
        this.name = 'Trivy config Scanner';
        this.binaryPath = null; // Assuming Trivy is already installed and path set in config.js
    }

    async install() {
        const path = require('path');
        const os = require('os');
        const trivyInstaller = require('./trivy');
        if (typeof trivyInstaller.install === 'function') {
            core.info('📦 Installing Trivy for Config Scanner using Trivy scanner installer...');
            await trivyInstaller.install();
            // Ensure PATH includes cached binary location
            process.env.PATH = `${process.env.PATH}:${path.join(os.homedir(), '.cache', 'actions', 'ntu-scanner-trivy', 'v0.48.0')}`;
            core.info(`🛠️ Updated PATH for Trivy: ${process.env.PATH}`);
        } else {
            core.info('ℹ️ Skipping install — Trivy installer not found, assuming it’s already installed.');
        }
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
            const reportPath = path.join(os.tmpdir(), `trivy-scan-results-${Date.now()}.json`);

            // Build command
            const command = `trivy config --format json --output ${reportPath} ${scanTarget}`;

             // 🧭 Debug PATH and check if Trivy is found
            core.info(`🧭 Current PATH: ${process.env.PATH}`);
            await exec.exec('which trivy', [], { ignoreReturnCode: true });
            
            // Execute the command
            core.info(`📝 Running: ${command}`);

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

            const exitCode = await exec.exec(command, [], options);

            core.info(`✅ Scan completed with exit code: ${exitCode}`);

            // Log any stderr (but not as error if exit code is 0)
            if (stderrOutput && exitCode !== 0) {
                core.warning(`Stderr output: ${stderrOutput}`);
            }

            // Check if the output file was created
            if (!fs.existsSync(reportPath)) {
                core.error(`❌ Output file was not created: ${reportPath}`);
                core.error(`Stdout: ${stdoutOutput}`);
                core.error(`Stderr: ${stderrOutput}`);
                throw new Error('Trivy did not produce output file');
            }

            // Parse results
            core.info(`📄 Reading results from: ${reportPath}`);
            const results = this.parseResults(reportPath);

            // Clean up
            try {
                if (fs.existsSync(reportPath)) {
                    fs.unlinkSync(reportPath);
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
module.exports = new ConfigScanner();
