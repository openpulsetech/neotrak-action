const core = require('@actions/core');
const exec = require('@actions/exec');
const { execSync } = require('child_process');
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
            const { scanTarget, severity, workspaceDir } = config;

            // Use workspace directory as the base for scanning
            const targetPath = path.isAbsolute(scanTarget)
                ? scanTarget
                : path.resolve(workspaceDir || process.cwd(), scanTarget);

            if (!fs.existsSync(targetPath)) {
                throw new Error(`Scan target does not exist: ${targetPath}`);
            }

            const severityUpper = severity.toUpperCase();
            core.info(`🔍 Scanning: ${targetPath}`);
            core.info(`⚠️  Severity: ${severityUpper}`);

            const reportPath = path.join(os.tmpdir(), `trivy-config-scan-${Date.now()}.json`);

            // Build command string
            let command = `${this.binaryPath} config --format json --output ${reportPath}`;

            // Add severity filter if specified
            if (severityUpper && severityUpper !== 'ALL') {
                command += ` --severity ${severityUpper}`;
            }
            command += ` ${targetPath}`;

            core.info(`📝 Running: ${command}`);

            // Use workspace directory as working directory
            const workingDir = workspaceDir || process.cwd();
            core.info(`📂 Working directory: ${workingDir}`);

            try {
                const output = execSync(command, {
                    cwd: workingDir,
                    encoding: 'utf8',
                    stdio: ['pipe', 'pipe', 'pipe']
                });

                core.info(`✅ Scan completed successfully`);
                if (output) {
                    core.debug(`Output: ${output}`);
                }
            } catch (error) {
                // execSync throws on non-zero exit code, but that's okay for Trivy
                if (error.stdout) {
                    core.debug(`Stdout: ${error.stdout}`);
                }
                if (error.stderr) {
                    core.warning(`Stderr: ${error.stderr}`);
                }
                core.info(`✅ Scan completed with exit code: ${error.status || 0}`);
            }

            if (!fs.existsSync(reportPath)) {
                core.error(`❌ Output file was not created: ${reportPath}`);
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
                    low: 0,
                    misconfigurations: [],
                    configScanResponseDto: {
                        ArtifactName: '',
                        ArtifactType: '',
                        Results: []
                    }
                };
            }

            const data = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));
            const files = [];
            const misconfigurations = [];
            let critical = 0;
            let high = 0;
            let medium = 0;
            let low = 0;
            let total = 0;

            // Build the API-compatible structure
            const configResultDtos = [];

            if (Array.isArray(data.Results)) {
                data.Results.forEach(result => {
                    if (result.Target) {
                        files.push(result.Target);
                    }

                    // Map Trivy result to ConfigResultDto
                    const trivyMisconfigurations = [];

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

                            // For display purposes (legacy)
                            misconfigurations.push({
                                File: result.Target || 'Unknown',
                                Issue: misconfiguration.Title || misconfiguration.ID || 'N/A',
                                Severity: severity || 'UNKNOWN',
                                Line: misconfiguration.CauseMetadata?.StartLine || 'N/A'
                            });

                            // For API (ConfigMisconfigurationDto)
                            trivyMisconfigurations.push({
                                ID: misconfiguration.ID || '',
                                Title: misconfiguration.Title || '',
                                Description: misconfiguration.Description || '',
                                Severity: severity || 'UNKNOWN',
                                PrimaryURL: misconfiguration.PrimaryURL || '',
                                Query: misconfiguration.Query || ''
                            });
                        });
                    }

                    // Add ConfigResultDto
                    if (result.Target) {
                        configResultDtos.push({
                            Target: result.Target || '',
                            Class: result.Class || '',
                            Type: result.Type || '',
                            Misconfigurations: trivyMisconfigurations
                        });
                    }
                });
            }

            const fileCount = files.length;
            // Log detected files and misconfigurations
            core.info(`📁 Total config files scanned: ${fileCount}`);
            core.info(`⚠️  Total misconfigurations found: ${total}`);
            if (fileCount > 0) {
                files.forEach((file, index) => {
                    const fileResults = data.Results.find(r => r.Target === file);
                    const fileMisconfigCount = fileResults?.Misconfigurations?.length || 0;
                    core.info(`   ${index + 1}. ${file} (${fileMisconfigCount} issues)`);
                });
            }

            // Build ConfigScanResponseDto
            const configScanResponseDto = {
                ArtifactName: data.ArtifactName || '',
                ArtifactType: data.ArtifactType || '',
                Results: configResultDtos
            };

            return {
                total: total,  // ✅ Return the actual count of misconfigurations, not file count
                totalFiles: fileCount,
                files,
                critical,
                high,
                medium,
                low,
                misconfigurations,
                configScanResponseDto  // ✅ Add the API-compatible structure
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
                low: 0,
                misconfigurations: [],
                configScanResponseDto: {
                    ArtifactName: '',
                    ArtifactType: '',
                    Results: []
                }
            };
        }
    }
}

module.exports = new ConfigScanner();
