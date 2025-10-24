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
            const { scanTarget, severity, ignoreUnfixed } = config;

            if (!fs.existsSync(scanTarget)) {
                throw new Error(`Scan target does not exist: ${scanTarget}`);
            }

            const severityUpper = severity.toUpperCase();
            core.info(`🔍 Scanning: ${scanTarget}`);
            core.info(`⚠️  Severity: ${severityUpper}`);

            const reportPath = path.join(os.tmpdir(), `trivy-config-scan-${Date.now()}.json`);

            // Build args array
            const args = ['config', '--format', 'json', '--output', reportPath];
            if (ignoreUnfixed) args.push('--ignore-unfixed');
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

            try { fs.unlinkSync(reportPath); } catch {}

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
                return { total: 0, critical: 0, high: 0, medium: 0, low: 0, vulnerabilities: [] };
            }

            const data = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));
            let critical = 0, high = 0, medium = 0, low = 0;
            const vulnerabilities = [];

            if (Array.isArray(data.Results)) {
                data.Results.forEach(result => {
                    if (Array.isArray(result.Vulnerabilities)) {
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
                                case 'CRITICAL': critical++; break;
                                case 'HIGH': high++; break;
                                case 'MEDIUM': medium++; break;
                                case 'LOW': low++; break;
                            }
                        });
                    }
                });
            }

            return { total: critical + high + medium + low, critical, high, medium, low, vulnerabilities };

        } catch (err) {
            core.error(`❌ Failed to parse Trivy results: ${err.message}`);
            return { total: 0, critical: 0, high: 0, medium: 0, low: 0, vulnerabilities: [] };
        }
    }
}

module.exports = new ConfigScanner();
