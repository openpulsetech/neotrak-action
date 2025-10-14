// Set up GitHub Actions environment for local testing
process.env.INPUT_SCAN_TYPE = 'fs';
process.env.INPUT_SCAN_TARGET = '.';
process.env.INPUT_SEVERITY = 'HIGH,CRITICAL';
process.env.INPUT_EXIT_CODE = '0';
process.env.INPUT_IGNORE_UNFIXED = 'false';
process.env.INPUT_FORMAT = 'table';

// Set GitHub Actions environment variables
process.env.RUNNER_TEMP = require('os').tmpdir();
process.env.RUNNER_TOOL_CACHE = require('path').join(require('os').homedir(), '.cache', 'actions');
process.env.RUNNER_WORKSPACE = process.cwd();
process.env.GITHUB_WORKSPACE = process.cwd();

console.log('🧪 Starting NTU Security Scanner local test...');
console.log('Environment variables set for local testing');

require('./index.js');
