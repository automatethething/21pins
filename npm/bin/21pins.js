#!/usr/bin/env node
const { spawnSync } = require('node:child_process');
const { platformBinaryPath } = require('../lib/platform');

let binary;
try {
  binary = process.env.PINS21_BINARY || platformBinaryPath();
} catch (error) {
  console.error(`21pins: ${error.message}`);
  process.exit(1);
}

const result = spawnSync(binary, process.argv.slice(2), { stdio: 'inherit' });
if (result.error) {
  console.error(`21pins: failed to start binary: ${result.error.message}`);
  process.exit(1);
}
process.exit(typeof result.status === 'number' ? result.status : 1);
