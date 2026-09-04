#!/usr/bin/env node
const { execFileSync } = require('node:child_process');
const path = require('node:path');

const dirs = ['darwin-arm64', 'darwin-x64', 'linux-arm64', 'linux-x64'];
for (const dir of dirs) {
  const cwd = path.join(__dirname, '..', 'platforms', dir);
  execFileSync('npm', ['pack', '--dry-run'], { cwd, stdio: 'inherit' });
}
