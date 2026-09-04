#!/usr/bin/env node
const pkg = require('../package.json');

const tag = process.env.GITHUB_REF_NAME || process.argv[2] || '';
if (!tag) {
  console.error('Missing tag. Pass v<package-version> or set GITHUB_REF_NAME.');
  process.exit(1);
}

const expected = `v${pkg.version}`;
if (tag !== expected) {
  console.error(`Tag/package mismatch: expected ${expected}, got ${tag}`);
  process.exit(1);
}

console.log(`Tag matches package version: ${tag}`);
