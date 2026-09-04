#!/usr/bin/env node
const fs = require('node:fs');
const path = require('node:path');
const rootPkg = require('../package.json');
const { TARGETS } = require('../lib/platform');

const expected = {
  '@privacyguy/21pins-darwin-arm64': { dir: 'darwin-arm64', os: 'darwin', cpu: 'arm64' },
  '@privacyguy/21pins-darwin-x64': { dir: 'darwin-x64', os: 'darwin', cpu: 'x64' },
  '@privacyguy/21pins-linux-arm64': { dir: 'linux-arm64', os: 'linux', cpu: 'arm64' },
  '@privacyguy/21pins-linux-x64': { dir: 'linux-x64', os: 'linux', cpu: 'x64' },
};

for (const [target, packageName] of Object.entries(TARGETS)) {
  if (!expected[packageName]) throw new Error(`Unexpected target package for ${target}: ${packageName}`);
}

for (const [name, meta] of Object.entries(expected)) {
  const declared = rootPkg.optionalDependencies && rootPkg.optionalDependencies[name];
  if (declared !== rootPkg.version) throw new Error(`${name} optionalDependency must equal root version ${rootPkg.version}, got ${declared}`);
  const pkgPath = path.join(__dirname, '..', 'platforms', meta.dir, 'package.json');
  const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
  if (pkg.name !== name) throw new Error(`${pkgPath} has wrong name ${pkg.name}`);
  if (pkg.version !== rootPkg.version) throw new Error(`${pkgPath} version must equal ${rootPkg.version}`);
  if (!pkg.os || pkg.os[0] !== meta.os) throw new Error(`${pkgPath} has wrong os`);
  if (!pkg.cpu || pkg.cpu[0] !== meta.cpu) throw new Error(`${pkgPath} has wrong cpu`);
}

console.log('Platform package manifests match root package.');
