#!/usr/bin/env node
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..', '..');
const dist = path.join(root, 'dist');
const targets = [
  ['darwin', 'arm64', 'platforms/darwin-arm64/bin/21pins'],
  ['darwin', 'amd64', 'platforms/darwin-x64/bin/21pins'],
  ['linux', 'arm64', 'platforms/linux-arm64/bin/21pins'],
  ['linux', 'amd64', 'platforms/linux-x64/bin/21pins'],
];

function findBinary(goos, goarch) {
  if (!fs.existsSync(dist)) throw new Error(`Missing GoReleaser dist directory: ${dist}`);
  const needle = `_${goos}_${goarch}`;
  for (const entry of fs.readdirSync(dist, { withFileTypes: true })) {
    if (!entry.isDirectory() || !entry.name.includes(needle)) continue;
    const candidate = path.join(dist, entry.name, '21pins');
    if (fs.existsSync(candidate)) return candidate;
  }
  throw new Error(`Missing GoReleaser binary for ${goos}/${goarch}`);
}

for (const [goos, goarch, destRel] of targets) {
  const source = findBinary(goos, goarch);
  const dest = path.join(__dirname, '..', destRel);
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.copyFileSync(source, dest);
  fs.chmodSync(dest, 0o755);
  console.log(`${path.relative(root, source)} -> npm/${destRel}`);
}
