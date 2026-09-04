const path = require('node:path');

const TARGETS = {
  'darwin/arm64': '@privacyguy/21pins-darwin-arm64',
  'darwin/x64': '@privacyguy/21pins-darwin-x64',
  'linux/arm64': '@privacyguy/21pins-linux-arm64',
  'linux/x64': '@privacyguy/21pins-linux-x64',
};

function platformPackageName(platform = process.platform, arch = process.arch) {
  const name = TARGETS[`${platform}/${arch}`];
  if (!name) {
    throw new Error(`Unsupported platform: ${platform}/${arch}. Install from source instead.`);
  }
  return name;
}

function platformBinaryPath(platform = process.platform, arch = process.arch) {
  const packageName = platformPackageName(platform, arch);
  return path.join(require.resolve(`${packageName}/package.json`), '..', 'bin', '21pins');
}

module.exports = { platformPackageName, platformBinaryPath, TARGETS };
