const test = require('node:test');
const assert = require('node:assert/strict');
const { platformPackageName, TARGETS } = require('../lib/platform');

test('platformPackageName maps supported targets', () => {
  assert.equal(platformPackageName('darwin', 'arm64'), '@privacyguy/21pins-darwin-arm64');
  assert.equal(platformPackageName('darwin', 'x64'), '@privacyguy/21pins-darwin-x64');
  assert.equal(platformPackageName('linux', 'arm64'), '@privacyguy/21pins-linux-arm64');
  assert.equal(platformPackageName('linux', 'x64'), '@privacyguy/21pins-linux-x64');
});

test('platformPackageName rejects unsupported targets', () => {
  assert.throws(() => platformPackageName('win32', 'x64'), /Unsupported platform/);
});

test('TARGETS only covers intended operating systems', () => {
  assert.deepEqual(Object.keys(TARGETS).sort(), ['darwin/arm64', 'darwin/x64', 'linux/arm64', 'linux/x64']);
});
