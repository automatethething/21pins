# Packaging and installs

21pins is a Go CLI. The package channels should install the binary only; local tokens, provider keys, grants, receipts, and usage rows remain in the state file.

Default state path comes from Go's `os.UserConfigDir()`:

```text
Linux:  ~/.config/21pins/state.json
macOS:  ~/Library/Application Support/21pins/state.json
```

If `PINS21_STATE_PATH` is set, that file is authoritative; back it up instead.

## Release artifacts

GitHub Releases are built from `.goreleaser.yaml`. Releases are manual for now; if a CI release workflow is added later, pin action SHAs and GoReleaser versions before granting `contents: write`.

Dry-run locally:

```bash
goreleaser release --snapshot --clean --skip=publish
```

Release artifacts expected by npm/Homebrew:

```text
21pins_<version>_darwin_amd64.tar.gz
21pins_<version>_darwin_arm64.tar.gz
21pins_<version>_linux_amd64.tar.gz
21pins_<version>_linux_arm64.tar.gz
checksums.txt
```

Do not publish releases, push tags, or publish packages without owner approval. Before publishing, ensure the git tag matches `npm/package.json`:

```bash
cd npm
npm run check:tag -- v0.1.1
```

## Homebrew

GoReleaser builds GitHub Release archives. `homebrew/Formula/twenty-one-pins.rb.template` is the formula template; fill in `{{VERSION}}` and archive SHA-256 placeholders from `checksums.txt`, then copy it to `automatethething/homebrew-tap/Formula/twenty-one-pins.rb` with alias `Aliases/21pins`.

Template check:

```bash
ruby homebrew/check-template.rb
```

Install path:

```bash
brew tap automatethething/tap
brew trust automatethething/tap
brew search 21pins
brew install 21pins
```

`brew search 21pins` only finds the formula after `brew tap automatethething/tap`; before that, Homebrew searches core and already-installed taps only.

`twenty-one-pins` is the internal formula name because Homebrew/Ruby cannot use a class name that starts with a digit. The tap exposes alias `21pins`, so user-facing commands stay lowercase.

Upgrade path:

```bash
brew upgrade 21pins
```

The upgrade replaces the binary only. It does not touch the 21pins state file.

## npm

The npm package lives in `npm/`. It does not run a remote-download postinstall. The root package exposes the unscoped `21pins` bin wrapper and depends on optional platform packages such as `@privacyguy/21pins-darwin-arm64`, each of which carries one prebuilt binary.

Local checks:

```bash
cd npm
npm test
npm run check:platforms
npm pack --dry-run
```

After a local GoReleaser snapshot build, prepare and verify platform packages with:

```bash
cd npm
npm run prepare:platforms
npm run pack:platforms
```

For an approved npm release, publish all four platform packages first, then publish the root wrapper package. Use the same version everywhere:

```bash
cd npm
npm run check:tag -- v0.1.1
npm run prepare:platforms
npm run pack:platforms
(cd platforms/darwin-arm64 && npm publish --access public)
(cd platforms/darwin-x64 && npm publish --access public)
(cd platforms/linux-arm64 && npm publish --access public)
(cd platforms/linux-x64 && npm publish --access public)
npm publish
```

Install path:

```bash
npm install -g 21pins
```

Upgrade path:

```bash
npm update -g 21pins
```

The upgrade replaces the npm package/binary only. It does not touch the 21pins state file.
