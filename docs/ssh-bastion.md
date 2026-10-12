# Explicit native SSH bastion transport

Owner authorized reuse of the existing management route for Mac → VM 221, rather than exposing the VM. This supersedes the original direct-only client restriction **only for explicitly configured issuer host scopes**. No new proxy service, target agent, trust installation, network change or VM 220 work.

## Binding and transport

Optional issuer host field `ssh_jump_alias` is a single validated identifier. Host registration accepts `--jump-alias`; existing configuration updates require an explicit reviewed edit. The field is copied to immutable lease metadata and included in its scope digest; policy drift stops issuance. Empty field retains direct operation and previous direct policy digest. Arbitrary inherited ProxyCommand/ProxyJump settings remain ignored.

The final requester SSH still uses local ephemeral key/certificate, account pinned by issuer, `-F /dev/null`, normal strict target known-host verification, no agent, multiplexing, PTY or forwarding outside role policy. For an approved hop, 21pins builds a fixed native `ssh -W host:port management-alias` ProxyCommand. Unlike plain `-J` under final `-F /dev/null`, this intentionally lets the hop reuse the owner's existing management identity configuration while explicitly overriding agent use/forwarding, strict host verification, batch mode, nested proxies, local commands, remote commands, PTY and multiplexing. Native `-W` is the only hop forwarding operation. Final host/port are validated and shell-quoted concrete values, not expandable `%h/%p` strings; percent/metacharacter injection and multi-hop/user@alias grammar fail closed.

The hop's existing owner SSH configuration is trusted local configuration: Include/Match exec may run owner-configured local commands as they already do for normal management SSH. No new configuration/trust is installed on the management host. File-accessible existing management identity was verified without an agent; agent-only identities are not silently accommodated by exposing the CA socket.

Requester SSH/config-resolution environments are allowlisted to PATH/HOME/USER/LOGNAME. API tokens, CA agent environment, unrelated secrets and provider credentials never reach SSH or its management child. Management `SendEnv` therefore cannot leak those credentials. Strict verification applies to both management and final target; known-host single filenames with spaces are quoted for native option parsing.

CA private storage/signing agent and ephemeral requester key remain on the Mac. The bastion supplies an opaque TCP channel; **the 21pins certificate authenticates pins-agent on the final VM**, with existing critical certificate/principal/server forced-command gate. Target certificate validity, immutable objective/host/role/user/key binding, renewal ceilings, completion and residual-window behavior are unchanged.

## Verified VM 221 path

Existing management TCP forwarding was already allowed; no sshd/firewall/route changes were required. Only VM 221's local issuer host was explicitly bound to `fipi`, with owner-only pre-change config backup. Target/management trust files and native policies were not altered.

```sh
# Repository-local current binary; does not replace an unrelated/global installation.
go build -o ./21pins ./cmd/21pins

# Reproducible opt-in actual Mac API-only CLI and final target smoke:
PINS21_VM221_MAC_DOGFOOD=1 go test ./cmd/21pins \
  -run TestApprovedVM221MacBastionCLI -count=1 -v -timeout 110s
```

Test runs the actual compiled CLI against a local loopback API using the real issuer/agent, local ephemeral scoped test tokens and local requester keys. Explicit approval precedes issuance. Fresh Mac→bastion→VM connections prove all three observe operations, arbitrary shell/chaining/substitution/extra-argument/wrapper denials, changed final host-key rejection, same-key API renewal and terminal execution/key cleanup. Temporary API/tokens/runtime files are removed; required issuance/audit metadata remains owner-only. No private key, signing material, socket or token is copied to the management host.

For normal execution select the current binary (Pi/Node may set `PINS21_BINARY` to this repository's `21pins`) and `PINS21_SSH_CONFIG_FILE` to `/Users/claw/Library/Application Support/21pins/ssh/ssh_config_vm221`. Reuse the established local issuer/API and existing narrowly scoped requester/approver token workflow; the smoke-test's ephemeral API/tokens are deliberately not permanent runtime grants.

If a future management policy denies `-W`, fail closed. Minimum owner decision is authorized SSH TCP forwarding to this one target port (ideally PermitOpen target:22 for the existing management identity), not public VM exposure, CA copying, agent forwarding or target firewall changes. This installation did not need that decision.
