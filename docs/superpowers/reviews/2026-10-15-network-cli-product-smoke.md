# Public network CLI — synthetic product smoke

**Baseline:** accepted `a4885e0`. **Decision:** no blocking product-model issue; proceed to a SMALL OpenWrt/GL.iNet evidence plan, not implementation. This is not mass-market launch approval.

## Method and boundary

21 command/presentation cases. Fifteen actual compiled-CLI invocations used disposable owner-local synthetic registry state: import, discovery, all six requested inspect forms, four offline verification requests, missing-grant output, help and source-syntax edge cases. No real state, credentials, login, device, route, interface inventory or network probe was used. Discovery performed its existing executable-presence check only.

Six result-presentation cases used an isolated temporary COPY of the generic package, existing CLI `Run`, synthetic grants/subject and injected sealed `synthetic_runtime` facts. They exercised gateway/VPN/access/isolation VERIFIED, an actual-format synthetic isolation VIOLATED, and incomplete-evidence UNVERIFIED. These are presentation tests, **not native/network verification**; `synthetic:true` remained visible. All temporary state, copies, binaries and records were removed. Product source/contracts were not edited.

The smoke's initial manifest used `mode` instead of the actual `access_mode` field; strict import correctly rejected it. The corrected fixture passed. This illustrates schema/error discoverability, not a reason to loosen validation.

## Results by public surface

| Surface | Observed | Product assessment |
| --- | --- | --- |
| `discover` | Six registered/tool-presence suggestions,149 JSON lines; confidence/missing data explicit. | No scans or claimed live enrollment. Name sounds like device finding; explain “saved objects and local client suggestions.” |
| `inspect gateway edge` | Alias and suppressed endpoint; `kind:network_gateway`;9 lines. | Correct LLM/network separation internally, but public label leaks storage terminology. Display “gateway” without changing serialized kind. |
| `inspect network home` | Alias, revision, suppressed endpoint;9 lines. | Understandable identity, but does not explain source membership or that this is saved metadata, not a connectivity check. |
| `inspect vpn private-link` | Same safe metadata plus implementation;10 lines. | `vpn` remains the right stable object; no need to rename it. |
| `inspect service name-service` | Safe alias/implementation, endpoint suppression;10 lines. | No endpoint leak. Explain the saved service and how to check access without exposing addresses. |
| `inspect policy home-names` | `allow`,45 lines of immutable source/endpoint/path refs and hashed realm. | Intent is stable, but matching this policy to friendly networks/services requires extra joins. Preserve JSON; add a future friendly intent summary. |
| `inspect wireguard private-link` | Same VPN ref/revision, expert implementation view. | Good: not a second object/registry. Keep WireGuard optional expertise. |
| Gateway/VPN `--request` |32/42 lines; exact4 and conditional6 properties, immutable targets and digests. | Machine contract correct. `interface_binding`, `route_ownership` and `policy_scope` require engineering knowledge; future prose should explain only what was requested. |
| Access/isolation `--request` |94/110 lines; source/service/family/UDP/TCP/direct scope and policies retained. | No silent coverage narrowing. Request is an authorization descriptor, not a completed check; label that plainly in a future human view. |
| Gateway/VPN synthetic result |172/294 lines with explicit exclusions. | VERIFIED is scoped, not whole-network health or attached-policy compliance. Exclusions are correct but buried. |
| Access/isolation synthetic result |734/1438 lines; friendly context, tuple properties, assurance, evidence and exclusions. | Model handles “deny behaved correctly = VERIFIED.” A user should not need to infer that from `dns.denied:true`. Lead a future human summary with expected allow/block and observed result. |
| Missing grant | Exit2, `UNVERIFIED`, `network_missing_binding`, no command context. | Recovery UX gap: error conflates missing authority with missing object/native binding. Do not bypass or weaken admission to fix copy. |
| Help/source syntax | `inspect gateway edge --help` → exit3 generic invalid metadata. Isolation takes positional source; access uses `--from`; conflicting isolation `--from home` produced exit3 in this fixture. | Syntax is learnable but inconsistent. Improve usage/errors first; do not redesign working positional/alias contracts for style. |

## Ranked findings

1. **P1 mass-market usability, not a product-model blocker:** successful default output is the complete evidence JSON. A1438-line isolation result does not let a non-engineer confidently answer “Were visitors blocked from this service?” `--json` currently has the same output. A later bounded presentation layer can lead with friendly source/service, expected allow/block, scoped verdict, missing evidence and exclusions, retaining exact JSON contracts and evidence detail.
2. **P1 first-run recovery UX, not an authority/model defect:** missing grant and invalid import/help return generic codes without the needed action. Future usage should distinguish “create/select the requested existing grant,” “register/bind the object,” “unsupported evidence” and “invalid arguments.” No auto-login, inferred membership, grants or permission expansion.
3. **P2 terminology:** `network_gateway`, revision/realm hashes, `route_ownership` and `interface_binding` are useful machine/expert terms, not the mass-market headline. No actual route tables, fwmarks, interfaces or UCI knowledge was necessary to invoke the reviewed commands after synthetic onboarding, but understanding all default output currently requires that background. Do not rename internal properties/schema just for style.
4. **P2 distinctions:** policy = saved expected behavior; access = a source→service question; verification = evidence evaluation of that question. A configured deny passing is VERIFIED; a leak is VIOLATED; incomplete proof is UNVERIFIED. The current data supports these distinctions, but the default prose does not teach them.
5. **P2 syntax/discovery clarity:** preserve canonical `vpn` and the expert WireGuard view. Document passive discovery, source placement and argument errors before considering aliases/new commands.
6. **P1 onboarding usability, not a product-model blocker:** this smoke started from an explicitly prepared synthetic manifest. A new user currently needs owner-local `0600` JSON containing native namespace/context/interface and firewall selectors before those friendly aliases work; passive discovery does not create those bindings. That setup still requires infrastructure knowledge. A later guided, explicitly authorized binding experience can hide the mechanics without inventing membership, auto-enrolling devices, weakening admission or changing public objects. This review does not claim frictionless first-run readiness.

## Product-model gate

**CLEAR for adapter planning.** No evidence of needing new public objects, a separate GL.iNet gateway model, changed verdict semantics, altered policy/grant contracts, broader claims or vendor commands. The human-presentation/first-run issues must be addressed before a mass-market release, but do not block validating the existing generic gateway abstraction. No UX fixes were implemented in this review and they are not silently bundled into the adapter plan.
