import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import { SSHObjectiveHarness } from "./ssh-harness.mjs";

// Opt-in only: pi --extension ./examples/pi-ssh-leases.ts
// Metadata only. No SSH output, credentials or commands are appended to session state.
export default function (pi: ExtensionAPI) {
 let harness: SSHObjectiveHarness;
 const persist = () => pi.appendEntry("21pins-ssh-handles", { handles: harness.snapshot() });
 pi.on("session_start", async (_event, ctx) => {
  harness = new SSHObjectiveHarness({ cwd: ctx.cwd, binary: process.env.PINS21_BINARY || "21pins", agentClass: "pi" });
  let handles: unknown[] = [];
  for (const entry of ctx.sessionManager.getBranch()) {
   if (entry.type === "custom" && entry.customType === "21pins-ssh-handles") handles = (entry.data as {handles:unknown[]}).handles || [];
  }
  harness.restore(handles);
  try {await harness.retryClosures();} finally {persist();}
 });
 pi.registerTool({
  name: "ssh_ensure_capability", label: "Objective SSH lease",
  description: "Request purpose-bound SSH authorization for this objective. Existing host-role policy or separate human approval is required; this tool cannot expand privileges. Returns a local handle, never keys or certificates.",
  parameters: Type.Object({host:Type.String(),role:Type.String(),objective:Type.String(),purpose:Type.String(),estimate:Type.Optional(Type.String())}),
  async execute(_id, q) {
   if (!harness) throw new Error("SSH lifecycle not started");
   const h = await harness.ensureCapability({type:"ssh", ...q}); persist();
   return {content:[{type:"text",text:JSON.stringify(h)}],details:h};
  }
 });
 const finishAll = async (status: string) => {
  if (!harness) return;
  let failed=false;
  try { for (const id of new Set(harness.snapshot().map((h:{objective:string}) => h.objective))) {try{await harness.onObjectiveStatus(id,status);}catch{failed=true;}} }
  finally { persist(); }
  if(failed)throw new Error("SSH lease closure incomplete; retry metadata retained");
 };
 // Do not close on agent_end/model-call completion; an objective may span workers/turns.
 pi.on("tool_result", async (event) => {
  if (event.toolName !== "objective_control" || event.isError) return;
  const text = event.content.filter((c) => c.type === "text").map((c) => c.type === "text" ? c.text : "").join("\n");
  if (event.input.action === "complete" && text.trim() === "Objective complete.") await finishAll("COMPLETE");
  else if (event.input.action === "block" && /^(?:Objective (?:owner[-_ ]?)?blocked(?:[.:](?:\s|$)|$)|OWNER_BLOCKED\b)/i.test(text.trim())) await finishAll("OWNER_BLOCKED");
 });
 pi.registerCommand("ssh-stop", {description:"Cancel this session's objective SSH leases and remove local keys",handler:async()=>finishAll("CANCELLED")});
 pi.on("session_shutdown", async () => {if(harness){try{await harness.shutdown()}finally{persist()}}});
 // Other harnesses should call onObjectiveStatus(id, COMPLETE|OWNER_BLOCKED|CANCELLED)
 // and shutdown() themselves; never infer terminal status from model prose.
}
