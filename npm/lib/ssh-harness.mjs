import {spawn} from 'node:child_process';
import {lstat,rm} from 'node:fs/promises';
import {homedir} from 'node:os';
import {join} from 'node:path';

const idPattern=/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/;
const terminal=new Set(['COMPLETE','OWNER_BLOCKED','CANCELLED']);
const runtime=(env)=>env.PINS21_SSH_RUNTIME_DIR||join(process.platform==='darwin'?join(homedir(),'Library','Caches'):(env.XDG_CACHE_HOME||join(homedir(),'.cache')),'21pins-ssh');

// ponytail: one local writer; no detached renewal timer or worker-per-key model.
export class SSHObjectiveHarness {
 constructor({binary='21pins',cwd=process.cwd(),env=process.env,agentClass='pi',invoke}={}){
  this.binary=binary;this.cwd=cwd;this.env={...env};this.agentClass=agentClass;
  this.invoke=invoke||((args)=>this.runJSON(args));this.handles=new Map();this.closed=new Set();this.children=new Map();this.queue=Promise.resolve();
 }
 serial(fn){const p=this.queue.then(fn);this.queue=p.catch(()=>{});return p}
 async runJSON(args){return new Promise((resolve,reject)=>{const child=spawn(this.binary,args,{cwd:this.cwd,env:this.env,stdio:['ignore','pipe','ignore']});let text='';const timer=setTimeout(()=>{child.kill('SIGTERM');reject(Error('SSH lifecycle operation timed out'))},30000);child.stdout.on('data',b=>{text+=b;if(text.length>65536){child.kill('SIGTERM');reject(Error('SSH metadata too large'))}});child.on('error',()=>{clearTimeout(timer);reject(Error('SSH CLI unavailable'))});child.on('close',code=>{clearTimeout(timer);if(code!==0)return reject(Error('SSH lifecycle operation rejected'));try{resolve(JSON.parse(text))}catch{reject(Error('SSH metadata invalid'))}})})}
 ensureCapability(q){return this.serial(async()=>{
  if(q.type!=='ssh'||![q.host,q.role,q.objective,this.agentClass].every(x=>typeof x==='string'&&idPattern.test(x))||typeof q.purpose!=='string'||!q.purpose||q.purpose.length>256)throw Error('Invalid SSH scope');
  if(this.closed.has(q.objective))throw Error('Objective has terminated');
  const key=JSON.stringify([q.objective,q.host,q.role]);const previous=this.handles.get(key);
  if(previous){if(previous.purpose!==q.purpose)throw Error('SSH purpose is immutable');return previous}
  const args=['ssh','open','--host',q.host,'--role',q.role,'--objective',q.objective,'--purpose',q.purpose,'--agent',this.agentClass,'--json'];if(q.estimate)args.push('--estimate',q.estimate);if(q.maxLease)args.push('--max-lease',q.maxLease);
  const result=await this.invoke(args);if(!/^[a-f0-9]{32}$/.test(result.lease_id)||!['ACTIVE','PENDING_APPROVAL'].includes(result.state))throw Error('SSH authorization unavailable');
  const handle=Object.freeze({leaseId:result.lease_id,objective:q.objective,host:q.host,role:q.role,purpose:q.purpose,state:result.state});this.handles.set(key,handle);return handle;
 })}
 restore(handles){for(const h of handles){if(h&&/^[a-f0-9]{32}$/.test(h.leaseId)&&[h.objective,h.host,h.role].every(x=>typeof x==='string'&&idPattern.test(x))&&typeof h.purpose==='string'&&h.purpose.length<=256&&(h.terminalStatus===undefined||terminal.has(h.terminalStatus))){if(h.terminalStatus)this.closed.add(h.objective);this.handles.set(JSON.stringify([h.objective,h.host,h.role]),Object.freeze({...h}))}}}
 async retryClosures(){const pending=new Map(this.snapshot().filter(h=>h.terminalStatus).map(h=>[h.objective,h.terminalStatus]));const failures=[];for(const [objective,status]of pending){try{await this.onObjectiveStatus(objective,status)}catch{failures.push(objective)}}if(failures.length)throw Error('SSH pending closure remains unconfirmed')}
 snapshot(){return [...this.handles.values()]}
 async exec(handle,argv,{signal,stdio='inherit',timeoutMs=120000}={}){
  if(!Number.isInteger(timeoutMs)||timeoutMs<1||timeoutMs>120000)throw Error('SSH invocation timeout must be 1–120000ms');
  if(!Array.isArray(argv)||!argv.length||argv.some(x=>typeof x!=='string'||x.includes('\0')))throw Error('Invalid SSH command');
  if(this.closed.has(handle.objective)||![...this.handles.values()].some(h=>h.leaseId===handle.leaseId))throw Error('Objective lease unavailable');
  if(this.children.has(handle.objective))throw Error('One objective writer permitted');
  if(signal?.aborted)throw Error('SSH operation cancelled');
  return new Promise((resolve,reject)=>{const child=spawn(this.binary,['ssh','exec',handle.leaseId,'--',...argv],{cwd:this.cwd,env:this.env,stdio});this.children.set(handle.objective,child);
   const abort=()=>child.kill('SIGTERM');signal?.addEventListener('abort',abort,{once:true});
   const timer=setTimeout(abort,timeoutMs);
   const done=()=>{clearTimeout(timer);this.children.delete(handle.objective);signal?.removeEventListener('abort',abort)};
   child.on('error',()=>{done();reject(Error('Direct SSH invocation failed'))});child.on('close',code=>{done();if(signal?.aborted)reject(Error('SSH operation cancelled'));else resolve({exitCode:code??1})});
  })
 }
 async cleanupLocal(leaseId){if(!/^[a-f0-9]{32}$/.test(leaseId))throw Error('Invalid local lease');const p=join(runtime(this.env),leaseId);try{const info=await lstat(p);if(!info.isDirectory()||info.isSymbolicLink())throw Error('Unsafe lease cleanup');await rm(p,{recursive:true,force:true})}catch(e){if(e.code!=='ENOENT')throw e}}
 onObjectiveStatus(objective,status){if(!terminal.has(status))return Promise.resolve();this.closed.add(objective);this.children.get(objective)?.kill('SIGTERM');return this.serial(async()=>{const all=[...this.handles.entries()].filter(([,h])=>h.objective===objective);const errors=[];for(const [key,h]of all){const ending=h.terminalStatus||status;this.handles.set(key,Object.freeze({...h,state:'CLOSING',terminalStatus:ending}));let confirmed=false,clean=false;try{await this.invoke(['ssh',ending==='COMPLETE'?'complete':'cancel',h.leaseId]);confirmed=true}catch{errors.push('server close unconfirmed')}finally{try{await this.cleanupLocal(h.leaseId);clean=true}catch{errors.push('local cleanup failed')}}if(confirmed&&clean)this.handles.delete(key)}if(errors.length)throw Error('SSH objective cleanup incomplete; certificate expiry remains the fallback')})}
 async shutdown(){const objectives=new Set([...this.handles.values()].map(h=>h.objective));const failures=[];for(const objective of objectives){try{await this.onObjectiveStatus(objective,'CANCELLED')}catch{failures.push(objective)}}if(failures.length)throw Error('SSH shutdown cleanup incomplete')}
 installSignalHandlers(){const handler=async()=>{try{await this.shutdown()}finally{dispose();process.kill(process.pid,'SIGTERM')}};const dispose=()=>process.off('SIGTERM',handler);process.once('SIGTERM',handler);return dispose}
}
