const test=require('node:test');const assert=require('node:assert/strict');const fs=require('node:fs');const os=require('node:os');const path=require('node:path');const {createRequire}=require('node:module');

test('actual Pi extension closes only successful objective terminal transitions',async(t)=>{
 const packageRoot=process.env.PINS21_PI_PACKAGE;if(!packageRoot){t.skip('set PINS21_PI_PACKAGE to installed Pi package for loader test');return}
 const req=createRequire(path.join(packageRoot,'package.json'));const {createJiti}=req('jiti');const loader=createJiti(__filename,{alias:{typebox:req.resolve('typebox')}});
 const factory=(await loader.import('../lib/pi-ssh-extension.ts')).default;
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'21pins-pi-test-'));const binary=path.join(root,'fake-cli');const events=path.join(root,'events');
 fs.writeFileSync(binary,`#!/usr/bin/env node\nconst fs=require('fs');const action=process.argv[3];fs.appendFileSync(${JSON.stringify(events)},action+'\\n');console.log(JSON.stringify(action==='open'?{lease_id:'d'.repeat(32),state:'ACTIVE'}:{state:'COMPLETED'}));\n`,{mode:0o700});
 const previous=process.env.PINS21_BINARY;process.env.PINS21_BINARY=binary;const previousRuntime=process.env.PINS21_SSH_RUNTIME_DIR;process.env.PINS21_SSH_RUNTIME_DIR=path.join(root,'runtime');
 try{const handlers={};const tools={};const commands={};const saved=[];factory({on:(n,f)=>handlers[n]=f,registerTool:d=>tools[d.name]=d,registerCommand:(n,d)=>commands[n]=d,appendEntry:(n,d)=>saved.push(d)});
 await handlers.session_start({}, {cwd:root,sessionManager:{getBranch:()=>[]}});
 await tools.ssh_ensure_capability.execute('call',{host:'alpha',role:'observe',objective:'task',purpose:'synthetic'});
 assert.equal(saved.at(-1).handles.length,1);
 await handlers.tool_result({toolName:'objective_control',input:{action:'complete'},isError:false,content:[{type:'text',text:'Completion requires more evidence.'}]});
 assert.equal(fs.readFileSync(events,'utf8').trim(),'open');
 await handlers.tool_result({toolName:'objective_control',input:{action:'complete'},isError:false,content:[{type:'text',text:'Objective complete.'}]});
 assert.equal(fs.readFileSync(events,'utf8').trim(),'open\ncomplete');assert.equal(saved.at(-1).handles.length,0);
 await tools.ssh_ensure_capability.execute('block-call',{host:'alpha',role:'observe',objective:'blocked-task',purpose:'synthetic'});
 await handlers.tool_result({toolName:'objective_control',input:{action:'block'},isError:false,content:[{type:'text',text:'Objective owner-blocked.'}]});
 assert.equal(fs.readFileSync(events,'utf8').trim(),'open\ncomplete\nopen\ncancel');assert.equal(saved.at(-1).handles.length,0);
 await handlers.session_shutdown({reason:'quit'});assert.equal(saved.at(-1).handles.length,0);
 }finally{if(previous===undefined)delete process.env.PINS21_BINARY;else process.env.PINS21_BINARY=previous;if(previousRuntime===undefined)delete process.env.PINS21_SSH_RUNTIME_DIR;else process.env.PINS21_SSH_RUNTIME_DIR=previousRuntime;fs.rmSync(root,{recursive:true,force:true})}
});
