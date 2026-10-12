#!/usr/bin/env python3
"""Isolated root helper validation; never calls or changes a real service VM.
WG tool and all keys/state are synthetic fixtures, NOT real client/E2E evidence.
"""
import importlib.util,pathlib,sys
sys.dont_write_bytecode=True
spec=importlib.util.spec_from_file_location('isolated_dns',pathlib.Path(__file__).with_name('ssh-dns-admin-isolated.py'))
runner=importlib.util.module_from_spec(spec);spec.loader.exec_module(runner)
runner.REMOTE=r'''
import pathlib,tempfile,subprocess,json,sys,base64,gzip,hashlib,shutil,fcntl,traceback
payload=json.load(sys.stdin);root=pathlib.Path(tempfile.mkdtemp(prefix='21pins-wg-chroot-',dir='/tmp'));root.chmod(0o755)
try:
 for d in ['etc/21pins','etc/wireguard','var/lib/21pins/wg-beryl','usr/local/bin','usr/bin','dev']:(root/d).mkdir(parents=True,exist_ok=True)
 (root/'dev/null').write_bytes(b'');(root/'dev/null').chmod(0o666)
 for name,dest in [('21pins','usr/local/bin/21pins'),('tools','usr/bin/wg')]:
  p=root/dest;p.write_bytes(gzip.decompress(base64.b64decode(payload[name])));p.chmod(0o755)
 state=root/'var/lib/21pins/wg-beryl';state.chmod(0o700)
 peer=base64.b64encode(bytes([1])*32).decode();other=base64.b64encode(bytes([2])*32).decode()
 def private(p,b):p.write_bytes(b);p.chmod(0o600)
 m={'workspace':'local','host':'wg-gateway','interface':'wg0','peer_public_key':peer,'wireguard_config':'/etc/wireguard/wg0.conf','allowed_ip':'10.66.66.5/32'}
 manifest=root/'etc/21pins/wg-beryl.json'
 def install(m):
  b=json.dumps(m).encode();private(manifest,b);return hashlib.sha256(b).hexdigest()
 h=install(m);private(state/'lock',b'');private(state/'fixture.json',json.dumps({'Peer':peer,'Other':other}).encode())
 config=root/'etc/wireguard/wg0.conf';old=b'[Interface]\nPrivateKey = synthetic-only\n\n[Peer]\nPublicKey = '+other.encode()+b'\nAllowedIPs = 10.66.66.6/32\n'
 def reset():
  private(config,old);private(state/'live.json',json.dumps({other:'10.66.66.6/32'}).encode());(state/'pending.json').unlink(missing_ok=True)
 reset()
 def run(op,hash=None,user=None,extra=[]):
  global last_op,last_result
  last_op=op;a=['/usr/sbin/chroot']+(['--userspec='+user] if user else [])+[str(root),'/usr/local/bin/21pins','wg-beryl',op,hash or h]+extra
  r=subprocess.run(a,capture_output=True,timeout=15);last_result=json.loads(r.stdout) if r.stdout else {};return r.returncode,last_result
 r,v=run('peer-enroll');assert r==0 and v['verified'];patched=config.read_bytes();assert patched.startswith(old) and json.loads((state/'live.json').read_text())[other]=='10.66.66.6/32'
 for op in ['peer-enroll','peer-inspect']:r,v=run(op);assert r==0 and v['verified'];assert config.read_bytes()==patched;assert peer not in json.dumps(v) and other not in json.dumps(v)
 assert v['handshake_at']>0 and v['handshake_recent']
 live=json.loads((state/'live.json').read_text());drift=dict(live);drift[base64.b64encode(bytes([3])*32).decode()]='10.66.66.7/32';private(state/'live.json',json.dumps(drift).encode());r,v=run('peer-inspect');assert r!=0;private(state/'live.json',json.dumps(live).encode())
 for op in ['dns-query','technitium-status','peer-verify','wg-state','wg-handshake','sh','peer-enroll;id','wg set','peer-enroll other']:r,v=run(op);assert r!=0
 r,v=run('peer-enroll',extra=['extra']);assert r!=0
 r,v=run('peer-inspect',hash='f'*64);assert r!=0
 r,v=run('peer-inspect',user='65534:65534');assert r!=0
 with (state/'lock').open('rb') as held:
  fcntl.flock(held,fcntl.LOCK_EX|fcntl.LOCK_NB);r,v=run('peer-inspect');assert r!=0;fcntl.flock(held,fcntl.LOCK_UN)
 manifest.chmod(0o666);r,v=run('peer-inspect');assert r!=0;manifest.chmod(0o600)
 actual=config.read_bytes();config.unlink();config.symlink_to('/var/lib/21pins/wg-beryl/live.json');r,v=run('peer-inspect');assert r!=0;config.unlink();private(config,actual)
 for field,value in [('host','dns-primary'),('interface','wg1'),('allowed_ip','10.66.66.6/32'),('wireguard_config','/etc/other'),('peer_public_key','invalid'),('unknown','ignored')]:
  bad=dict(m);bad[field]=value;z=install(bad);r,v=run('peer-enroll',hash=z);assert r!=0
 h=install(m)
 # Actual root helper is SIGKILLed after durable disk/journal and before fixture live-set.
 reset();private(state/'kill-before-live',b'1');r,v=run('peer-enroll');assert r!=0
 assert config.read_bytes()!=old and (state/'pending.json').exists() and peer not in json.loads((state/'live.json').read_text())
 r,v=run('peer-enroll');assert r==0 and v['verified'] and not (state/'pending.json').exists();assert config.read_bytes().startswith(old)
 ops=['peer-enroll','peer-inspect'];commands=[f'/usr/local/bin/21pins wg-beryl {op} {h}' for op in ops]
 sudo=root/'sudoers';private(sudo,('Defaults:pins-wg-agent env_reset, !setenv, !requiretty, secure_path=/usr/sbin:/usr/bin\npins-wg-agent ALL=(root) NOPASSWD: NOSETENV: '+', '.join(commands)+'\n').encode())
 visudo=shutil.which('visudo');assert visudo and subprocess.run([visudo,'-c','-f',str(sudo)],capture_output=True,timeout=5).returncode==0
 print(json.dumps({'native_root_chroot_helper_pass':True,'native_root_WG_helper_two_operations_pass':True,'exact_scope_ownership_lock_hash_argv_negatives_pass':True,'idempotent_preserves_config_and_other_peer':True,'actual_SIGKILL_disk_before_live_recovery_pass':True,'native_sudoers_syntax_pass':True,'all_keys_WG_state_tools_synthetic':True,'no_actual_client_handshake_DNS_or_isolation_claim':True,'no_service_VM_touched':True}))
except Exception as e:
 print(json.dumps({'failed':True,'error_type':type(e).__name__,'line':traceback.extract_tb(e.__traceback__)[-1].lineno,'operation':globals().get('last_op'),'result':globals().get('last_result')}));sys.exit(1)
finally:shutil.rmtree(root)
'''
if __name__=='__main__':runner.main()
