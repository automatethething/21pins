#!/usr/bin/env python3
"""Root Linux chroot test on existing management host; never accesses VM220/221.
Native root/helper/permissions and exact sudoers validation; WG/DNS/service tools are
explicit stateful fixtures, NOT real target/network or guest-origin packet evidence.
"""
import argparse, pathlib, subprocess, tempfile, os, gzip, base64, json
REPO=pathlib.Path(__file__).resolve().parents[1]
REMOTE=r'''
import os,pathlib,tempfile,subprocess,json,sys,base64,gzip,hashlib,shutil,time,traceback,fcntl
payload=json.load(sys.stdin)
root=pathlib.Path(tempfile.mkdtemp(prefix='21pins-dns-chroot-',dir='/tmp'));root.chmod(0o755)
try:
 for d in ['etc/wireguard','etc/21pins','var/lib/21pins/dns-admin','usr/local/bin','usr/bin','usr/sbin','dev']:(root/d).mkdir(parents=True,exist_ok=True)
 # /tmp may be nodev; an empty regular input fixture avoids opening a device there.
 (root/'dev/null').write_bytes(b'');(root/'dev/null').chmod(0o666)
 for name in ['21pins','tools']:
  data=gzip.decompress(base64.b64decode(payload[name]));p=root/('usr/local/bin/21pins' if name=='21pins' else 'tools');p.write_bytes(data);p.chmod(0o755)
 for name in ['wg','dig','systemctl']:shutil.copyfile(root/'tools',root/('usr/bin/'+name));(root/('usr/bin/'+name)).chmod(0o755)
 shutil.copyfile(root/'tools',root/'usr/sbin/nft');(root/'usr/sbin/nft').chmod(0o755)
 state=root/'var/lib/21pins/dns-admin';state.chmod(0o700)
 peer=base64.b64encode(bytes([1])*32).decode();other=base64.b64encode(bytes([2])*32).decode()
 def private(p,data):p.write_bytes(data);p.chmod(0o600)
 m={'workspace':'local','host':'dns-primary','interface':'wg0','peer_public_key':peer,'wireguard_config':'/etc/wireguard/wg0.conf','resolver':'10.77.0.53','control_domain':'probe.example','control_a':'10.77.0.53','blocked_domain':'blocked.example','blocked_a':'NXDOMAIN','adguard_unit':'AdGuardHome.service','isolation_rules_hash':hashlib.sha256(b'fixture-pinned-rules').hexdigest(),'isolation_proof':'/var/lib/21pins/dns-admin/guest-proof.json','guest_prefix':'10.88.0.0/24','guest_ingress':'guest0'}
 manifest=root/'etc/21pins/dns-admin.json';raw=json.dumps(m).encode();private(manifest,raw);h=hashlib.sha256(raw).hexdigest()
 private(state/'lock',b'');private(state/'fixture.json',json.dumps({'Peer':peer,'Other':other,'Control':m['control_domain'],'Blocked':m['blocked_domain']}).encode());private(state/'live.json',json.dumps({other:'10.66.66.6/32'}).encode())
 config=root/'etc/wireguard/wg0.conf';original=b'[Interface]\nPrivateKey = synthetic-private-fixture\n\n[Peer]\nPublicKey = '+other.encode()+b'\nAllowedIPs = 10.66.66.6/32\n';private(config,original)
 def run(op,hash=h,user=None,extra=[]):
  global last_op,last_result
  last_op=op
  a=['/usr/sbin/chroot'];a+=['--userspec='+user] if user else [];a+=[str(root),'/usr/local/bin/21pins','dns-admin',op,hash]+extra
  r=subprocess.run(a,capture_output=True,timeout=25);last_result=json.loads(r.stdout);last_result['tool_metadata_denied']=b'helper_tool_metadata_denied' in r.stderr;last_result['tool_execution_denied']=b'helper_tool_execution_denied' in r.stderr;last_result['tool_child_exited']=b'*exec.ExitError' in r.stderr;last_result['tool_path_error']=b'*fs.PathError' in r.stderr or b'*os.PathError' in r.stderr;return r.returncode,last_result
 probe=subprocess.run(['/usr/sbin/chroot',str(root),'/usr/bin/wg','show','wg0','allowed-ips'],capture_output=True,timeout=5)
 assert probe.returncode==0 and other.encode() in probe.stdout and b'10.66.66.6/32' in probe.stdout
 r,v=run('peer-enroll');assert r==0 and v['verified'];assert config.read_bytes().startswith(original)
 r,v=run('peer-enroll');assert r==0
 for op in ['peer-verify','wg-state','wg-handshake','dns-query','dns-test','adguard-status','adguard-filtering']:r,v=run(op);assert r==0 and v['verified']
 r,v=run('guest-isolation');assert r!=0 and v['guest_policy'] and not v.get('guest_packet_proof',False)
 proof={'rules_hash':m['isolation_rules_hash'],'at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'guest_origin':True,'guest_prefix':m['guest_prefix'],'guest_ingress':m['guest_ingress'],'udp_blocked':True,'tcp_blocked':True};private(state/'guest-proof.json',json.dumps(proof).encode());r,v=run('guest-isolation');assert r==0
 for op in ['sh','peer-enroll;id','wg set','dns-query other']:r,v=run(op);assert r!=0
 r,v=run('peer-enroll',extra=['extra']);assert r!=0
 r,v=run('peer-verify',hash='f'*64);assert r!=0
 r,v=run('peer-verify',user='65534:65534');assert r!=0
 with (state/'lock').open('rb') as held:
  fcntl.flock(held,fcntl.LOCK_EX|fcntl.LOCK_NB);r,v=run('peer-verify');assert r!=0
  fcntl.flock(held,fcntl.LOCK_UN)
 manifest.chmod(0o666);r,v=run('peer-verify');assert r!=0;manifest.chmod(0o600)
 raw2=raw+b'\n';private(manifest,raw2);r,v=run('peer-verify');assert r!=0;private(manifest,raw)
 actual=config.read_bytes();config.unlink();config.symlink_to('/var/lib/21pins/dns-admin/live.json');r,v=run('peer-verify');assert r!=0;config.unlink();private(config,actual)
 commands=[f'/usr/local/bin/21pins dns-admin {op} {h}' for op in ['peer-enroll','peer-verify','wg-state','wg-handshake','dns-query','dns-test','adguard-status','adguard-filtering','guest-isolation']]
 sudoers=root/'sudoers-review';private(sudoers,('Defaults:pins-dns-agent env_reset, !setenv, !requiretty, secure_path=/usr/sbin:/usr/bin\npins-dns-agent ALL=(root) NOPASSWD: NOSETENV: '+', '.join(commands)+'\n').encode())
 visudo=shutil.which('visudo');assert visudo;assert subprocess.run([visudo,'-c','-f',str(sudoers)],capture_output=True,timeout=5).returncode==0
 assert not (root/'root/.config').exists()
 print(json.dumps({'native_root_chroot_helper_pass':True,'all_nine_literal_operations_pass':True,'unprivileged_argv_manifest_digest_permissions_symlink_denials_pass':True,'native_sudoers_syntax_pass':True,'no_provider_state_created':True,'network_tools_explicit_fixtures':True,'guest_proof_fixture_not_actual_packet_test':True,'VM220_untouched':True}))
except Exception as e:
 print(json.dumps({'failed':True,'error_type':type(e).__name__,'line':traceback.extract_tb(e.__traceback__)[-1].lineno,'operation':globals().get('last_op'),'result':globals().get('last_result')}))
 sys.exit(1)
finally:shutil.rmtree(root)
'''
def main():
 p=argparse.ArgumentParser();p.add_argument('--run',action='store_true');p.add_argument('--self-test',action='store_true');a=p.parse_args()
 if a.self_test:compile(REMOTE,'remote','exec');assert 'qm ' not in REMOTE and 'guest exec' not in REMOTE;print('PASS: bounded isolated chroot runner syntax; no VM command path');return
 if not a.run:p.error('explicit --run required')
 with tempfile.TemporaryDirectory(prefix='21pins-dns-build-') as d:
  payload={};env=dict(os.environ,CGO_ENABLED='0',GOOS='linux',GOARCH='amd64')
  for name,package in [('21pins','./cmd/21pins'),('tools','./internal/dnsadmin/testdata/native-tools')]:
   path=pathlib.Path(d)/name;subprocess.run(['go','build','-trimpath','-buildvcs=false','-ldflags=-s -w','-o',str(path),package],cwd=REPO,env=env,check=True,timeout=60);payload[name]=base64.b64encode(gzip.compress(path.read_bytes(),mtime=0)).decode()
  # remote script reads only the fixture payload, with no secret/config inventory.
  script="import io,sys\nsys.stdin=io.StringIO("+repr(json.dumps(payload))+")\n"+REMOTE
  r=subprocess.run(['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ForwardAgent=no','-o','ConnectTimeout=10','fipi','sudo -n /usr/bin/python3 -'],input=script.encode(),capture_output=True,timeout=100)
  if r.returncode:
   try:print(json.dumps(json.loads(r.stdout)))
   except Exception:print('isolated native chroot failure with no filtered receipt')
   raise SystemExit('isolated native chroot validation failed; no raw output disclosed')
  result=json.loads(r.stdout);assert result['native_root_chroot_helper_pass'];print(json.dumps(result))
if __name__=='__main__':main()
