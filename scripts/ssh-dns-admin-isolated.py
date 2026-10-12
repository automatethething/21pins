#!/usr/bin/env python3
"""Isolated root Linux chroot on existing management host. No VM calls/mutations.
DNS/service/firewall tools and guest packet evidence are explicit fixtures.
"""
import argparse, pathlib, subprocess, tempfile, os, gzip, base64, json
REPO=pathlib.Path(__file__).resolve().parents[1]
REMOTE=r'''
import os,pathlib,tempfile,subprocess,json,sys,base64,gzip,hashlib,shutil,time,traceback,fcntl
payload=json.load(sys.stdin)
root=pathlib.Path(tempfile.mkdtemp(prefix='21pins-dns-chroot-',dir='/tmp'));root.chmod(0o755)
try:
 for d in ['etc/21pins','etc/systemd/system','var/lib/21pins/dns-admin','usr/local/bin','usr/bin','usr/sbin','dev']:(root/d).mkdir(parents=True,exist_ok=True)
 (root/'dev/null').write_bytes(b'');(root/'dev/null').chmod(0o666)
 for name in ['21pins','tools']:
  p=root/('usr/local/bin/21pins' if name=='21pins' else 'tools');p.write_bytes(gzip.decompress(base64.b64decode(payload[name])));p.chmod(0o755)
 for name in ['dig','systemctl']:shutil.copyfile(root/'tools',root/('usr/bin/'+name));(root/('usr/bin/'+name)).chmod(0o755)
 shutil.copyfile(root/'tools',root/'usr/sbin/nft');(root/'usr/sbin/nft').chmod(0o755)
 state=root/'var/lib/21pins/dns-admin';state.chmod(0o700)
 def private(p,data):p.write_bytes(data);p.chmod(0o600)
 unit=root/'etc/systemd/system/dns.service';unit.write_bytes(b'[Service]\nExecStart=/usr/bin/dotnet /opt/technitium/dns/DnsServerApp.dll\n');unit.chmod(0o644)
 m={'workspace':'local','host':'dns-primary','resolver':'10.77.0.53','control_domain':'probe.example','control_a':'10.77.0.53','blocked_domain':'blocked.example','blocked_a':'NXDOMAIN','technitium_unit':'dns.service','service_config_hash':hashlib.sha256(unit.read_bytes()).hexdigest(),'isolation_rules_hash':hashlib.sha256(b'fixture-pinned-rules').hexdigest(),'isolation_proof':'/var/lib/21pins/dns-admin/guest-proof.json','guest_prefix':'10.88.0.0/24','guest_ingress':'guest0'}
 manifest=root/'etc/21pins/dns-admin.json'
 def install(m):
  b=json.dumps(m).encode();private(manifest,b);return hashlib.sha256(b).hexdigest()
 h=install(m);private(state/'lock',b'');private(state/'fixture.json',json.dumps({'Control':m['control_domain'],'Blocked':m['blocked_domain']}).encode())
 def run(op,hash=None,user=None,extra=[]):
  global last_op,last_result
  last_op=op
  a=['/usr/sbin/chroot']+(['--userspec='+user] if user else [])+[str(root),'/usr/local/bin/21pins','dns-admin',op,hash or h]+extra
  r=subprocess.run(a,capture_output=True,timeout=20);last_result=json.loads(r.stdout);return r.returncode,last_result
 for op in ['dns-query','dns-test','technitium-status','technitium-filtering']:
  r,v=run(op);assert r==0 and v['verified']
 r,v=run('guest-isolation');assert r!=0 and v['guest_policy'] and not v.get('guest_packet_proof',False)
 proof={'rules_hash':m['isolation_rules_hash'],'at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'guest_origin':True,'guest_prefix':m['guest_prefix'],'guest_ingress':m['guest_ingress'],'udp_blocked':True,'tcp_blocked':True}
 private(state/'guest-proof.json',json.dumps(proof).encode());r,v=run('guest-isolation');assert r==0
 for op in ['peer-enroll','peer-verify','wg-state','wg-handshake','adguard-status','adguard-filtering','sh','dns-query;id','dns-query other']:r,v=run(op);assert r!=0
 r,v=run('dns-query',extra=['extra']);assert r!=0
 r,v=run('dns-query',hash='f'*64);assert r!=0
 r,v=run('dns-query',user='65534:65534');assert r!=0
 with (state/'lock').open('rb') as held:
  fcntl.flock(held,fcntl.LOCK_EX|fcntl.LOCK_NB);r,v=run('dns-query');assert r!=0;fcntl.flock(held,fcntl.LOCK_UN)
 manifest.chmod(0o666);r,v=run('dns-query');assert r!=0;manifest.chmod(0o600)
 unit.chmod(0o666);r,v=run('technitium-status');assert r!=0;unit.chmod(0o644)
 actual=unit.read_bytes();unit.unlink();unit.symlink_to('/var/lib/21pins/dns-admin/fixture.json');r,v=run('technitium-status');assert r!=0;unit.unlink();unit.write_bytes(actual+b'\n');unit.chmod(0o644);r,v=run('technitium-status');assert r!=0;unit.write_bytes(actual)
 for field,value in [('interface','wg0'),('peer_public_key','synthetic'),('resolver','127.0.0.2'),('control_domain','-funsafe'),('unknown_path','/arbitrary')]:
  bad=dict(m);bad[field]=value;bad_hash=install(bad);r,v=run('dns-query',hash=bad_hash);assert r!=0
 raw=json.dumps(m).encode()+b' {}';private(manifest,raw);r,v=run('dns-query',hash=hashlib.sha256(raw).hexdigest());assert r!=0
 h=install(m)
 for k in ['blocked_domain','blocked_a','isolation_rules_hash','isolation_proof','guest_prefix','guest_ingress']:m.pop(k)
 old=h;h=install(m)
 r,v=run('dns-query',hash=old);assert r!=0
 for op in ['dns-query','dns-test','technitium-status']:r,v=run(op);assert r==0
 for op in ['technitium-filtering','guest-isolation']:r,v=run(op);assert r!=0 and not v['verified']
 ops=['dns-query','dns-test','technitium-status','technitium-filtering','guest-isolation'];commands=[f'/usr/local/bin/21pins dns-admin {op} {h}' for op in ops]
 sudoers=root/'sudoers-review';private(sudoers,('Defaults:pins-dns-agent env_reset, !setenv, !requiretty, secure_path=/usr/sbin:/usr/bin\npins-dns-agent ALL=(root) NOPASSWD: NOSETENV: '+', '.join(commands)+'\n').encode())
 visudo=shutil.which('visudo');assert visudo and subprocess.run([visudo,'-c','-f',str(sudoers)],capture_output=True,timeout=5).returncode==0
 assert not (root/'root/.config').exists() and not (root/'usr/bin/wg').exists()
 print(json.dumps({'native_root_chroot_helper_pass':True,'five_DNS_only_operations_pass':True,'WG_AdGuard_operations_denied':True,'missing_filter_guest_evidence_honestly_denied':True,'UDP_TCP_and_service_hash_verified':True,'ownership_symlink_scope_digest_lock_negatives_pass':True,'native_sudoers_syntax_pass':True,'network_and_guest_evidence_explicit_fixtures':True,'VM220_untouched':True}))
except Exception as e:
 print(json.dumps({'failed':True,'error_type':type(e).__name__,'line':traceback.extract_tb(e.__traceback__)[-1].lineno,'operation':globals().get('last_op'),'result':globals().get('last_result')}));sys.exit(1)
finally:shutil.rmtree(root)
'''
def main():
 p=argparse.ArgumentParser();p.add_argument('--run',action='store_true');p.add_argument('--self-test',action='store_true');a=p.parse_args()
 if a.self_test:compile(REMOTE,'remote','exec');assert 'qm ' not in REMOTE and 'guest exec' not in REMOTE;print('PASS: isolated chroot runner syntax; no VM path');return
 if not a.run:p.error('explicit --run required')
 with tempfile.TemporaryDirectory(prefix='21pins-dns-build-') as d:
  payload={};env=dict(os.environ,CGO_ENABLED='0',GOOS='linux',GOARCH='amd64')
  for name,package in [('21pins','./cmd/21pins'),('tools','./internal/dnsadmin/testdata/native-tools')]:
   path=pathlib.Path(d)/name;subprocess.run(['go','build','-trimpath','-buildvcs=false','-ldflags=-s -w','-o',str(path),package],cwd=REPO,env=env,check=True,timeout=60);payload[name]=base64.b64encode(gzip.compress(path.read_bytes(),mtime=0)).decode()
  script='import io,sys\nsys.stdin=io.StringIO('+repr(json.dumps(payload))+')\n'+REMOTE
  r=subprocess.run(['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ForwardAgent=no','-o','ConnectTimeout=10','fipi','sudo -n /usr/bin/python3 -'],input=script.encode(),capture_output=True,timeout=100)
  if r.returncode:
   try:print(json.dumps(json.loads(r.stdout)))
   except Exception:print('isolated native chroot failure with no filtered receipt')
   raise SystemExit('isolated validation failed; no raw output disclosed')
  result=json.loads(r.stdout);assert result['native_root_chroot_helper_pass'];print(json.dumps(result))
if __name__=='__main__':main()
