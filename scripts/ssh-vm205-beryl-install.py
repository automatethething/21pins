#!/usr/bin/env python3
"""Explicit approved trust-only VM205 installer; private CA/requester/API material never transported."""
import argparse,base64,gzip,json,os,pathlib,subprocess,tempfile,hashlib
REPO=pathlib.Path(__file__).resolve().parents[1]
STAGE=pathlib.Path.home()/'Library/Caches/21pins-vm205-review'
REMOTE=r'''
import pathlib,subprocess,os,json,pwd,shutil,hashlib,base64,stat
p=json.loads(__import__('gzip').decompress(pathlib.Path('/root/21pins-wg-stage-input.gz').read_bytes()))
backup=pathlib.Path('/root/21pins-bootstrap-backup');user='pins-wg-agent';created=[];account=False;live=False
assert not backup.exists()
try:pwd.getpwnam(user);raise AssertionError('existing account')
except KeyError:pass
for f in ['/usr/local/bin/21pins','/etc/ssh/21pins','/etc/21pins/wg-beryl.json','/var/lib/21pins/wg-beryl','/etc/sudoers.d/21pins-wg-agent']:
 assert not pathlib.Path(f).exists()
def call(a,data=None):
 r=subprocess.run(a,input=data,capture_output=True,timeout=8,env={'PATH':'/usr/sbin:/usr/bin:/bin','LANG':'C','LC_ALL':'C'});assert r.returncode==0;return r.stdout
def effective(user,text):
 b=call(['/usr/sbin/sshd','-T','-f','/dev/stdin','-C','user='+user+',host=localhost,addr=127.0.0.1'],text)
 return dict(x.split(' ',1) for x in b.decode().lower().splitlines() if ' ' in x)
def mkdir(path,mode):
 f=pathlib.Path(path)
 if not f.exists():f.mkdir();created.append((f,True));f.chmod(mode)
 else:assert f.is_dir() and not f.is_symlink() and f.stat().st_uid==0 and not f.stat().st_mode&0o022
def install(path,b,mode):
 f=pathlib.Path(path);assert not f.exists();f.write_bytes(b);f.chmod(mode);os.chown(f,0,0);created.append((f,False))
original=pathlib.Path('/etc/ssh/sshd_config').read_bytes();users=[x.pw_name for x in pwd.getpwall()];old={u:effective(u,original) for u in users}
backup.mkdir(mode=0o700);(backup/'sshd_config').write_bytes(original);(backup/'sshd_config').chmod(0o600)
if pathlib.Path('/etc/ssh/sshd_config.d').exists():shutil.copytree('/etc/ssh/sshd_config.d',backup/'sshd_config.d')
try:
 manifest=base64.b64decode(p['wg-beryl.json']);m=json.loads(manifest)
 assert hashlib.sha256(manifest).hexdigest()=='d31791b5dc95aae7467bfbbad0f305e6e2e19242c45a53451098f42d4f3cae68'
 config=pathlib.Path('/etc/wireguard/wg0.conf');original_wg=config.read_bytes()
 original_live=call(['/usr/bin/wg','show','wg0','allowed-ips']);peers=dict(x.split() for x in original_live.decode().splitlines())
 assert peers.get(m['peer_public_key'])==m['allowed_ip'] and len(peers)==4
 binary=base64.b64decode(p['21pins']);assert hashlib.sha256(binary).hexdigest()==p['binary_digest']
 call(['/usr/sbin/useradd','--system','--user-group','--no-create-home','--home-dir','/var/empty/pins-wg-agent','--shell','/usr/bin/dash',user]);account=True
 call(['/usr/sbin/usermod','--password','*',user]);a=pwd.getpwnam(user);assert a.pw_uid>0 and os.getgrouplist(user,a.pw_gid)==[a.pw_gid]
 for path,mode in [('/var/empty',0o755),('/var/empty/pins-wg-agent',0o755),('/etc/ssh/21pins',0o755),('/etc/ssh/21pins/principals',0o755),('/etc/21pins',0o755),('/var/lib/21pins',0o755),('/var/lib/21pins/wg-beryl',0o700)]:mkdir(path,mode)
 for name,path,mode in [('21pins','/usr/local/bin/21pins',0o755),('21pins-ca.pub','/etc/ssh/21pins/ca.pub',0o644),('commands.json','/etc/ssh/21pins/commands.json',0o644),('principals-pins-wg-agent','/etc/ssh/21pins/principals/pins-wg-agent',0o644),('wg-beryl.json','/etc/21pins/wg-beryl.json',0o600),('sudoers','/etc/sudoers.d/21pins-wg-agent',0o440)]:install(path,base64.b64decode(p[name]),mode)
 install('/var/lib/21pins/wg-beryl/lock',b'',0o600)
 call(['/usr/sbin/visudo','-c'])
 digest=hashlib.sha256(manifest).hexdigest();base=['/usr/bin/sudo','-u',user,'--','/usr/bin/sudo','-n','/usr/local/bin/21pins','wg-beryl']
 for op in ['peer-enroll']:
  v=json.loads(call(base+[op,digest]));assert v['verified']
 for argv in [base+[op,digest] for op in ['dns-query','technitium-status','peer-verify','wg-state','wg-handshake']]+[base+['peer-enroll','f'*64],['/usr/bin/sudo','-u',user,'--','/usr/bin/sudo','-n','/bin/sh','-c','true']]:
  r=subprocess.run(argv,capture_output=True,timeout=8);assert r.returncode!=0
 fragment=base64.b64decode(p['sshd_config.fragment']);candidate=original+b'\n'+fragment
 call(['/usr/sbin/sshd','-t','-f','/dev/stdin'],candidate)
 assert all(effective(u,candidate)==old[u] for u in users)
 q=effective(user,candidate);assert q['disableforwarding']=='yes' and q['permittty']=='no' and q['permituserenvironment']=='no' and q['acceptenv']=='21pins_unused' and q['authorizedkeysfile']=='none'
 (backup/'candidate').write_bytes(candidate);(backup/'candidate').chmod(0o600)
 assert pathlib.Path('/etc/ssh/sshd_config').read_bytes()==original
 pathlib.Path('/etc/ssh/sshd_config').write_bytes(candidate);live=True
 call(['/usr/sbin/sshd','-t']);call(['/usr/bin/systemctl','reload','ssh.service']);call(['/usr/bin/systemctl','is-active','--quiet','ssh.service'])
 assert all(effective(u,candidate)==old[u] for u in users)
 assert config.read_bytes()==original_wg and call(['/usr/bin/wg','show','wg0','allowed-ips'])==original_live
 receipt={'installed':True,'recovery_contexts_preserved':len(users),'native_sudo_positive_negative_pass':True,'WireGuard_unchanged':True,'SSH_safe_reload_healthy':True,'binary_digest':p['binary_digest'],'manifest_digest':digest,'no_network_WG_or_filter_change':True}
 (backup/'install-receipt.json').write_text(json.dumps(receipt));(backup/'install-receipt.json').chmod(0o600);print(json.dumps(receipt))
except Exception as e:
 if live:
  pathlib.Path('/etc/ssh/sshd_config').write_bytes(original);call(['/usr/sbin/sshd','-t']);call(['/usr/bin/systemctl','reload','ssh.service'])
 if account:subprocess.run(['/usr/sbin/userdel',user],capture_output=True,timeout=8)
 for f,directory in reversed(created):
  if directory:
   if f.exists():f.rmdir()
  elif f.exists():f.unlink()
 assert pathlib.Path('/etc/ssh/sshd_config').read_bytes()==original
 print(json.dumps({'installed':False,'rollback_verified':True,'error_type':type(e).__name__}));raise SystemExit(1)
finally:pathlib.Path('/root/21pins-wg-stage-input.gz').unlink(missing_ok=True)
'''
def guest(code,short=False):
 script="import subprocess,json,sys\nr=subprocess.run(['sudo','-n','/usr/sbin/qm','guest','exec','205','--pass-stdin','1','--timeout',"+repr('8' if short else '90')+",'--','/usr/bin/python3','-'],input="+repr(code.encode())+",capture_output=True,timeout="+str(10 if short else 100)+")\nassert r.returncode==0\nv=json.loads(r.stdout);assert v.get('exitcode')==0\nprint(v.get('out-data',''))"
 r=subprocess.run(['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ForwardAgent=no','-o','ConnectTimeout=10','fipi','/usr/bin/python3 -'],input=script.encode(),capture_output=True,timeout=12 if short else 110,env={k:os.environ[k] for k in ['PATH','HOME','USER','LOGNAME'] if k in os.environ})
 if r.returncode:raise RuntimeError('guest operation rejected; no raw output disclosed')
 return r.stdout

def self_test():
 import types,sys,io,contextlib
 compile(REMOTE,'approved-guest','exec');assert '220' not in REMOTE
 for failure in [None,'visudo','reload']:
  with tempfile.TemporaryDirectory(prefix='21pins-install-check-') as d:
   root=pathlib.Path(d)
   for p in ['root','etc/ssh','etc/systemd/system','etc/wireguard','etc/sudoers.d','usr/local/bin','var/lib']:(root/p).mkdir(parents=True,exist_ok=True)
   original=b'PermitUserEnvironment no\n';(root/'etc/ssh/sshd_config').write_bytes(original)
   unit=b'synthetic-config';(root/'etc/wireguard/wg0.conf').write_bytes(unit)
   manifest=json.dumps({'peer_public_key':'synthetic-peer','allowed_ip':'synthetic-ip'}).encode()
   artifacts={'21pins':b'synthetic-binary','21pins-ca.pub':b'synthetic-public','commands.json':b'{}','principals-pins-wg-agent':b'synthetic-principal','wg-beryl.json':manifest,'sudoers':b'synthetic-sudoers','sshd_config.fragment':b'Match User pins-wg-agent\n'}
   payload={n:base64.b64encode(b).decode() for n,b in artifacts.items()};payload['binary_digest']=hashlib.sha256(artifacts['21pins']).hexdigest()
   (root/'root/21pins-wg-stage-input.gz').write_bytes(gzip.compress(json.dumps(payload).encode()))
   state={'account':False,'failed':False}
   entry=types.SimpleNamespace(pw_name='pins-wg-agent',pw_uid=900,pw_gid=900)
   def getuser(n):
    if state['account']:return entry
    raise KeyError(n)
   def run(a,input=None,**kwargs):
    rc=0;out=b''
    if 'useradd' in a[0]:state['account']=True
    elif 'userdel' in a[0]:state['account']=False
    elif a[0].endswith('/sudo'):
     op=a[-2] if len(a)>2 else ''
     if op in ['peer-enroll'] and a[-1]==hashlib.sha256(manifest).hexdigest():out=b'{"verified":true}'
     else:rc=1
    elif a[0].endswith('/wg'):out=b'synthetic-peer synthetic-ip\nother1 ip1\nother2 ip2\nother3 ip3\n'
    elif '-T' in a:
     u=a[-1].split(',')[0].split('=')[1]
     out=b'disableforwarding yes\npermittty no\npermituserenvironment no\nacceptenv 21pins_unused\nauthorizedkeysfile none\n' if u=='pins-wg-agent' else b'permitrootlogin yes\n'
    if not state['failed'] and ((failure=='visudo' and a[0].endswith('/visudo')) or (failure=='reload' and 'reload' in a)):
     state['failed']=True;rc=1
    return types.SimpleNamespace(returncode=rc,stdout=out,stderr=b'')
   fakepath=types.SimpleNamespace(Path=lambda p:root/str(p).lstrip('/'))
   fakeos=types.SimpleNamespace(getgrouplist=lambda u,g:[g],chown=lambda *a:None)
   fakepwd=types.SimpleNamespace(getpwnam=getuser,getpwall=lambda:[types.SimpleNamespace(pw_name='root'),types.SimpleNamespace(pw_name='admin')])
   replacements={'pathlib':fakepath,'subprocess':types.SimpleNamespace(run=run),'os':fakeos,'pwd':fakepwd};saved={k:sys.modules[k] for k in replacements}
   try:
    sys.modules.update(replacements)
    try:
     with contextlib.redirect_stdout(io.StringIO()):exec(REMOTE.replace('d31791b5dc95aae7467bfbbad0f305e6e2e19242c45a53451098f42d4f3cae68',hashlib.sha256(manifest).hexdigest()),{})
    except SystemExit as e:assert failure is not None and e.code==1
   finally:sys.modules.update(saved)
   if failure:
    assert not state['account'] and (root/'etc/ssh/sshd_config').read_bytes()==original
    assert not (root/'usr/local/bin/21pins').exists() and not (root/'etc/sudoers.d/21pins-wg-agent').exists()
   else:assert state['account'] and json.loads((root/'root/21pins-bootstrap-backup/install-receipt.json').read_text())['installed']
   assert not (root/'root/21pins-wg-stage-input.gz').exists()
 print('PASS: synthetic install plus pre/post-live failure rollback; original recovery/config restored; no real host changes')

def main():
 a=argparse.ArgumentParser();a.add_argument('--approved-install',action='store_true');a.add_argument('--self-test',action='store_true');a.add_argument('--upload-start',type=int);a.add_argument('--upload-count',type=int,default=4);a.add_argument('--apply',action='store_true');x=a.parse_args()
 if x.self_test:self_test();return
 if not x.approved_install:a.error('explicit owner approval required')
 names=['21pins','21pins-ca.pub','commands.json','principals-pins-wg-agent','wg-beryl.json','sudoers','sshd_config.fragment'];p={n:base64.b64encode((STAGE/n).read_bytes()).decode() for n in names};p['binary_digest']=hashlib.sha256((STAGE/'21pins').read_bytes()).hexdigest();b=gzip.compress(json.dumps(p).encode(),mtime=0)
 assert p['binary_digest']=='816ebdfd92f2d8efa13ed410c7668b60f00c749a2badaace1f8b512790937f41'
 # Bounded chunks avoid guest-agent upload limits; only approved public artifacts.
 if x.upload_start is not None:
  assert x.upload_start>=0 and 1<=x.upload_count<=64
  start=x.upload_start*24000
  if start==0:guest("import pathlib\np=pathlib.Path('/root/21pins-wg-stage-input.gz');assert not p.exists();p.write_bytes(b'');p.chmod(0o600)",True)
  codes=["import pathlib,base64\np=pathlib.Path('/root/21pins-wg-stage-input.gz');assert p.stat().st_size=="+str(i)+"\nwith p.open('ab') as f:f.write(base64.b64decode("+repr(base64.b64encode(b[i:i+24000]).decode())+"))" for i in range(start,min(len(b),start+x.upload_count*24000),24000)]
  script="import subprocess,json,time\nend=time.monotonic()+100\ncount=0\nfor code in "+repr(codes)+":\n if time.monotonic()+10>end:break\n r=subprocess.run(['sudo','-n','/usr/sbin/qm','guest','exec','205','--pass-stdin','1','--timeout','8','--','/usr/bin/python3','-'],input=code.encode(),capture_output=True,timeout=10)\n assert r.returncode==0\n v=json.loads(r.stdout);assert v.get('exitcode')==0\n count+=1\nprint(json.dumps({'upload_next':"+str(x.upload_start)+"+count,'upload_total':"+str((len(b)+23999)//24000)+"}))"
  r=subprocess.run(['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ForwardAgent=no','-o','ConnectTimeout=10','fipi','/usr/bin/python3 -'],input=script.encode(),capture_output=True,timeout=115)
  assert r.returncode==0;v=json.loads(r.stdout);print(json.dumps(v));return
 if not x.apply:a.error('select bounded --upload-start or --apply')
 result=guest(REMOTE);v=json.loads(result);assert v['installed'];print(json.dumps(v))
if __name__=='__main__':main()
