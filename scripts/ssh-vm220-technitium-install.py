#!/usr/bin/env python3
"""Explicit approved trust-only VM220 installer; private CA/requester/API material never transported."""
import argparse,base64,gzip,json,os,pathlib,subprocess,tempfile,hashlib
REPO=pathlib.Path(__file__).resolve().parents[1]
STAGE=pathlib.Path.home()/'Library/Caches/21pins-vm220-install'
REMOTE=r'''
import pathlib,subprocess,os,json,pwd,shutil,hashlib,base64,stat
p=json.loads(__import__('gzip').decompress(pathlib.Path('/root/21pins-tech-stage-input.gz').read_bytes()))
backup=pathlib.Path('/root/21pins-bootstrap-backup');user='pins-dns-agent';created=[];account=False;live=False
assert not backup.exists()
try:pwd.getpwnam(user);raise AssertionError('existing account')
except KeyError:pass
for f in ['/usr/local/bin/21pins','/etc/ssh/21pins','/etc/21pins/dns-admin.json','/var/lib/21pins/dns-admin','/etc/sudoers.d/21pins-dns-agent']:
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
 unit=pathlib.Path('/etc/systemd/system/dns.service').read_bytes();manifest=base64.b64decode(p['dns-admin.json']);m=json.loads(manifest)
 assert hashlib.sha256(unit).hexdigest()==m['service_config_hash']
 assert not call(['/usr/bin/systemctl','show','--property=DropInPaths','--value','dns.service']).strip()
 binary=base64.b64decode(p['21pins']);assert hashlib.sha256(binary).hexdigest()==p['binary_digest']
 call(['/usr/sbin/useradd','--system','--user-group','--no-create-home','--home-dir','/var/empty/pins-dns-agent','--shell','/usr/bin/dash',user]);account=True
 call(['/usr/sbin/usermod','--password','*',user]);a=pwd.getpwnam(user);assert a.pw_uid>0 and os.getgrouplist(user,a.pw_gid)==[a.pw_gid]
 for path,mode in [('/var/empty',0o755),('/var/empty/pins-dns-agent',0o755),('/etc/ssh/21pins',0o755),('/etc/ssh/21pins/principals',0o755),('/etc/21pins',0o755),('/var/lib/21pins',0o755),('/var/lib/21pins/dns-admin',0o700)]:mkdir(path,mode)
 for name,path,mode in [('21pins','/usr/local/bin/21pins',0o755),('21pins-ca.pub','/etc/ssh/21pins/ca.pub',0o644),('commands.json','/etc/ssh/21pins/commands.json',0o644),('principals-pins-dns-agent','/etc/ssh/21pins/principals/pins-dns-agent',0o644),('dns-admin.json','/etc/21pins/dns-admin.json',0o600),('sudoers','/etc/sudoers.d/21pins-dns-agent',0o440)]:install(path,base64.b64decode(p[name]),mode)
 install('/var/lib/21pins/dns-admin/lock',b'',0o600)
 call(['/usr/sbin/visudo','-c'])
 digest=hashlib.sha256(manifest).hexdigest();base=['/usr/bin/sudo','-u',user,'--','/usr/bin/sudo','-n','/usr/local/bin/21pins','dns-admin']
 for op in ['dns-query','dns-test','technitium-status']:
  v=json.loads(call(base+[op,digest]));assert v['verified']
 for argv in [base+[op,digest] for op in ['technitium-filtering','guest-isolation','peer-enroll','wg-state']]+[base+['dns-query','f'*64],['/usr/bin/sudo','-u',user,'--','/usr/bin/sudo','-n','/bin/sh','-c','true']]:
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
 call(['/usr/bin/systemctl','is-active','--quiet','dns.service']);assert pathlib.Path('/etc/systemd/system/dns.service').read_bytes()==unit
 receipt={'installed':True,'recovery_contexts_preserved':len(users),'native_sudo_positive_negative_pass':True,'Technitium_unchanged':True,'SSH_safe_reload_healthy':True,'binary_digest':p['binary_digest'],'manifest_digest':digest,'no_network_WG_or_filter_change':True}
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
finally:pathlib.Path('/root/21pins-tech-stage-input.gz').unlink(missing_ok=True)
'''
def guest(code,short=False):
 script="import subprocess,json,sys\nr=subprocess.run(['sudo','-n','/usr/sbin/qm','guest','exec','220','--pass-stdin','1','--timeout',"+repr('8' if short else '90')+",'--','/usr/bin/python3','-'],input="+repr(code.encode())+",capture_output=True,timeout="+str(10 if short else 100)+")\nassert r.returncode==0\nv=json.loads(r.stdout);assert v.get('exitcode')==0\nprint(v.get('out-data',''))"
 r=subprocess.run(['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ForwardAgent=no','-o','ConnectTimeout=10','fipi','/usr/bin/python3 -'],input=script.encode(),capture_output=True,timeout=12 if short else 110,env={k:os.environ[k] for k in ['PATH','HOME','USER','LOGNAME'] if k in os.environ})
 if r.returncode:raise RuntimeError('guest operation rejected; no raw output disclosed')
 return r.stdout

def self_test():
 import types,sys,io,contextlib
 compile(REMOTE,'approved-guest','exec');assert '205' not in REMOTE
 for failure in [None,'visudo','reload']:
  with tempfile.TemporaryDirectory(prefix='21pins-install-check-') as d:
   root=pathlib.Path(d)
   for p in ['root','etc/ssh','etc/systemd/system','etc/sudoers.d','usr/local/bin','var/lib']:(root/p).mkdir(parents=True,exist_ok=True)
   original=b'PermitUserEnvironment no\n';(root/'etc/ssh/sshd_config').write_bytes(original)
   unit=b'synthetic-unit';(root/'etc/systemd/system/dns.service').write_bytes(unit)
   manifest=json.dumps({'service_config_hash':hashlib.sha256(unit).hexdigest()}).encode()
   artifacts={'21pins':b'synthetic-binary','21pins-ca.pub':b'synthetic-public','commands.json':b'{}','principals-pins-dns-agent':b'synthetic-principal','dns-admin.json':manifest,'sudoers':b'synthetic-sudoers','sshd_config.fragment':b'Match User pins-dns-agent\n'}
   payload={n:base64.b64encode(b).decode() for n,b in artifacts.items()};payload['binary_digest']=hashlib.sha256(artifacts['21pins']).hexdigest()
   (root/'root/21pins-tech-stage-input.gz').write_bytes(gzip.compress(json.dumps(payload).encode()))
   state={'account':False,'failed':False}
   entry=types.SimpleNamespace(pw_name='pins-dns-agent',pw_uid=900,pw_gid=900)
   def getuser(n):
    if state['account']:return entry
    raise KeyError(n)
   def run(a,input=None,**kwargs):
    rc=0;out=b''
    if 'useradd' in a[0]:state['account']=True
    elif 'userdel' in a[0]:state['account']=False
    elif a[0].endswith('/sudo'):
     op=a[-2] if len(a)>2 else ''
     if op in ['dns-query','dns-test','technitium-status'] and a[-1]==hashlib.sha256(manifest).hexdigest():out=b'{"verified":true}'
     else:rc=1
    elif '-T' in a:
     u=a[-1].split(',')[0].split('=')[1]
     out=b'disableforwarding yes\npermittty no\npermituserenvironment no\nacceptenv 21pins_unused\nauthorizedkeysfile none\n' if u=='pins-dns-agent' else b'permitrootlogin yes\n'
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
     with contextlib.redirect_stdout(io.StringIO()):exec(REMOTE,{})
    except SystemExit as e:assert failure is not None and e.code==1
   finally:sys.modules.update(saved)
   if failure:
    assert not state['account'] and (root/'etc/ssh/sshd_config').read_bytes()==original
    assert not (root/'usr/local/bin/21pins').exists() and not (root/'etc/sudoers.d/21pins-dns-agent').exists()
   else:assert state['account'] and json.loads((root/'root/21pins-bootstrap-backup/install-receipt.json').read_text())['installed']
   assert not (root/'root/21pins-tech-stage-input.gz').exists()
 print('PASS: synthetic install plus pre/post-live failure rollback; original recovery/config restored; no real host changes')

def main():
 a=argparse.ArgumentParser();a.add_argument('--approved-install',action='store_true');a.add_argument('--self-test',action='store_true');a.add_argument('--upload-start',type=int);a.add_argument('--upload-count',type=int,default=4);a.add_argument('--apply',action='store_true');x=a.parse_args()
 if x.self_test:self_test();return
 if not x.approved_install:a.error('explicit owner approval required')
 names=['21pins','21pins-ca.pub','commands.json','principals-pins-dns-agent','dns-admin.json','sudoers','sshd_config.fragment'];p={n:base64.b64encode((STAGE/n).read_bytes()).decode() for n in names};p['binary_digest']=hashlib.sha256((STAGE/'21pins').read_bytes()).hexdigest();b=gzip.compress(json.dumps(p).encode(),mtime=0)
 # Bounded chunks avoid guest-agent upload limits; only approved public artifacts.
 if x.upload_start is not None:
  assert x.upload_start>=0 and 1<=x.upload_count<=8
  start=x.upload_start*24000
  if start==0:guest("import pathlib\np=pathlib.Path('/root/21pins-tech-stage-input.gz');assert not p.exists();p.write_bytes(b'');p.chmod(0o600)",True)
  for i in range(start,min(len(b),start+x.upload_count*24000),24000):guest("import pathlib,base64\np=pathlib.Path('/root/21pins-tech-stage-input.gz');assert p.stat().st_size=="+str(i)+"\nwith p.open('ab') as f:f.write(base64.b64decode("+repr(base64.b64encode(b[i:i+24000]).decode())+"))",True)
  print(json.dumps({'upload_next':min((len(b)+23999)//24000,x.upload_start+x.upload_count),'upload_total':(len(b)+23999)//24000}));return
 if not x.apply:a.error('select bounded --upload-start or --apply')
 result=guest(REMOTE);v=json.loads(result);assert v['installed'];print(json.dumps(v))
if __name__=='__main__':main()
