#!/usr/bin/env python3
"""Approved observe prestage only: never creates a CA, enables trust or reloads SSH."""
import base64, gzip, hashlib, json, pathlib, subprocess, tempfile

REPO = pathlib.Path(__file__).resolve().parents[1]
REMOTE = r'''
import base64,hashlib,json,os,pathlib,pwd,shutil,stat,subprocess
payload=PAYLOAD
backup=pathlib.Path('/root/21pins-bootstrap-backup')
assert os.geteuid()==0 and not backup.exists(),'backup reuse/root gate'
assert not pathlib.Path('/etc/ssh/21pins').exists(),'existing trust must be reconciled'
assert not pathlib.Path('/usr/local/bin/21pins').exists(),'existing gate must be reconciled'
try:pwd.getpwnam('pins-agent');raise AssertionError('existing account must be reconciled')
except KeyError:pass
shell=pathlib.Path('/bin/sh').resolve();ss=shell.stat()
assert ss.st_uid==0 and not ss.st_mode&0o022 and shell.name=='dash','trusted shell gate'
def checked(args):
 p=subprocess.run(args,capture_output=True,text=True,timeout=20)
 assert p.returncode==0,'native operation failed'
 return p.stdout
checked(['/usr/sbin/sshd','-t'])
current=pathlib.Path('/etc/ssh/sshd_config').read_bytes()
accounts=[x.pw_name for x in pwd.getpwall()]
def effective(user,config):return checked(['/usr/sbin/sshd','-T','-f',str(config),'-C','user='+user+',host=localhost,addr=127.0.0.1,laddr=127.0.0.1,lport=22'])
before={u:effective(u,'/etc/ssh/sshd_config') for u in accounts}
backup.mkdir(mode=0o700)
shutil.copy2('/etc/ssh/sshd_config',backup/'sshd_config')
if pathlib.Path('/etc/ssh/sshd_config.d').exists():shutil.copytree('/etc/ssh/sshd_config.d',backup/'sshd_config.d')
for name,data in payload['files'].items():
 b=base64.b64decode(data,validate=True)
 path=backup/name
 with path.open('xb') as f:f.write(b)
 path.chmod(0o600)
assert hashlib.sha256((backup/'21pins').read_bytes()).hexdigest()==payload['binary_digest'],'artifact digest mismatch'
fragment=(backup/'match.conf').read_bytes()
candidate=backup/'sshd_config.candidate'
candidate.write_bytes(current+b'\n'+fragment);candidate.chmod(0o600)
checked(['/usr/sbin/sshd','-t','-f',str(candidate)])
assert all(before[u]==effective(u,candidate) for u in accounts),'existing recovery policy drift'
# ponytail: no trust installation before owner selects real CA custody.
# Account, fixed artifacts and a complete candidate are reversible approved prep.
checked(['/usr/sbin/useradd','--system','--user-group','--no-create-home','--home-dir','/var/empty/pins-agent','--shell','/bin/sh','pins-agent'])
account=pwd.getpwnam('pins-agent');assert account.pw_uid>0
assert os.getgrouplist('pins-agent',account.pw_gid)==[account.pw_gid],'unexpected supplementary groups'
for path in ['/var/empty','/var/empty/pins-agent','/etc/ssh/21pins','/etc/ssh/21pins/principals']:
 p=pathlib.Path(path);p.mkdir(mode=0o755,parents=True,exist_ok=True);s=p.lstat()
 assert s.st_uid==0 and not s.st_mode&0o022 and stat.S_ISDIR(s.st_mode),'unsafe artifact ancestor'
for source,dest,mode in [('21pins','/usr/local/bin/21pins',0o755),('commands.json','/etc/ssh/21pins/commands.json',0o644),('principals','/etc/ssh/21pins/principals/pins-agent',0o644)]:
 p=pathlib.Path(dest)
 assert not p.exists(),'artifact collision'
 shutil.copyfile(backup/source,p);p.chmod(mode)
sudo=subprocess.run(['/usr/bin/sudo','-l','-U','pins-agent'],capture_output=True,text=True,timeout=10,env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'})
assert sudo.returncode in (0,1) and ('not allowed to run sudo' in sudo.stdout+sudo.stderr) and 'unknown user' not in sudo.stderr.lower(),'no-sudo not established'
values={x.split(None,1)[0].lower():x.split(None,1)[1] for x in effective('pins-agent',candidate).splitlines() if len(x.split(None,1))==2}
assert values.get('acceptenv')=='21PINS_UNUSED' and values.get('permituserenvironment')=='no' and values.get('permituserrc')=='no','startup environment gate'
assert pathlib.Path('/etc/ssh/sshd_config').read_bytes()==current,'live config changed'
receipt={'account_created':True,'no_sudo_verified':True,'supplementary_groups_none':True,'root_empty_home':True,'gate_policy_principals_installed':True,'candidate_native_valid':True,'recovery_contexts_unchanged':len(accounts),'live_config_unchanged':True,'real_ca_trust_installed':False,'reload_performed':False,'binary_digest':payload['binary_digest']}
(backup/'prestage-receipt.json').write_text(json.dumps(receipt)+'\n');(backup/'prestage-receipt.json').chmod(0o600)
print(json.dumps(receipt))
'''

def main():
    with tempfile.TemporaryDirectory(prefix='21pins-observe-build-') as td:
        binary = pathlib.Path(td)/'21pins'
        import os
        env=dict(os.environ,CGO_ENABLED='0',GOOS='linux',GOARCH='amd64')
        subprocess.run(['go','build','-trimpath','-buildvcs=false','-ldflags=-s -w','-o',str(binary),'./cmd/21pins'],cwd=REPO,env=env,check=True,timeout=110,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        data={'21pins':binary.read_bytes(),'commands.json':(REPO/'docs/ssh-pins-agent-commands.json').read_bytes(),'principals':(REPO/'docs/ssh-pins-agent-principals').read_bytes(),'match.conf':(REPO/'docs/ssh-pins-agent-match.conf').read_bytes()}
        payload={'binary_digest':hashlib.sha256(data['21pins']).hexdigest(),'files':{k:base64.b64encode(v).decode() for k,v in data.items()}}
        compressed=gzip.compress(json.dumps(payload).encode(),mtime=0)
        # Management guest input is bounded: stream fixed-size chunks through one SSH session.
        remote_stage=REMOTE.replace('PAYLOAD',"__import__('json').loads(__import__('gzip').decompress(pathlib.Path('/root/21pins-observe-stage-input.gz').read_bytes()))",1)
        wrapper="import base64,json,subprocess\ndata=base64.b64decode("+repr(base64.b64encode(compressed).decode())+")\n"
        wrapper+="def guest(code):\n r=subprocess.run(['sudo','-n','/usr/sbin/qm','guest','exec','221','--pass-stdin','1','--timeout','90','--','/usr/bin/python3','-'],input=code,capture_output=True,text=True,timeout=100)\n assert r.returncode==0,'guest transport failure'\n o=json.loads(r.stdout);assert o.get('exitcode')==0,'guest stage failure'\n return o\n"
        wrapper+="o=guest(\"import pathlib,hashlib,json\\np=pathlib.Path('/root/21pins-observe-stage-input.gz');p.touch(mode=0o600,exist_ok=True);b=p.read_bytes();b=b[:4]+bytes(4)+b[8:] if len(b)>=8 else b;p.write_bytes(b);print(json.dumps({'offset':len(b),'digest':hashlib.sha256(b).hexdigest()}))\\n\")\nstate=json.loads(o['out-data']);offset=state['offset'];assert hashlib.sha256(data[:offset]).hexdigest()==state['digest'],'partial payload mismatch'\n"
        wrapper=wrapper.replace('import base64,json,subprocess','import base64,json,subprocess,hashlib',1)
        wrapper+="end=min(len(data),offset+50*24000)\nfor offset in range(offset,end,24000):\n chunk=base64.b64encode(data[offset:offset+24000]).decode()\n guest(\"import pathlib,base64\\np=pathlib.Path('/root/21pins-observe-stage-input.gz');assert p.stat().st_size==\"+str(offset)+\"\\nwith p.open('ab') as f:f.write(base64.b64decode(\"+repr(chunk)+\"))\\n\")\nif end<len(data):print(json.dumps({'exitcode':0,'out-data':json.dumps({'upload_checkpoint':True,'bytes':end,'total':len(data)})}));raise SystemExit(0)\n"
        wrapper+="o=guest("+repr(remote_stage)+")\nguest(\"import pathlib;pathlib.Path('/root/21pins-observe-stage-input.gz').unlink()\");print(json.dumps(o))\n"
        script=wrapper
        cmd=['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ForwardAgent=no','-o','ConnectTimeout=10','fipi','python3 -']
        result=subprocess.run(cmd,input=script,capture_output=True,text=True,timeout=110)
        if result.returncode!=0:
            text=(result.stderr+result.stdout).lower()
            kinds={k:(k in text) for k in ['input-data','too large','maximum','413','argument list','parameter verification','connection','permission denied','partial payload mismatch','guest stage failure']}
            print(json.dumps({'transport_failed':True,'diagnostic_matches':kinds}));raise RuntimeError('management transport failed')
        outcome=json.loads(result.stdout)
        assert outcome.get('exitcode')==0 and not outcome.get('out-truncated'),'prestage failed; inspect only minimized diagnostics'
        receipt=json.loads(outcome['out-data'])
        print(json.dumps(receipt))

def self_test():
    compile(REMOTE.replace('PAYLOAD','{}',1),'<target-prestage>','exec')
    data=gzip.compress(json.dumps({'public_artifact':'fixture'}).encode(),mtime=0)
    assert data==gzip.compress(json.dumps({'public_artifact':'fixture'}).encode(),mtime=0)
    reconstructed=b''.join(data[i:i+7] for i in range(0,len(data),7))
    assert reconstructed==data and json.loads(gzip.decompress(reconstructed))=={'public_artifact':'fixture'}
    assert 'systemctl' not in REMOTE and 'ca.pub' not in REMOTE
    print('PASS: staged script syntax, deterministic/resumable transport, no CA/reload mutation')

if __name__=='__main__':
    import sys
    self_test() if sys.argv[1:]==['--self-test'] else main()
