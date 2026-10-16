#!/usr/bin/env python3
"""Private serial-only controller for an owned offline OpenWrt validation guest.

Run only inside the disposable, network-none runner. No product transport or
host credential is used. Serial bytes are memory-only; replies allowlist JSON.
"""
import argparse,contextlib,fcntl,gzip,hashlib,ipaddress,json,os,pathlib,re,shutil,signal,socket,subprocess,tempfile,threading,time,urllib.request,uuid,zlib
from datetime import datetime,timezone

LAB=pathlib.Path('/lab')
SOCKET=LAB/'control.sock'
ALLOWED={'schema','stage','status','release','revision','target','kernel','packages','signature_checks','signature_ok','installation_ok','result','cases','defect','source_commit','adapter_sha256','network_none','generic_contract_defect','cleanup','reason','test_exit','native_versions','digests','observations','assertions','started_utc','finished_utc','elapsed_ms','event','exit_code','sequence','record_sha256'}
STAGES=['environment_provenance','logical_runtime_binding','logical_rebind','collection_nonmutation','stored_runtime_separation','destination_set_membership','rpdb_classifier_path','forwarding_guard','negative_context','negative_expression','negative_uncalled_chain','negative_unknown_override','negative_controls']

def utc():return datetime.now(timezone.utc).isoformat()

def atomic_json(path,value):
 path=pathlib.Path(path);path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
 temporary=path.with_name('.'+path.name+'.'+uuid.uuid4().hex+'.tmp')
 try:
  with temporary.open('x',encoding='utf8') as stream:
   os.chmod(temporary,0o600);json.dump(value,stream,sort_keys=True);stream.write('\n');stream.flush();os.fsync(stream.fileno())
  os.link(temporary,path) # no replacement of a committed result, even if the caller dies
  descriptor=os.open(path.parent,os.O_RDONLY)
  try:os.fsync(descriptor)
  finally:os.close(descriptor)
 finally:temporary.unlink(missing_ok=True)

class Journal:
 """A result is completed only after host fsync, never on guest exit alone."""
 def __init__(self,root):
  self.root=pathlib.Path(root);self.root.mkdir(mode=0o700,parents=True,exist_ok=True)
 def path(self,stage,event):
  if stage not in STAGES+['cleanup']:raise ValueError('unknown stage')
  number=STAGES.index(stage) if stage in STAGES else 99
  return self.root/('%02d-%s-%s.json'%(number,stage,event))
 @contextlib.contextmanager
 def lock(self):
  with (self.root/'.lock').open('a') as stream:
   os.chmod(stream.name,0o600);fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
   try:yield
   finally:fcntl.flock(stream,fcntl.LOCK_UN)
 def reserve_boot(self):
  with self.lock():
   try:atomic_json(self.root/'boot-token.json',{'budget':1,'consumed':True,'created_utc':utc()})
   except FileExistsError:raise ValueError('one boot budget already consumed')
 def records(self):
  records=[]
  for path in sorted(self.root.glob('*-result.json')):
   record=json.loads(path.read_text());digest=record.pop('record_sha256')
   if hashlib.sha256(json.dumps(record,sort_keys=True).encode()).hexdigest()!=digest:raise ValueError('checkpoint_corruption')
   record['record_sha256']=digest;records.append(record)
  return records
 def state(self):
  results=self.records();good=[r for r in results if r['stage']!='cleanup' and r['status']=='PASS'];bad=[r for r in results if r['stage']!='cleanup' and r['status']!='PASS']
  done={r['stage'] for r in results};pending=[json.loads(p.read_text())['stage'] for p in sorted(self.root.glob('*-started.json')) if json.loads(p.read_text())['stage'] not in done]
  return {'last_completed':good[-1]['stage'] if good else None,'failed_stage':bad[0]['stage'] if bad else None,'interrupted_stage':pending[0] if pending else None}
 def start(self,stage):
  if stage=='cleanup':return
  with self.lock():
   if self.path('cleanup','result').exists() or (self.root/'orchestration-failure.json').exists():raise ValueError('run_closed')
   state=self.state();index=STAGES.index(stage)
   if state['failed_stage'] or state['interrupted_stage']:raise ValueError('failed or interrupted stage; no automatic continuation')
   if index and not self.path(STAGES[index-1],'result').exists():raise ValueError('prior checkpoint missing')
   try:atomic_json(self.path(stage,'started'),{'stage':stage,'event':'started','started_utc':utc()})
   except FileExistsError:raise ValueError('stage already started')
 def finish(self,stage,value):
  with self.lock():
   if stage!='cleanup' and not self.path(stage,'started').exists():raise ValueError('stage not started')
   value=sanitize(dict(value,stage=stage))
   if value.get('status') not in ['PASS','UNVERIFIED','CONTRADICTION']:raise ValueError('invalid terminal gate status')
   record=dict(value,schema=1,event='result',finished_utc=utc(),source_commit='214aad5')
   record['record_sha256']=hashlib.sha256(json.dumps(record,sort_keys=True).encode()).hexdigest()
   try:atomic_json(self.path(stage,'result'),record)
   except FileExistsError:raise ValueError('committed result is immutable')
   return record

def bounded_stage(journal,stage,command,timeout=100):
 if not 0<timeout<=110:raise ValueError('deadline outside bounded policy')
 journal.start(stage)
 child=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
 try:
  try:out,_=child.communicate(timeout=timeout)
  except subprocess.TimeoutExpired:
   os.killpg(child.pid,signal.SIGKILL);child.communicate(timeout=5)
   return journal.finish(stage,{'status':'UNVERIFIED','reason':'outer_deadline'})
  if child.returncode:return journal.finish(stage,{'status':'UNVERIFIED','reason':'external_exit_'+str(abs(child.returncode)),'exit_code':child.returncode})
  try:
   response=sanitize(json.loads(out));frames=response.get('observations',[]);matches=[f for f in frames if f.get('stage')==stage]
   if len(matches)!=1:
    code=response.get('test_exit')
    return journal.finish(stage,{'status':'UNVERIFIED','reason':'native_exit_'+str(code) if isinstance(code,int) and code else 'missing_or_ambiguous_stage_frame'})
   value=sanitize(matches[0]);status=value.get('status')
   if status=='PASS' and response.get('test_exit')!=0:raise ValueError('nonzero native test exit')
   return journal.finish(stage,value)
  except (ValueError,TypeError,KeyError):return journal.finish(stage,{'status':'UNVERIFIED','reason':'invalid_or_missing_safe_frame'})
 finally:
  if child.poll() is None:os.killpg(child.pid,signal.SIGKILL);child.wait(timeout=5)

def sanitize(value):
 if not isinstance(value,dict) or not set(value)<=ALLOWED:raise ValueError('non-allowlisted result fields')
 def check(item,depth=0):
  if depth>8:raise ValueError('nested output exceeds bound')
  if isinstance(item,dict):
   for key,child in item.items():
    if not isinstance(key,str) or re.search(r'token|secret|password|authorization|cookie|credential|endpoint|hostname|(?:^|_)address|(?:^|_)mac(?:_|$)',key,re.I):raise ValueError('sensitive nested field')
    check(child,depth+1)
  elif isinstance(item,list):
   if len(item)>64:raise ValueError('oversized collection')
   for child in item:check(child,depth+1)
  elif isinstance(item,str):
   if len(item)>512 or '://' in item:raise ValueError('oversized or endpoint string')
   for candidate in re.split(r'[\s=,()/\[\]]+',item):
    if ':' not in candidate:continue
    try:ipaddress.IPv6Address(candidate)
    except ValueError:continue
    raise ValueError('identifying string')
  elif item is not None and type(item) not in (int,bool,float):raise ValueError('unsupported value')
 check(value)
 # This lab uses no external identifiers. Never expose address/hardware/credential values.
 text=json.dumps(value)
 if re.search(r'(?:\b\d{1,3}\.){3}\d{1,3}\b|(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}',text):raise ValueError('identifier in result')
 return value

class Console:
 def __init__(self):
  if not (LAB/'base.img').is_file() or not (LAB/'payload.img').is_file():raise RuntimeError('missing owned disks')
  subprocess.run(['qemu-img','create','-q','-f','qcow2','-F','raw','-b',str(LAB/'base.img'),str(LAB/'overlay.qcow2')],check=True,timeout=15)
  self.proc=subprocess.Popen(['qemu-system-x86_64','-accel','tcg,thread=single,tb-size=64','-machine','q35','-cpu','qemu64','-m','768','-smp','1','-nographic','-monitor','none','-serial','stdio','-nic','none','-no-reboot','-drive','file=/lab/overlay.qcow2,format=qcow2,if=virtio','-drive','file=/lab/payload.img,format=raw,if=virtio,readonly=on'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,bufsize=0)
  self.data=bytearray();self.condition=threading.Condition();self.enter=False;self.safe_frames=[];self.private_failure=False
  threading.Thread(target=self.consume,daemon=True).start()
 def consume(self):
  pending=bytearray()
  while True:
   data=os.read(self.proc.stdout.fileno(),4096)
   if not data:return
   with self.condition:
    self.data.extend(data);pending.extend(data)
    if len(self.data)>1<<20:del self.data[:len(self.data)-(1<<20)]
    if len(pending)>65536:self.private_failure=True;pending.clear()
    while b'\n' in pending:
     line,_,rest=pending.partition(b'\n');pending=bytearray(rest)
     frame=re.search(rb'PINS_JSON:(\{.*\})',line)
     if frame:
      try:
       value=sanitize(json.loads(frame.group(1)));atomic_json(LAB/'safe'/'frames'/(uuid.uuid4().hex+'.json'),value);self.safe_frames.append(value)
      except (ValueError,TypeError,OSError):self.private_failure=True
    self.condition.notify_all()
 def ready(self,seconds=90):
  end=time.monotonic()+min(seconds,100)
  while time.monotonic()<end:
   with self.condition:
    current=bytes(self.data)
    if b'Please press Enter' in current and not self.enter:self.proc.stdin.write(b'\n');self.enter=True
    if re.search(rb'root@[^\r\n]+[#$] ?',current):return {'stage':'boot','status':'ready','network_none':True}
    if self.proc.poll() is not None:return {'stage':'boot','status':'failed','reason':'guest_exited'}
    self.condition.wait(.2)
  return {'stage':'boot','status':'pending','network_none':True}
 def execute(self,command,seconds=90):
  marker='PINS_RC_'+uuid.uuid4().hex
  encoded=''.join('\\0%03o'%value for value in command.encode())
  with self.condition:self.data.clear();self.safe_frames.clear()
  # BusyBox ash's interactive line limit is smaller than a complete encoded script.
  # Keep every serial input line short; no raw command/output is persisted.
  end=time.monotonic()+min(seconds,100)
  self.proc.stdin.write(b': > /tmp/pins-command.sh\n')
  for start in range(0,len(encoded),190):
   ack='PINS_CHUNK_'+uuid.uuid4().hex
   self.proc.stdin.write(("printf '%b' '"+encoded[start:start+190]+"' >> /tmp/pins-command.sh; printf '\\n"+ack+"\\n'\n").encode())
   chunk_end=min(end,time.monotonic()+5)
   while True:
    with self.condition:
     if ('\n'+ack+'\n').encode() in bytes(self.data).replace(b'\r',b''):break
     if time.monotonic()>=chunk_end:return {'stage':'command','status':'failed','reason':'serial_chunk_not_acknowledged'}
     self.condition.wait(.1)
  self.proc.stdin.write(("sh /tmp/pins-command.sh; printf '\\n"+marker+":%s\\n' \"$?\"\n").encode())
  while time.monotonic()<end:
   with self.condition:
    current=bytes(self.data).replace(b'\r',b'')
    match=re.search((marker+r':(\d+)').encode(),current)
    if self.private_failure:return {'stage':'command','status':'failed','reason':'privacy_boundary_rejected'}
    if match:
     return {'stage':'command','status':'finished','test_exit':int(match.group(1)),'observations':list(self.safe_frames)}
    if self.proc.poll() is not None:return {'stage':'command','status':'failed','reason':'guest_exited'}
    self.condition.wait(.2)
  return {'stage':'command','status':'failed','reason':'bounded_console_timeout'}
 def stop(self):
  if self.proc.poll() is None:
   self.proc.terminate()
   try:self.proc.wait(timeout=5)
   except subprocess.TimeoutExpired:self.proc.kill();self.proc.wait(timeout=5)
  with self.condition:self.data.clear()

def serve():
 console=None;server=socket.socket(socket.AF_UNIX)
 try:
  if SOCKET.exists():raise RuntimeError('control socket already exists')
  console=Console();server.bind(str(SOCKET));os.chmod(SOCKET,0o600);server.listen(1);server.settimeout(15)
  last=time.monotonic()
  while time.monotonic()-last<100:
   try:conn,_=server.accept()
   except socket.timeout:continue
   with conn:
    conn.settimeout(10);data=bytearray()
    while b'\n' not in data:
     part=conn.recv(65536)
     if not part or len(data)>65536:raise RuntimeError('invalid control input')
     data.extend(part)
    req=json.loads(bytes(data).split(b'\n',1)[0]);action=req.get('action')
    if action=='boot':result=console.ready()
    elif action=='exec':result=console.execute(req['command'])
    elif action=='stop':result={'stage':'stop','status':'stopped'}
    else:result={'stage':'control','status':'failed','reason':'invalid_action'}
    atomic_json(LAB/'safe'/'replies'/(uuid.uuid4().hex+'.json'),sanitize(result))
    conn.sendall(json.dumps(result).encode()+b'\n');last=time.monotonic()
    if action=='stop' or result.get('status')=='failed':break
 finally:
  if console:console.stop()
  server.close()
  if SOCKET.exists():SOCKET.unlink()

def docker(config,*arguments,timeout=20):
 return subprocess.run(['docker','--context',config['context'],*arguments],capture_output=True,text=True,timeout=timeout)

def lease(config,journal,phase,stage=None):
 path=pathlib.Path(config['local_root'])/'leases'/(str(time.monotonic_ns())+'.json')
 atomic_json(path,{'pid':os.getpid(),'deadline':time.monotonic()+110,'phase':phase,'stage':stage,'state':journal.state()})

def recover_safe(config,journal):
 destination=pathlib.Path(config['local_root'])/'recovered-safe';destination.mkdir(exist_ok=True,mode=0o700)
 copied=docker(config,'cp',config['container']+':/lab/safe/.',str(destination),timeout=10).returncode==0
 recovered=0
 if copied:
  for file in destination.rglob('*.json'):
   value=sanitize(json.loads(file.read_text()))
   atomic_json(journal.root/'recovered'/(uuid.uuid4().hex+'.json'),value);recovered+=1
 return recovered

@contextlib.contextmanager
def cleanup_lock(journal,timeout=5):
 with (journal.root/'.cleanup.lock').open('a') as stream:
  os.chmod(stream.name,0o600);deadline=time.monotonic()+timeout
  while True:
   try:fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB);break
   except BlockingIOError:
    if time.monotonic()>=deadline:raise TimeoutError('cleanup_writer_busy')
    time.sleep(.02)
  try:yield
  finally:fcntl.flock(stream,fcntl.LOCK_UN)

def cleanup_owned(config,journal):
 with cleanup_lock(journal):
  if journal.path('cleanup','result').exists():return json.loads(journal.path('cleanup','result').read_text())
  try:value=_cleanup_owned(config,journal)
  except (OSError,ValueError,subprocess.SubprocessError):value={'stage':'cleanup','status':'UNVERIFIED','reason':'bounded_cleanup_failed'}
  if value['status']=='PASS':return journal.finish('cleanup',value)
  atomic_json(journal.root/'cleanup-attempts'/(uuid.uuid4().hex+'.json'),sanitize(dict(value,stage='cleanup')))
  return value

def _cleanup_owned(config,journal):
 # Only the newly created profile is eligible. Never choose a discovered/production target.
 if config.get('owned_profile')!='21pins-fw4-retry' or config.get('context')!='colima-21pins-fw4-retry' or config.get('container')!='21pins-fw4-retry-lab':raise ValueError('invalid owned cleanup scope')
 if journal.path('cleanup','result').exists():return json.loads(journal.path('cleanup','result').read_text())
 recovered=0
 try:recovered=recover_safe(config,journal)
 except (ValueError,OSError,subprocess.SubprocessError):pass
 # No raw Docker/control-plane output is returned or persisted.
 state=docker(config,'inspect','--format','{{.State.OOMKilled}}',config['container'],timeout=5)
 oom=state.returncode==0 and state.stdout.strip()=='true'
 docker(config,'rm','-f',config['container'],timeout=8)
 deleted=subprocess.run(['colima','delete','--profile',config['owned_profile'],'--data','--force'],capture_output=True,text=True,timeout=45).returncode==0
 context=docker(config,'info',timeout=5).returncode==0
 if subprocess.run(['docker','context','inspect',config['context']],capture_output=True,timeout=5).returncode==0:
  subprocess.run(['docker','context','rm',config['context']],capture_output=True,timeout=5)
 context_absent=subprocess.run(['docker','context','inspect',config['context']],capture_output=True,timeout=5).returncode!=0
 current=subprocess.run(['docker','context','show'],capture_output=True,text=True,timeout=5).stdout.strip()
 home=pathlib.Path.home();directories=[home/'.colima'/config['owned_profile'],home/'.colima'/'_lima'/config['owned_profile'],home/'.colima'/'_lima'/('colima-'+config['owned_profile']),home/'.colima'/'_lima'/'_disks'/config['owned_profile'],home/'.colima'/'_lima'/'_disks'/('colima-'+config['owned_profile'])]
 clean=deleted and not context and context_absent and current==config['original_context'] and all(not p.exists() for p in directories)
 local=pathlib.Path(config['local_root']);local_ok=False
 if clean and local.parent==pathlib.Path.home()/'.cache' and local.name.startswith('21pins-fw4-retry-') and not local.is_symlink() and (local/'owned-lab-marker').read_text()=='214aad5':
  shutil.rmtree(local);local_ok=not local.exists()
 clean=clean and local_ok
 return {'status':'PASS' if clean else 'UNVERIFIED','reason':'zero_owned_runtime_resources' if clean else 'cleanup_incomplete','observations':{'vm_and_data_deleted':deleted,'owned_context_absent':context_absent,'owner_context_preserved':current==config['original_context'],'owned_directories_absent':all(not p.exists() for p in directories),'local_staging_removed':local_ok,'container_init_oom_flag':oom,'safe_recovery_records':recovered}}

def guard(config,journal):
 # Each lease <=110s. Only explicit coordinator operations renew it. Never boots/retries.
 root=pathlib.Path(config['local_root'])/'leases';deadline=time.monotonic()+110;value={};reason='lease_expired'
 atomic_json(journal.root/'guard-ready.json',{'mode':'cleanup_only','ready_utc':utc()})
 try:
  while True:
   if journal.path('cleanup','result').exists():return
   files=sorted(root.glob('*.json'),key=lambda p:int(p.stem)) if root.exists() else []
   if files:
    if len(files)>2*(len(STAGES)+5):reason='lease_budget_exhausted';break
    value=json.loads(files[-1].read_text());deadline=min(value['deadline'],float(files[-1].stem)/1e9+110)
    if journal.state()['failed_stage']:reason='native_stage_failed';break
    if value['phase']=='running':
     try:os.kill(value['pid'],0)
     except ProcessLookupError:reason='host_coordinator_terminated';break
   if time.monotonic()>=deadline:break
   time.sleep(.5)
  atomic_json(journal.root/'orchestration-failure.json',{'stage':value.get('stage') or 'orchestration','status':'UNVERIFIED','reason':reason})
 finally:
  try:cleanup_owned(config,journal)
  finally:atomic_json(journal.root/'guard-stopped.json',{'status':'STOPPED','finished_utc':utc()})

def host_step(config,journal,stage,command_file):
 if not (journal.root/'guard-ready.json').exists() or (journal.root/'guard-stopped.json').exists():raise ValueError('guard_not_active')
 os.kill(json.loads((pathlib.Path(config['local_root'])/'guard.json').read_text())['pid'],0)
 lease(config,journal,'running',stage)
 try:
  result=bounded_stage(journal,stage,['docker','--context',config['context'],'exec',config['container'],'python3','/lab/controller.py','rpc','--action','exec','--command-file',command_file],timeout=105)
  if result['status']=='PASS':lease(config,journal,'idle',stage)
  return result # the independent cleanup guard handles terminal failure in its own bounded checkpoint
 except BaseException:
  if not (journal.root/'orchestration-failure.json').exists():atomic_json(journal.root/'orchestration-failure.json',{'stage':stage,'status':'UNVERIFIED','reason':'host_stage_failed'})
  raise

def rpc(action,command=''):
 with socket.socket(socket.AF_UNIX) as client:
  client.settimeout(100);client.connect(str(SOCKET));client.sendall(json.dumps({'action':action,'command':command}).encode()+b'\n');result=bytearray()
  while b'\n' not in result:
   part=client.recv(65536)
   if not part:raise RuntimeError('controller stopped')
   result.extend(part)
  value=json.loads(bytes(result).split(b'\n',1)[0]);print(json.dumps(value))

if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('mode',choices=['serve','rpc','step','guard','cleanup']);parser.add_argument('--action',choices=['boot','exec','stop']);parser.add_argument('--command-file');parser.add_argument('--config');parser.add_argument('--journal');parser.add_argument('--stage');args=parser.parse_args()
 if args.mode=='serve':serve()
 elif args.mode=='rpc':rpc(args.action,pathlib.Path(args.command_file).read_text() if args.command_file else '')
 else:
  config=json.loads(pathlib.Path(args.config).read_text());journal=Journal(args.journal)
  if args.mode=='guard':guard(config,journal)
  elif args.mode=='cleanup':print(json.dumps(cleanup_owned(config,journal)))
  else:print(json.dumps(host_step(config,journal,args.stage,args.command_file)))
