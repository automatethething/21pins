#!/usr/bin/env python3
"""Private serial-only controller for an owned offline OpenWrt validation guest.

Run only inside the disposable, network-none runner. No product transport or
host credential is used. Serial bytes are memory-only; replies allowlist JSON.
"""
import argparse,base64,collections,json,os,pathlib,re,socket,subprocess,threading,time,uuid

LAB=pathlib.Path('/lab')
SOCKET=LAB/'control.sock'
ALLOWED={'stage','status','release','revision','target','kernel','packages','signature_checks','signature_ok','installation_ok','result','cases','defect','source_commit','adapter_sha256','network_none','generic_contract_defect','cleanup','reason','test_exit','native_versions','digests','observations'}

def sanitize(value):
 if not isinstance(value,dict) or not set(value)<=ALLOWED:raise ValueError('non-allowlisted result fields')
 # This lab uses no external identifiers. Never expose address/hardware/credential values.
 text=json.dumps(value)
 if re.search(r'(?:\b\d{1,3}\.){3}\d{1,3}\b|(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}',text):raise ValueError('identifier in result')
 return value

class Console:
 def __init__(self):
  if not (LAB/'base.img').is_file() or not (LAB/'payload.img').is_file():raise RuntimeError('missing owned disks')
  subprocess.run(['qemu-img','create','-q','-f','qcow2','-F','raw','-b',str(LAB/'base.img'),str(LAB/'overlay.qcow2')],check=True,timeout=15)
  self.proc=subprocess.Popen(['qemu-system-x86_64','-accel','tcg,thread=multi','-machine','q35','-cpu','qemu64','-m','512','-smp','2','-nographic','-monitor','none','-serial','stdio','-nic','none','-no-reboot','-drive','file=/lab/overlay.qcow2,format=qcow2,if=virtio','-drive','file=/lab/payload.img,format=raw,if=virtio,readonly=on'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,bufsize=0)
  self.data=bytearray();self.condition=threading.Condition();self.enter=False
  threading.Thread(target=self.consume,daemon=True).start()
 def consume(self):
  while True:
   data=os.read(self.proc.stdout.fileno(),4096)
   if not data:return
   with self.condition:
    self.data.extend(data)
    if len(self.data)>1<<20:del self.data[:len(self.data)-(1<<20)]
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
 def execute(self,command,seconds=80):
  marker='PINS_RC_'+uuid.uuid4().hex
  encoded=''.join('\\0%03o'%value for value in command.encode())
  with self.condition:self.data.clear()
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
    if match:
     records=[]
     for line in current.decode(errors='replace').splitlines():
      frame=re.search(r'PINS_JSON:(\{.*\})',line)
      if frame:records.append(sanitize(json.loads(frame.group(1))))
     return {'stage':'command','status':'finished','test_exit':int(match.group(1)),'observations':records}
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
    conn.sendall(json.dumps(result).encode()+b'\n');last=time.monotonic()
    if action=='stop' or result.get('status')=='failed':break
 finally:
  if console:console.stop()
  server.close()
  if SOCKET.exists():SOCKET.unlink()

def rpc(action,command=''):
 with socket.socket(socket.AF_UNIX) as client:
  client.settimeout(110);client.connect(str(SOCKET));client.sendall(json.dumps({'action':action,'command':command}).encode()+b'\n');result=bytearray()
  while b'\n' not in result:
   part=client.recv(65536)
   if not part:raise RuntimeError('controller stopped')
   result.extend(part)
  value=json.loads(bytes(result).split(b'\n',1)[0]);print(json.dumps(value))

if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('mode',choices=['serve','rpc']);parser.add_argument('--action',choices=['boot','exec','stop']);parser.add_argument('--command-file');args=parser.parse_args()
 if args.mode=='serve':serve()
 else:rpc(args.action,pathlib.Path(args.command_file).read_text() if args.command_file else '')
