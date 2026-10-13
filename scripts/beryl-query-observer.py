#!/usr/bin/env python3
"""Bounded VM220 read-only IPv4 raw observer: no Ethernet/MAC, kernel-filtered
single private source/destination, DNS query port and synthetic pins- challenge.
Never run on Beryl. No packet/config/endpoint output or persistence.
"""
import socket,ctypes,ipaddress,time,json,re,select,pathlib,sys,os,subprocess

def filters(src,dst,proto,expected=None):
 p=[];guards=[]
 def add(code,k=0):p.append([code,0,0,k])
 def equal(k):guards.append(len(p));add(0x15,k)
 add(0x20,12);equal(int(ipaddress.ip_address(src)));add(0x20,16);equal(int(ipaddress.ip_address(dst)))
 add(0x30,9);equal(proto)
 add(0xb1,0);add(0x48,2);equal(53)
 if proto==17:offset=21
 else:
  add(0x50,12);add(0x54,0xf0);add(0x74,2);add(0x0c);add(0x07);offset=15
 add(0x50,offset-1);equal(21)
 add(0x40,offset);equal(int.from_bytes(b'pins','big'));add(0x50,offset+4);equal(45)
 add(0x40,offset+21);equal(int.from_bytes(b'\x07inv','big'));add(0x40,offset+25);equal(int.from_bytes(b'alid','big'));add(0x50,offset+29);equal(0)
 if expected:
  assert re.fullmatch(r'pins-[0-9a-f]{16}\.invalid',expected)
  label=expected.split('.')[0].encode('ascii')
  for i in range(0,20,4):add(0x40,offset+i);equal(int.from_bytes(label[i:i+4],'big'))
  add(0x50,offset+20);equal(label[20])
 add(0x06,65535);add(0x06,0)
 for i in guards:p[i][2]=len(p)-i-2
 return p

def challenge(packet,proto):
 try:
  ihl=(packet[0]&15)*4;off=ihl+(8 if proto==17 else (packet[ihl+12]>>4)*4+2)+12
  parts=[]
  while packet[off]:
   n=packet[off];assert 0<n<64;parts.append(packet[off+1:off+1+n].decode('ascii'));off+=n+1
  name='.'.join(parts)
  return name if re.fullmatch(r'pins-[0-9a-f]{16}\.invalid',name) else None
 except (IndexError,ValueError,UnicodeError,AssertionError):return None

def main():
 gateway_mode=sys.argv[4:5]==['--gateway'];src=sys.argv[1];assert ipaddress.ip_address(src).is_private
 if gateway_mode:
  m=json.loads(pathlib.Path('/etc/21pins/wg-beryl.json').read_text());assert m['interface']=='wg0' and src==m['allowed_ip'].split('/')[0]
  assert pathlib.Path('/sys/class/net/wg0/type').read_text().strip()=='65534' # ARPHRD_NONE: no link/MAC header.
  dst=sys.argv[5];assert ipaddress.ip_address(dst).is_private
 else:
  m=json.loads(pathlib.Path('/etc/21pins/dns-admin.json').read_text());dst=m['resolver'];assert m['technitium_unit']=='dns.service'
  service=subprocess.run(['/usr/bin/systemctl','is-active','dns.service'],capture_output=True,text=True,timeout=3)
  assert service.returncode==0 and service.stdout.strip()=='active'
 seconds=int(sys.argv[2]) if len(sys.argv)>2 else 95;assert 1<=seconds<=100
 expected=sys.argv[3] if len(sys.argv)>3 else None
 if expected:assert re.fullmatch(r'pins-[0-9a-f]{16}\.invalid',expected)
 stop=pathlib.Path('/tmp/21pins-beryl-observer-stop');assert not stop.exists() and not stop.is_symlink()
 class Filter(ctypes.Structure):_fields_=[('code',ctypes.c_ushort),('jt',ctypes.c_ubyte),('jf',ctypes.c_ubyte),('k',ctypes.c_uint)]
 class Program(ctypes.Structure):_fields_=[('len',ctypes.c_ushort),('filter',ctypes.POINTER(Filter))]
 sockets=[];arrays=[]
 for proto in [17,6]:
  # Cooked packets contain IP only, never Ethernet/MAC or sockaddr link metadata.
  if gateway_mode:s=socket.socket(socket.AF_PACKET,socket.SOCK_DGRAM,0)
  else:s=socket.socket(socket.AF_INET,socket.SOCK_RAW,proto);s.bind((dst,0))
  p=filters(src,dst,proto,expected);a=(Filter*len(p))(*(Filter(*i) for i in p));arrays.append(a);f=Program(len(p),a);s.setsockopt(socket.SOL_SOCKET,26,bytes(f))
  if gateway_mode:s.bind((m['interface'],0x0800))
  s.setblocking(False)
  # Discard any pre-filter queued datagrams without copying payload or identifiers.
  libc=ctypes.CDLL(None,use_errno=True);libc.recv.argtypes=[ctypes.c_int,ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int];libc.recv.restype=ctypes.c_ssize_t
  for _ in range(128):
   n=libc.recv(s.fileno(),None,0,socket.MSG_TRUNC|socket.MSG_DONTWAIT)
   if n<0:
    if ctypes.get_errno() in [11,35]:break
    raise RuntimeError('queue purge failed closed')
  else:raise RuntimeError('queue purge bound exceeded')
  sockets.append((s,proto))
 started=time.time()
 ready=pathlib.Path('/tmp/21pins-beryl-observer-ready');fd=os.open(str(ready),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);os.write(fd,(expected or 'kernel-filter-active').encode());os.close(fd)
 print(json.dumps({'synthetic_only_kernel_filter_active':True,'window_seconds':seconds,'no_MAC_public_IP_or_nonchallenge_query_collection':True}),flush=True)
 end=time.monotonic()+seconds;counts={};epochs={}
 try:
  while time.monotonic()<end:
   if expected and stop.is_file() and not stop.is_symlink() and stop.stat().st_uid==0 and stop.read_bytes()==expected.encode():break
   selected,_,_=select.select([x[0] for x in sockets],[],[],max(0,min(1,end-time.monotonic())))
   for s in selected:
    proto=next(p for v,p in sockets if v is s);name=challenge(s.recv(2048),proto)
    if name and (not expected or name==expected):
     row=counts.setdefault(name,{'UDP':0,'TCP':0});row['UDP' if proto==17 else 'TCP']+=1;epochs.setdefault(name,[]).append(time.time())
 finally:
  ended=time.time()
  for s,_ in sockets:s.close()
  ready.unlink(missing_ok=True)
  if expected and stop.is_file() and not stop.is_symlink() and stop.stat().st_uid==0 and stop.read_bytes()==expected.encode():stop.unlink()
 print(json.dumps({'source_bound_synthetic_queries':counts,'query_UTC_epochs':epochs,'observer_closed':True,'technitium_active':not gateway_mode,'gateway_interface_observed':gateway_mode,'observation_start_UTC_epoch':started,'observation_end_UTC_epoch':ended,'not_guest_or_handshake_proof_alone':True}),flush=True)
def self_test():
 # RFC5737 documentation fixtures, never live endpoints or owner identifiers.
 src=str(ipaddress.IPv4Address(0xc000020a));dst=str(ipaddress.IPv4Address(0xc0000235));name='pins-0123456789abcdef.invalid';q=b'\x15pins-0123456789abcdef\x07invalid\x00\x00\x01\x00\x01';dns=b'\x00'*12+q
 def packet(proto):
  ip=bytearray(20);ip[0]=0x45;ip[9]=proto;ip[12:16]=ipaddress.ip_address(src).packed;ip[16:20]=ipaddress.ip_address(dst).packed
  h=bytearray(8 if proto==17 else 20);h[2:4]=b'\x00\x35'
  if proto==6:h[12]=0x50
  return bytes(ip)+bytes(h)+(b'\x00'+bytes([len(dns)]) if proto==6 else b'')+dns
 def accept(p,program):
  a=x=pc=0
  while pc<len(program):
   code,jt,jf,k=program[pc]
   if code in [0x20,0x30,0x40,0x48,0x50]:
    off=k+(x if code not in [0x20,0x30] else 0);n={0x20:4,0x30:1,0x40:4,0x48:2,0x50:1}[code]
    if off+n>len(p):return False
    a=int.from_bytes(p[off:off+n],'big')
   elif code==0xb1:x=(p[k]&15)*4
   elif code==0x15:pc+=(jt if a==k else jf)
   elif code==0x54:a&=k
   elif code==0x74:a>>=k
   elif code==0x0c:a+=x
   elif code==0x07:x=a
   elif code==0x06:return k!=0
   else:raise AssertionError('unknown opcode')
   pc+=1
  return False
 for proto in [17,6]:
  p=packet(proto);program=filters(src,dst,proto);assert accept(p,program) and challenge(p,proto)==name
  bad=bytearray(p);bad[12]=11;assert not accept(bad,program)
  bad=p.replace(b'invalid',b'example');assert not accept(bad,program) and challenge(bad,proto) is None
  assert not accept(p[:25],program)
  exact=filters(src,dst,proto,name);assert accept(p,exact)
  assert not accept(p.replace(b'0123456789abcdef',b'fedcba9876543210'),exact)
  ip=bytearray(p[:20]);ip[0]=0x46;options=bytes(ip)+b'\0'*4+p[20:]
  assert accept(options,exact) and challenge(options,proto)==name
  if proto==6:
   tcp=bytearray(p[20:40]);tcp[12]=0x60;options=p[:20]+bytes(tcp)+b'\0'*4+p[40:]
   assert accept(options,exact) and challenge(options,proto)==name
 print('PASS: kernel filter synthetic UDP/TCP/source/domain/truncation and parser checks')
def native_self_test():
 # Existing server itself only; never send a probe to Beryl or alter DNS settings.
 m=json.loads(pathlib.Path('/etc/21pins/dns-admin.json').read_text());dst=m['resolver']
 class F(ctypes.Structure):_fields_=[('code',ctypes.c_ushort),('jt',ctypes.c_ubyte),('jf',ctypes.c_ubyte),('k',ctypes.c_uint)]
 class P(ctypes.Structure):_fields_=[('len',ctypes.c_ushort),('filter',ctypes.POINTER(F))]
 name='pins-0123456789abcdef.invalid';dns=bytes.fromhex('312101000001000000000000')+bytes([21])+b'pins-0123456789abcdef'+bytes([7])+b'invalid'+bytes.fromhex('0000010001');out={}
 for proto in [17,6]:
  raw=socket.socket(socket.AF_INET,socket.SOCK_RAW,proto);raw.bind((dst,0));program=filters(dst,dst,proto);array=(F*len(program))(*(F(*i) for i in program));pr=P(len(program),array);raw.setsockopt(socket.SOL_SOCKET,26,bytes(pr));raw.settimeout(2)
  client=socket.socket(socket.AF_INET,socket.SOCK_DGRAM if proto==17 else socket.SOCK_STREAM);client.settimeout(2);client.bind((dst,0))
  try:
   if proto==17:client.sendto(dns,(dst,53))
   else:client.connect((dst,53));client.sendall(len(dns).to_bytes(2,'big')+dns)
   valid=challenge(raw.recv(2048),proto)==name
  except socket.timeout:valid=False
  finally:client.close();raw.close()
  out['UDP' if proto==17 else 'TCP']=valid
 print(json.dumps({'native_kernel_positive_synthetic_SELF_server_only':out,'no_Beryl_probe_or_settings_change':True}));assert all(out.values())
if __name__=='__main__':
 if sys.argv[1:]==['--self-test']:self_test()
 elif sys.argv[1:]==['--native-self-test']:native_self_test()
 else:main()
