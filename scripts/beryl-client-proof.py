#!/usr/bin/env python3
"""OWNER-RUN client checks only. Pi must not run this against human-controlled Beryl.
No router login/admin, MAC/public-IP collection or raw DNS/network output.
These results require fresh server-side correlation; alone they are NOT E2E proof.
"""
import argparse,json,pathlib,re,subprocess,datetime,socket,secrets,shutil,ipaddress,struct

def wire_result(data,ident,domain):
 # Decode only this test response; old macOS dig may not render EDNS EDE.
 def name(off):
  labels=[];end=None;seen=set()
  for _ in range(128):
   if off in seen or off>=len(data):raise ValueError('invalid DNS name')
   seen.add(off);n=data[off]
   if n&192==192:
    if off+1>=len(data):raise ValueError('short pointer')
    if end is None:end=off+2
    off=((n&63)<<8)|data[off+1];continue
   if n&192 or off+1+n>len(data):raise ValueError('invalid label')
   off+=1
   if not n:return '.'.join(labels),end if end is not None else off
   labels.append(data[off:off+n].decode('ascii').lower());off+=n
  raise ValueError('name bound')
 if len(data)<12:raise ValueError('short DNS')
 xid,flags,qd,an,ns,ar=struct.unpack('!6H',data[:12])
 if xid!=ident or not flags&0x8000 or flags&0x7a00 or qd!=1 or an+ns+ar>128:raise ValueError('unexpected DNS response')
 q,off=name(12)
 if q!=domain or data[off:off+4]!=struct.pack('!HH',1,1):raise ValueError('wrong question')
 off+=4;ede=False
 for _ in range(an+ns+ar):
  _,off=name(off)
  if off+10>len(data):raise ValueError('short RR')
  typ,cl,ttl,n=struct.unpack('!HHIH',data[off:off+10]);off+=10;end=off+n
  if end>len(data):raise ValueError('short RDATA')
  if typ==41 and (ttl>>16)&255==0:
   pos=off
   while pos<end:
    if pos+4>end:raise ValueError('short OPT')
    code,length=struct.unpack('!HH',data[pos:pos+4]);pos+=4
    if pos+length>end:raise ValueError('short option')
    if code==15 and length>=2 and int.from_bytes(data[pos:pos+2],'big') in [15,17]:ede=True
    pos+=length
  off=end
 return {'status':{0:'NOERROR',3:'NXDOMAIN'}.get(flags&15,'unverified'),'transport_completed':not bool(flags&512),'answer_present':an>0,'explicit_block_or_filter_EDE':ede}

def policy_query(resolver,tcp):
 domain='ad.doubleclick.net';ident=secrets.randbits(16)
 q=struct.pack('!6H',ident,0x100,1,0,0,1)+b'\x02ad\x0bdoubleclick\x03net\0'+struct.pack('!HH',1,1)+b'\0'+struct.pack('!HHIH',41,1232,0,0)
 try:
  with socket.socket(socket.AF_INET,socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as s:
   s.settimeout(2);s.connect((resolver,53))
   if tcp:
    s.sendall(len(q).to_bytes(2,'big')+q)
    def receive(n):
     result=b''
     while len(result)<n:
      part=s.recv(n-len(result))
      if not part:raise ValueError('short TCP response')
      result+=part
     return result
    n=int.from_bytes(receive(2),'big')
    if not 12<=n<=4096:raise ValueError('response bound')
    data=receive(n)
   else:s.send(q);data=s.recv(4096)
   return wire_result(data,ident,domain)
 except (OSError,ValueError,UnicodeError,struct.error):return dns_result(1,'')

def dns_result(returncode,text):
 m=re.search(r'status: ([A-Z]+)',text)
 answer=re.search(r'ANSWER: (\d+)',text)
 return {'status':m.group(1) if m else 'unverified','transport_completed':returncode==0 and bool(m),'answer_present':bool(answer and int(answer.group(1))),'explicit_block_or_filter_EDE':bool(re.search(r'EDE:\s*(?:15|17)\s*\((?:Blocked|Filtered)\)',text,re.I))}

def self_test():
 assert dns_result(0,'status: NXDOMAIN, ANSWER: 0\n; EDE: 15 (Blocked)')['explicit_block_or_filter_EDE']
 assert not dns_result(9,'timeout')['transport_completed']
 assert not dns_result(0,'status: NXDOMAIN, ANSWER: 0')['explicit_block_or_filter_EDE']
 assert dns_result(0,'status: NOERROR, ANSWER: 1')['answer_present']
 print('PASS: timeout/NXDOMAIN alone not filtering; explicit EDE/control parsed without addresses')

def main():
 a=argparse.ArgumentParser();a.add_argument('--self-test',action='store_true');a.add_argument('--network',choices=['trusted','guest']);a.add_argument('--challenge',help='synchronized owner-run nonce');x=a.parse_args()
 if x.self_test:self_test();return
 if not x.network:a.error('owner must select actual connected trusted/guest client network')
 if not shutil.which('dig'):a.error('native dig required; do not substitute router-origin checks')
 manifest=json.loads((pathlib.Path(__file__).resolve().parents[1]/'docs/ssh-technitium-manifest.json').read_text());resolver=manifest['resolver'];nonce='pins-'+secrets.token_hex(8);challenge=x.challenge or nonce+'.invalid'
 if not re.fullmatch(r'pins-[0-9a-f]{16}\.invalid',challenge):a.error('invalid synthetic challenge')
 def query(domain,tcp=False,direct=True):
  args=['dig','+time=2','+tries=1']+(['@'+resolver] if direct else [])+[domain,'A']+(['+tcp'] if tcp else [])
  try:r=subprocess.run(args,capture_output=True,text=True,timeout=4);return dns_result(r.returncode,r.stdout)
  except subprocess.TimeoutExpired:return dns_result(1,'')
 out={'owner_attested_client_network':x.network,'UTC_start':datetime.datetime.now(datetime.timezone.utc).isoformat(),'synthetic_query_challenge':challenge,'default_public_DNS':query('example.com',direct=False),'default_synthetic_query':query(challenge,direct=False),'private_DNS':{}}
 for tcp in [False,True]:
  out['private_DNS']['TCP' if tcp else 'UDP']={'allowed_control':query('example.com',tcp),'blocked_control':policy_query(resolver,tcp),'challenge':query(challenge,tcp)}
 if x.network=='guest':
  out['private_admin_TCP']={}
  for port in [22,5380]:
   try:
    with socket.create_connection((resolver,port),timeout=2):reachable=True
   except OSError:reachable=False
   out['private_admin_TCP'][str(port)]={'reachable':reachable,'negative_alone_not_packet_isolation_proof':True}
  if shutil.which('scutil'):
   r=subprocess.run(['scutil','--dns'],capture_output=True,text=True,timeout=3);private=ipaddress.ip_network(resolver+'/24',strict=False)
   vals=re.findall(r'nameserver\[\d+\]\s*:\s*([0-9.]+)',r.stdout)
   out['private_resolver_advertised_as_DNS_or_failover']=any(ipaddress.ip_address(v) in private for v in vals)
 if shutil.which('curl'):
  r=subprocess.run(['curl','--max-time','5','--silent','--head','--output','/dev/null','--write-out','%{http_code}','https://example.com'],capture_output=True,text=True,timeout=6)
  out['public_Internet_HTTPS_works']=r.returncode==0 and r.stdout[:1] in ['2','3']
 out['UTC_end']=datetime.datetime.now(datetime.timezone.utc).isoformat();out['fresh_server_query_packet_handshake_correlation_required']=True;out['E2E_complete']=False
 print(json.dumps(out,separators=(',',':')))
if __name__=='__main__':main()
