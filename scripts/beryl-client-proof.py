#!/usr/bin/env python3
"""OWNER-RUN client checks only. Pi must not run this against human-controlled Beryl.
No router login/admin, MAC/public-IP collection or raw DNS/network output.
These results require fresh server-side correlation; alone they are NOT E2E proof.
"""
import argparse,json,pathlib,re,subprocess,datetime,socket,secrets,shutil,ipaddress

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
 a=argparse.ArgumentParser();a.add_argument('--self-test',action='store_true');a.add_argument('--network',choices=['trusted','guest']);x=a.parse_args()
 if x.self_test:self_test();return
 if not x.network:a.error('owner must select actual connected trusted/guest client network')
 if not shutil.which('dig'):a.error('native dig required; do not substitute router-origin checks')
 manifest=json.loads((pathlib.Path(__file__).resolve().parents[1]/'docs/ssh-technitium-manifest.json').read_text());resolver=manifest['resolver'];nonce='pins-'+secrets.token_hex(8);challenge=nonce+'.invalid'
 def query(domain,tcp=False,direct=True):
  args=['dig','+time=2','+tries=1']+(['@'+resolver] if direct else [])+[domain,'A']+(['+tcp'] if tcp else [])
  try:r=subprocess.run(args,capture_output=True,text=True,timeout=4);return dns_result(r.returncode,r.stdout)
  except subprocess.TimeoutExpired:return dns_result(1,'')
 out={'owner_attested_client_network':x.network,'UTC_start':datetime.datetime.now(datetime.timezone.utc).isoformat(),'synthetic_query_challenge':challenge,'default_public_DNS':query('example.com',direct=False),'default_synthetic_query':query(challenge,direct=False),'private_DNS':{}}
 for tcp in [False,True]:
  out['private_DNS']['TCP' if tcp else 'UDP']={'allowed_control':query('example.com',tcp),'blocked_control':query('ad.doubleclick.net',tcp),'challenge':query(challenge,tcp)}
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
