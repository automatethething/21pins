#!/usr/bin/env python3
"""OWNER-RUN only: one bounded server witness + immediate trusted client proof.
Pi may run pure tests, never --owner-run. No guest testing or settings changes.
"""
import argparse,datetime,json,os,pathlib,secrets,shlex,signal,subprocess,sys,time
ROOT=pathlib.Path(__file__).resolve().parents[1]
BASE='''import pathlib,json,subprocess,time
m=json.loads(pathlib.Path('/etc/21pins/wg-beryl.json').read_text());peer=m['peer_public_key'];interface=m['interface'];assert interface=='wg0'
def row(kind):
 r=subprocess.run(['/usr/bin/wg','show',interface,kind],capture_output=True,text=True,check=True,timeout=3)
 matches=[x.split()[1:] for x in r.stdout.splitlines() if x.split() and x.split()[0]==peer];assert len(matches)==1
 return [int(x) for x in matches[0]]
a=row('transfer');b=row('latest-handshakes');assert len(a)==2 and len(b)==1
r=subprocess.run(['/usr/bin/wg','show',interface,'allowed-ips'],capture_output=True,text=True,check=True,timeout=3)
allowed=[x.split()[1:] for x in r.stdout.splitlines() if x.split() and x.split()[0]==peer];assert allowed==[[m['allowed_ip']]]
print(json.dumps({'pinned_source_mapping_verified':True,'UTC_epoch':time.time(),'pinned_peer_rx_bytes':a[0],'pinned_peer_tx_bytes':a[1],'pinned_peer_handshake_epoch':b[0]}))
'''
def command(vm,seconds):
 return ['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ForwardAgent=no','-o','ConnectTimeout=4','fipi',shlex.join(['sudo','-n','/usr/sbin/qm','guest','exec',str(vm),'--pass-stdin','1','--timeout',str(seconds),'--','/usr/bin/python3','-'])]
def decode(text):
 d=json.loads(text)
 if d.get('exitcode')!=0:raise ValueError('bounded guest operation failed')
 return [json.loads(l) for l in d.get('out-data','').splitlines() if l.strip()]
def guest(vm,source,seconds=6):
 r=subprocess.run(command(vm,seconds),input=source,text=True,capture_output=True,timeout=seconds+6)
 if r.returncode:raise ValueError('existing management unavailable')
 return decode(r.stdout)
def marker(nonce,stop=False):
 return '''import pathlib,json,os,time
p=pathlib.Path('/tmp/21pins-beryl-observer-ready');nonce='''+repr(nonce)+'''
ready=p.is_file() and not p.is_symlink() and p.stat().st_uid==0 and p.stat().st_mode&0o777==0o600 and p.read_bytes()==nonce.encode()
'''+('''if not ready:raise ValueError('owned observer not ready')
fd=os.open('/tmp/21pins-beryl-observer-stop',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);os.write(fd,nonce.encode());os.close(fd)
''' if stop else '')+'''print(json.dumps({'ready':ready,'server_UTC_epoch':time.time()}))
'''
def correlated(before,after,client,observer):
 result={'trusted_network_E2E_verified':False,'guest_isolation_verified':False,'nonce_arrival_verified':False,'filtering_policy_verified':False,'peer_traffic_verified':False,'time_window_verified':False}
 try:
  nonce=client['synthetic_query_challenge'];counts=observer['source_bound_synthetic_queries'][nonce];epochs=observer['query_UTC_epochs'][nonce]
  start=datetime.datetime.fromisoformat(client['UTC_start']).timestamp();end=datetime.datetime.fromisoformat(client['UTC_end']).timestamp()
  result['nonce_arrival_verified']=counts['UDP']>0 and counts['TCP']>0 and observer['observer_closed'] and observer['technitium_active']
  result['time_window_verified']=before['UTC_epoch']<=start<=end<=after['UTC_epoch'] and bool(epochs) and all(start-2<=x<=end+2 for x in epochs)
  result['peer_traffic_verified']=before['pinned_source_mapping_verified'] and after['pinned_source_mapping_verified'] and after['pinned_peer_rx_bytes']>before['pinned_peer_rx_bytes'] and after['pinned_peer_tx_bytes']>before['pinned_peer_tx_bytes'] and 0<=after['UTC_epoch']-after['pinned_peer_handshake_epoch']<=180
  def allowed(r):return r['transport_completed'] and r['status']=='NOERROR' and r['answer_present']
  result['filtering_policy_verified']=all(client['private_DNS'][x]['blocked_control']['transport_completed'] and client['private_DNS'][x]['blocked_control']['status']=='NXDOMAIN' and client['private_DNS'][x]['blocked_control']['explicit_block_or_filter_EDE'] for x in ['UDP','TCP'])
  controls=allowed(client['default_public_DNS']) and client['public_Internet_HTTPS_works'] and all(allowed(client['private_DNS'][x]['allowed_control']) and client['private_DNS'][x]['challenge']['transport_completed'] and client['private_DNS'][x]['challenge']['status']=='NXDOMAIN' for x in ['UDP','TCP'])
  result['trusted_network_E2E_verified']=client.get('owner_attested_client_network')=='trusted' and controls and all(result[x] for x in ['nonce_arrival_verified','time_window_verified','peer_traffic_verified','filtering_policy_verified'])
 except (KeyError,TypeError,ValueError):pass
 return result

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--owner-run',action='store_true');a=p.parse_args()
 if not a.owner_run:p.error('owner must invoke --owner-run while on trusted Beryl network; Pi must not run this')
 os.umask(0o077)
 # ponytail: one owner process, no daemon/retries; 100s main + at most15s cleanup.
 def deadline(*_):raise TimeoutError('attempt hard deadline')
 signal.signal(signal.SIGALRM,deadline);signal.signal(signal.SIGTERM,deadline);signal.alarm(100)
 nonce='pins-'+secrets.token_hex(8)+'.invalid';process=None;closed=False;client=None;client_started=False;report={};stage='preflight'
 try:
  # Fail closed on any earlier collector/control marker; never remove someone else's.
  rows=guest(220,"import pathlib,json\nprint(json.dumps({'clear':all(not p.exists() and not p.is_symlink() for p in [pathlib.Path('/tmp/21pins-beryl-observer-ready'),pathlib.Path('/tmp/21pins-beryl-observer-stop')])}))")
  if not rows[0]['clear']:raise ValueError('previous observation must be reconciled')
  stage='peer_baseline';before=guest(205,BASE)[0]
  m=json.loads((pathlib.Path.home()/'Library/Application Support/21pins/ssh/wg-beryl-manifest.json').read_text());src=m['allowed_ip'].split('/')[0]
  source='import sys\nsys.argv=["observer",'+repr(src)+',"85",'+repr(nonce)+']\n'+(ROOT/'scripts/beryl-query-observer.py').read_text()
  stage='observer_start';armed_at=time.monotonic()
  process=subprocess.Popen(command(220,93),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
  process.stdin.write(source);process.stdin.close();process.stdin=None
  stage='readiness';ready=False
  for _ in range(3):
   if process.poll() is not None:break
   state=guest(220,marker(nonce))[0]
   if state['ready']:
    if abs(time.time()-state['server_UTC_epoch'])>2:raise ValueError('server/client clocks not aligned')
    ready=True;break
   time.sleep(.2)
  if not ready or time.monotonic()-armed_at>20:raise ValueError('kernel observer not ready with sufficient live time; client NOT run')
  print('observer ready / RUN NOW',flush=True)
  # The owner launched this process: no chat delay or second action before client starts.
  stage='owner_client';client_started=True
  r=subprocess.run([sys.executable,str(ROOT/'scripts/beryl-client-proof.py'),'--network','trusted','--challenge',nonce],capture_output=True,text=True,timeout=45)
  if r.returncode:raise ValueError('owner client proof failed')
  client=json.loads(r.stdout)
  stage='observer_stop';guest(220,marker(nonce,True))
  stdout,_=process.communicate(timeout=15)
  if process.returncode:raise ValueError('observer transport did not close cleanly')
  rows=decode(stdout);observer=rows[-1]
  if not observer.get('observer_closed'):raise ValueError('observer cleanup unverified')
  closed=True;stage='peer_post';after=guest(205,BASE)[0];result=correlated(before,after,client,observer)
  report={'client':client,'server_nonce_evidence':observer,'peer_rx_increase':after['pinned_peer_rx_bytes']-before['pinned_peer_rx_bytes'],'peer_tx_increase':after['pinned_peer_tx_bytes']-before['pinned_peer_tx_bytes'],'peer_handshake_before':before['pinned_peer_handshake_epoch'],'peer_handshake_after':after['pinned_peer_handshake_epoch'],'before_UTC_epoch':before['UTC_epoch'],'after_UTC_epoch':after['UTC_epoch'],'correlation':result}
 except (Exception,KeyboardInterrupt):
  report={'trusted_network_E2E_verified':False,'attempt_failed_closed':True,'client_started':client_started,'failure_stage':stage,'no_automatic_retry':True}
 finally:
  signal.alarm(0)
  if process is not None and not closed:
   try:
    if process.poll() is None:guest(220,marker(nonce,True),3)
    stdout,_=process.communicate(timeout=6)
    closed=process.returncode==0 and decode(stdout)[-1].get('observer_closed',False)
   except Exception:pass
   if not closed:report.update({'cleanup_unverified':True,'remote_observer_has_85s_hard_limit':True,'do_not_retry':True})
  report.update({'observer_cleanup_verified':closed or process is None,'observer_started':process is not None,'guest_isolation_verified':False,'single_attempt_authorization_consumed':True})
  print(json.dumps(report,separators=(',',':')),flush=True)
if __name__=='__main__':main()
