#!/usr/bin/env python3
"""OWNER-RUN guest-only diagnostic. Never run live from Pi, never re-test trusted.
Silence cannot verify the intended boundary. No policy/configuration changes.
"""
import argparse,datetime,importlib.util,json,os,pathlib,secrets,signal,subprocess,sys,time
ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('synchronized',ROOT/'scripts/beryl-synchronized-proof.py');common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)

def classify(client,gateway,resolver,before,after,*,trusted_dns_baseline_verified=False,boundary_witness=None):
 # Witness is an independently validated policy-audit result, NEVER raw client JSON.
 r={'guest_isolation_verified':False,'intended_boundary_rejection_verified':False,'trusted_DNS_baseline_verified':trusted_dns_baseline_verified is True,'public_not_protected_DNS_behavior_verified':False,'public_controls_pass':False,'private_DNS_no_completed_transport':False,'no_observed_protected_path_nonce':False,'protected_path_nonce_detected':False,'observation_brackets_guest_test':False,'reason':'incomplete_observation'}
 try:
  nonce=client['synthetic_query_challenge'];start=datetime.datetime.fromisoformat(client['UTC_start']).timestamp();end=datetime.datetime.fromisoformat(client['UTC_end']).timestamp()
  r['observation_brackets_guest_test']=before<=start<=end<=after and all(o['observer_closed'] and o['observation_start_UTC_epoch']<=start<=end<=o['observation_end_UTC_epoch'] for o in [gateway,resolver])
  r['public_controls_pass']=client['owner_attested_client_network']=='guest' and client['default_public_DNS']['transport_completed'] and client['default_public_DNS']['status']=='NOERROR' and client['default_public_DNS']['answer_present'] and client['public_Internet_HTTPS_works']
  r['private_DNS_no_completed_transport']=all(not client['private_DNS'][p][k]['transport_completed'] for p in ['UDP','TCP'] for k in ['allowed_control','blocked_control','challenge'])
  total=sum(sum(o['source_bound_synthetic_queries'].get(nonce,{}).values()) for o in [gateway,resolver])
  r['protected_path_nonce_detected']=total>0;r['no_observed_protected_path_nonce']=total==0 and r['observation_brackets_guest_test']
  r['protected_DNS_endpoint_no_completed_transport']=r['private_DNS_no_completed_transport']
  r['supplementary_private_admin_TCP_reachable']=any(x['reachable'] for x in client.get('private_admin_TCP',{}).values())
  default=client['default_synthetic_query']
  r['public_not_protected_DNS_behavior_verified']=r['public_controls_pass'] and client.get('private_resolver_advertised_as_DNS_or_failover') is False and default['transport_completed'] and default['status']=='NXDOMAIN' and r['no_observed_protected_path_nonce']
  w=boundary_witness if isinstance(boundary_witness,dict) else {}
  r['intended_boundary_rejection_verified']=all(w.get(k) is True for k in ['independently_validated','guest_to_protected_DNS_path','test_specific_match','UDP_TCP_scope_verified','applicable_policy_verified']) and w.get('action') in ['drop','reject','prohibit'] and isinstance(w.get('rule_identity'),str) and bool(w['rule_identity'].strip())
  required=['public_controls_pass','public_not_protected_DNS_behavior_verified','trusted_DNS_baseline_verified','private_DNS_no_completed_transport','no_observed_protected_path_nonce','observation_brackets_guest_test','intended_boundary_rejection_verified']
  r['guest_isolation_verified']=all(r[k] for k in required)
  if total or not r['private_DNS_no_completed_transport']:r['reason']='private_DNS_or_protected_path_access_observed'
  elif not r['public_controls_pass']:r['reason']='public_positive_control_failed'
  elif not r['observation_brackets_guest_test']:r['reason']='server_observation_did_not_cover_guest_test'
  elif not r['public_not_protected_DNS_behavior_verified']:r['reason']='public_vs_protected_DNS_behavior_not_proven'
  elif not r['trusted_DNS_baseline_verified']:r['reason']='known_positive_trusted_DNS_baseline_missing'
  elif not r['intended_boundary_rejection_verified']:r['reason']='intended_boundary_rejection_not_proven'
  else:r['reason']='required_guest_DNS_path_properties_verified'
  # ponytail: admin probes are supplementary; absence is not a boundary witness.
 except (KeyError,TypeError,ValueError):pass
 return r

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--owner-run',action='store_true');a=p.parse_args()
 if not a.owner_run:p.error('owner only: connect guest then invoke --owner-run; Pi must not run live')
 os.umask(0o077);processes={};observers={};client=None;client_started=False;stage='preflight';report={}
 def deadline(*_):raise TimeoutError('bounded attempt deadline')
 signal.signal(signal.SIGALRM,deadline);signal.signal(signal.SIGTERM,deadline);signal.alarm(95)
 nonce='pins-'+secrets.token_hex(8)+'.invalid'
 try:
  clear="import pathlib,json\nprint(json.dumps({'clear':all(not p.exists() and not p.is_symlink() for p in [pathlib.Path('/tmp/21pins-beryl-observer-ready'),pathlib.Path('/tmp/21pins-beryl-observer-stop')])}))"
  for vm in [205,220]:
   if not common.guest(vm,clear)[0]['clear']:raise ValueError('previous observer must be reconciled')
  stage='peer_baseline';before=common.guest(205,common.BASE)[0]
  wg=json.loads((pathlib.Path.home()/'Library/Application Support/21pins/ssh/wg-beryl-manifest.json').read_text());src=wg['allowed_ip'].split('/')[0]
  dns=json.loads((ROOT/'docs/ssh-technitium-manifest.json').read_text());dst=dns['resolver'];observer=(ROOT/'scripts/beryl-query-observer.py').read_text()
  stage='observer_start';armed=time.monotonic()
  for vm in [205,220]:
   argv=['observer',src,'85',nonce]+(['--gateway',dst] if vm==205 else [])
   source='import sys\nsys.argv='+repr(argv)+'\n'+observer
   proc=subprocess.Popen(common.command(vm,93),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True);processes[vm]=proc
   proc.stdin.write(source);proc.stdin.close();proc.stdin=None
  stage='readiness';ready=set()
  for _ in range(3):
   for vm in [205,220]:
    if vm in ready:continue
    if processes[vm].poll() is not None:raise ValueError('observer failed')
    state=common.guest(vm,common.marker(nonce))[0]
    if state['ready']:
     if abs(time.time()-state['server_UTC_epoch'])>2:raise ValueError('clocks not aligned')
     ready.add(vm)
   if len(ready)==2:break
   if time.monotonic()-armed>15:break
   time.sleep(.2)
  if len(ready)!=2 or time.monotonic()-armed>15:raise ValueError('both witnesses not ready in time; client NOT run')
  print('observer ready / RUN GUEST TEST',flush=True)
  stage='owner_guest_client';client_started=True
  response=subprocess.run([sys.executable,str(ROOT/'scripts/beryl-client-proof.py'),'--network','guest','--challenge',nonce],capture_output=True,text=True,timeout=45)
  if response.returncode:raise ValueError('owner guest harness failed')
  client=json.loads(response.stdout);stage='observer_stop'
  for vm in [205,220]:common.guest(vm,common.marker(nonce,True))
  for vm,proc in processes.items():
   stdout,_=proc.communicate(timeout=10)
   if proc.returncode:raise ValueError('observer transport failed')
   observations=common.decode(stdout);observers[vm]=observations[-1]
   if not observers[vm].get('observer_closed'):raise ValueError('cleanup unverified')
  if not observers[205].get('gateway_interface_observed') or not observers[220].get('technitium_active'):raise ValueError('path/service witness missing')
  stage='peer_post';after=common.guest(205,common.BASE)[0]
  report={'client':client,'gateway_nonce_evidence':observers[205],'resolver_nonce_evidence':observers[220],'peer_rx_increase':after['pinned_peer_rx_bytes']-before['pinned_peer_rx_bytes'],'peer_tx_increase':after['pinned_peer_tx_bytes']-before['pinned_peer_tx_bytes'],'peer_handshake_before':before['pinned_peer_handshake_epoch'],'peer_handshake_after':after['pinned_peer_handshake_epoch'],'before_UTC_epoch':before['UTC_epoch'],'after_UTC_epoch':after['UTC_epoch'],'classification':classify(client,observers[205],observers[220],before['UTC_epoch'],after['UTC_epoch'],trusted_dns_baseline_verified=True)}
 except (Exception,KeyboardInterrupt):report={'guest_isolation_verified':False,'attempt_failed_closed':True,'failure_stage':stage,'client_started':client_started,'no_automatic_retry':True}
 finally:
  signal.alarm(0)
  # At most two*(9s stop +1s wait): main95s+cleanup20s <=115s, no daemon/retry.
  for vm,proc in processes.items():
   if observers.get(vm,{}).get('observer_closed'):continue
   try:
    if proc.poll() is None:common.guest(vm,common.marker(nonce,True),3)
    stdout,_=proc.communicate(timeout=1)
    if proc.returncode==0:observers[vm]=common.decode(stdout)[-1]
   except Exception:pass
  cleaned=all(observers.get(vm,{}).get('observer_closed',False) for vm in processes)
  report.update({'observer_cleanup_verified':cleaned,'single_guest_attempt_authorization_consumed':True,'trusted_network_retested':False,'no_automatic_retry':True})
  if not cleaned:report.update({'cleanup_unverified':True,'remote_observers_have_85s_hard_limits':True,'do_not_retry':True})
  print(json.dumps(report,separators=(',',':')),flush=True)
if __name__=='__main__':main()
