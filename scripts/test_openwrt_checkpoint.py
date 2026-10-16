#!/usr/bin/env python3
"""No VM/network needed: exercise checkpoint durability under actual process kills."""
import importlib.util,json,os,pathlib,signal,subprocess,sys,tempfile,unittest
SCRIPT=pathlib.Path(__file__).with_name('validate-openwrt-fw4.py')
spec=importlib.util.spec_from_file_location('fw4',SCRIPT);fw4=importlib.util.module_from_spec(spec);spec.loader.exec_module(fw4)

LABSCRIPT=SCRIPT.with_name('openwrt-fw4-lab.py')
lspec=importlib.util.spec_from_file_location('lab',LABSCRIPT);lab=importlib.util.module_from_spec(lspec);lspec.loader.exec_module(lab)

class Checkpoints(unittest.TestCase):
 def test_failed_plumbing_rejects_later_operations_synchronously(self):
  from unittest.mock import patch
  with tempfile.TemporaryDirectory() as directory:
   j=self.journal(directory);local=pathlib.Path(directory);(local/'guard.json').write_text(json.dumps({'pid':os.getpid()}));(local/'guard-ready.json').write_text('{}');(local/'orchestration-failure.json').write_text('{}')
   config=dict(lab.NAMES,local_root=directory,original_context='synthetic_context')
   with patch.object(lab,'run',return_value='') as command:
    with self.assertRaises(ValueError):lab.operation('runner-build',config,j)
    command.assert_not_called()
 def test_completed_cleanup_or_coordinator_death_closes_run(self):
  for name in ['cleanup','orchestration']:
   with tempfile.TemporaryDirectory() as directory:
    j=self.journal(directory)
    if name=='cleanup':j.finish('cleanup',{'status':'PASS','reason':'fixture_clean'})
    else:fw4.atomic_json(pathlib.Path(directory)/'orchestration-failure.json',{'stage':'environment_provenance','status':'UNVERIFIED','reason':'fixture_kill'})
    with self.assertRaises(ValueError):j.start('environment_provenance')
 def test_every_declared_native_stage_has_a_handler(self):
  source=(lab.ROOT/'internal/netpolicy/openwrt_firmware_integration_test.go').read_text()
  for stage in fw4.STAGES[1:]:self.assertIn('case "'+stage+'"',source)
 def test_guard_survives_coordinator_death_and_preserves_checkpoint(self):
  with tempfile.TemporaryDirectory() as directory:
   j=self.journal(directory);j.start('environment_provenance');j.finish('environment_provenance',{'status':'PASS','reason':'fixture_verified'})
   child_code="""import importlib.util,sys,pathlib,time
s=importlib.util.spec_from_file_location('fw4',sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
j=m.Journal(sys.argv[2]);config={'local_root':sys.argv[2]}
m.atomic_json(pathlib.Path(sys.argv[2])/'leases'/'1.json',{'pid':99999999,'deadline':time.monotonic()+1,'phase':'running','stage':'logical_runtime_binding'})
m.cleanup_owned=lambda c,j:j.finish('cleanup',{'status':'PASS','reason':'fixture_cleanup_only'})
m.guard(config,j)
"""
   result=subprocess.run([sys.executable,'-c',child_code,str(SCRIPT),directory],capture_output=True,timeout=3);self.assertEqual(result.returncode,0)
   self.assertEqual(j.state()['last_completed'],'environment_provenance');self.assertTrue((pathlib.Path(directory)/'guard-stopped.json').exists())
 def test_empty_preboot_review_cannot_authorize_boot(self):
  with tempfile.TemporaryDirectory() as directory:
   j=self.journal(directory);(pathlib.Path(directory)/'preboot-review.json').write_text(json.dumps({'approved':True,'files':{}}))
   with self.assertRaises(ValueError):lab.check_review(j)
 def test_untracked_product_source_is_rejected(self):
  path=lab.ROOT/'internal/netpolicy/fw4_untracked_canary.go';self.assertFalse(path.exists())
  try:
   path.write_text('package netpolicy\\n')
   with self.assertRaises(ValueError):lab.freeze()
  finally:path.unlink(missing_ok=True)
 def test_guard_has_an_explicit_start_and_required_review_set(self):
  self.assertTrue(hasattr(lab,'start_guard'),'cleanup guard is never launched')
  self.assertEqual(len(lab.REVIEW_FILES),5)

 def journal(self,path):
  self.assertTrue(hasattr(fw4,'Journal'),'Durable host Journal is missing')
  return fw4.Journal(path)
 def test_sigkill_preserves_last_completed_and_exact_interrupted_stage(self):
  with tempfile.TemporaryDirectory() as directory:
   self.journal(directory)
   code="""import importlib.util,sys,os,signal
s=importlib.util.spec_from_file_location('fw4',sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
j=m.Journal(sys.argv[2]);j.start('environment_provenance');j.finish('environment_provenance',{'status':'PASS','reason':'fixture_verified'})
j.start('logical_runtime_binding');os.kill(os.getpid(),signal.SIGKILL)
"""
   child=subprocess.run([sys.executable,'-c',code,str(SCRIPT),directory],capture_output=True,timeout=5)
   self.assertEqual(child.returncode,-signal.SIGKILL)
   state=self.journal(directory).state();self.assertEqual(state['last_completed'],'environment_provenance');self.assertEqual(state['interrupted_stage'],'logical_runtime_binding')
 def test_exit137_and_cleanup_cannot_erase_completed_gate(self):
  with tempfile.TemporaryDirectory() as directory:
   j=self.journal(directory);j.start('environment_provenance');j.finish('environment_provenance',{'status':'PASS','reason':'fixture_verified'});j.start('logical_runtime_binding');j.finish('logical_runtime_binding',{'status':'UNVERIFIED','reason':'child_exit_137'});j.finish('cleanup',{'status':'PASS','reason':'zero_owned_resources'})
   self.assertEqual(j.state()['last_completed'],'environment_provenance');self.assertEqual(j.state()['failed_stage'],'logical_runtime_binding')
   with self.assertRaises(ValueError):j.start('stored_runtime_separation')
 def test_boot_token_consumed_exactly_once(self):
  with tempfile.TemporaryDirectory() as directory:
   j=self.journal(directory);j.reserve_boot()
   with self.assertRaises(ValueError):self.journal(directory).reserve_boot()
 def test_existing_result_is_immutable_and_uncommitted_file_is_not_a_pass(self):
  with tempfile.TemporaryDirectory() as directory:
   j=self.journal(directory);j.start('environment_provenance');j.finish('environment_provenance',{'status':'PASS','reason':'fixture_verified'})
   before={p.name:p.read_bytes() for p in pathlib.Path(directory).glob('*.json')}
   with self.assertRaises(ValueError):j.finish('environment_provenance',{'status':'UNVERIFIED','reason':'overwrite'})
   (pathlib.Path(directory)/'.incomplete.tmp').write_text('{')
   self.assertEqual({p.name:p.read_bytes() for p in pathlib.Path(directory).glob('*.json')},before)
   self.assertEqual(j.state()['last_completed'],'environment_provenance')
 def test_timeout_and_controller_failure_preserve_checkpoint(self):
  with tempfile.TemporaryDirectory() as directory:
   j=self.journal(directory);j.start('environment_provenance');j.finish('environment_provenance',{'status':'PASS','reason':'fixture_verified'})
   self.assertTrue(hasattr(fw4,'bounded_stage'),'Bounded stage coordinator is missing')
   result=fw4.bounded_stage(j,'logical_runtime_binding',[sys.executable,'-c','import time;time.sleep(2)'],timeout=.1)
   self.assertEqual(result['status'],'UNVERIFIED');self.assertEqual(result['reason'],'outer_deadline')
   self.assertEqual(self.journal(directory).state()['last_completed'],'environment_provenance')
 def test_actual_controller_sigkill_is_durable_and_does_not_advance(self):
  with tempfile.TemporaryDirectory() as directory:
   j=self.journal(directory);j.start('environment_provenance');j.finish('environment_provenance',{'status':'PASS','reason':'fixture_verified'})
   result=fw4.bounded_stage(j,'logical_runtime_binding',[sys.executable,'-c','import os,signal;os.kill(os.getpid(),signal.SIGKILL)'],timeout=2)
   self.assertEqual(result['status'],'UNVERIFIED');self.assertEqual(result['reason'],'external_exit_9');self.assertEqual(j.state()['failed_stage'],'logical_runtime_binding')
 def test_success_needs_exact_safe_stage_frame_and_exit_zero(self):
  for response in [{'stage':'command','test_exit':0,'observations':[]},{'stage':'command','test_exit':137,'observations':[{'stage':'environment_provenance','status':'PASS','reason':'fake_exit'}]}]:
   with tempfile.TemporaryDirectory() as directory:
    result=fw4.bounded_stage(self.journal(directory),'environment_provenance',[sys.executable,'-c','print('+repr(json.dumps(response))+')'],timeout=2)
    self.assertEqual(result['status'],'UNVERIFIED')
 def test_cleanup_writer_is_serialized(self):
  self.assertTrue(hasattr(fw4,'cleanup_lock'),'Independent cleanup writer lock is missing')
  with tempfile.TemporaryDirectory() as directory:
   with fw4.cleanup_lock(self.journal(directory),timeout=.2):
    with self.assertRaises(TimeoutError):
     with fw4.cleanup_lock(self.journal(directory),timeout=.05):pass
 def test_timestamps_are_not_mistaken_for_ipv6_and_ipv6_is_rejected(self):
  self.assertEqual(fw4.sanitize({'stage':'logical_runtime_binding','status':'PASS','started_utc':'2026-10-16T01:02:03Z'})['status'],'PASS')
  with self.assertRaises(ValueError):fw4.sanitize({'stage':'logical_runtime_binding','status':'PASS','reason':str(__import__('ipaddress').IPv6Address(1))})
 def test_privacy_rejects_nested_sensitive_fields_and_address_strings(self):
  for value in [{'stage':'logical_runtime_binding','status':'PASS','observations':{'password':'synthetic'}},{'stage':'logical_runtime_binding','status':'PASS','reason':str(__import__('ipaddress').IPv4Address(bytes([192,0,2,1])))}]:
   with self.assertRaises(ValueError):fw4.sanitize(value)

if __name__=='__main__':unittest.main()
