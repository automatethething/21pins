import importlib.util,pathlib,unittest
p=pathlib.Path(__file__).with_name('beryl-guest-synchronized-proof.py')
s=importlib.util.spec_from_file_location('guest',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class GuestChecks(unittest.TestCase):
 def test_silence_is_not_boundary_proof(self):
  public={'status':'NOERROR','transport_completed':True,'answer_present':True};negative={'status':'unverified','transport_completed':False}
  client={'owner_attested_client_network':'guest','synthetic_query_challenge':'pins-0123456789abcdef.invalid','UTC_start':'1970-01-01T00:00:15+00:00','UTC_end':'1970-01-01T00:00:25+00:00','default_public_DNS':public,'default_synthetic_query':{'status':'NXDOMAIN','transport_completed':True},'public_Internet_HTTPS_works':True,'private_DNS':{x:{k:negative for k in ['allowed_control','blocked_control','challenge']} for x in ['UDP','TCP']},'private_admin_TCP':{str(x):{'reachable':False} for x in [22,5380]},'private_resolver_advertised_as_DNS_or_failover':False}
  obs={'observer_closed':True,'source_bound_synthetic_queries':{},'observation_start_UTC_epoch':12,'observation_end_UTC_epoch':28}
  r=m.classify(client,obs,dict(obs),10,30,trusted_dns_baseline_verified=True)
  self.assertTrue(r['public_controls_pass'])
  self.assertTrue(r['private_DNS_no_completed_transport'])
  self.assertTrue(r['no_observed_protected_path_nonce'])
  self.assertFalse(r['intended_boundary_rejection_verified'])
  self.assertFalse(r['guest_isolation_verified'])
  self.assertTrue(r['public_not_protected_DNS_behavior_verified'])
  self.assertTrue(r['trusted_DNS_baseline_verified'])
  self.assertNotIn('protected_admin_trusted_baselines_available',r)
  self.assertEqual(r['reason'],'intended_boundary_rejection_not_proven')
  witness={'independently_validated':True,'guest_to_protected_DNS_path':True,'test_specific_match':True,'UDP_TCP_scope_verified':True,'applicable_policy_verified':True,'action':'reject','rule_identity':'fixture-rule'}
  verified=m.classify(client,obs,dict(obs),10,30,trusted_dns_baseline_verified=True,boundary_witness=witness)
  self.assertTrue(verified['guest_isolation_verified'])
  partial=dict(witness);partial['UDP_TCP_scope_verified']=False
  self.assertFalse(m.classify(client,obs,dict(obs),10,30,trusted_dns_baseline_verified=True,boundary_witness=partial)['guest_isolation_verified'])
  client['boundary_witness']=witness;client['intended_boundary_rejection_verified']=True
  self.assertFalse(m.classify(client,obs,dict(obs),10,30,trusted_dns_baseline_verified=True)['guest_isolation_verified'])
  self.assertFalse(m.classify(client,obs,dict(obs),10,30,trusted_dns_baseline_verified=True,boundary_witness=True)['guest_isolation_verified'])
  policy={'kind':'active_source_scoped_routing','rule_identity':'fixture-LAN-only-policy'}
  for key in ['independently_validated','applicable_policy_verified','guest_to_protected_DNS_path','UDP_TCP_scope_verified','active_policy','trusted_source_only','guest_equivalent_policy_absent','guest_leak_blackhole_enabled','protected_destination_binding_verified','marked_table_uses_private_tunnel','killswitch_enabled']:policy[key]=True
  self.assertTrue(m.classify(client,obs,dict(obs),10,30,trusted_dns_baseline_verified=True,boundary_witness=policy)['guest_isolation_verified'])
  for key in ['active_policy','protected_destination_binding_verified','guest_equivalent_policy_absent','guest_leak_blackhole_enabled']:
   broken=dict(policy);broken[key]=False
   self.assertFalse(m.classify(client,obs,dict(obs),10,30,trusted_dns_baseline_verified=True,boundary_witness=broken)['guest_isolation_verified'])
  witness['test_specific_match']=False
  self.assertFalse(m.classify(client,obs,dict(obs),10,30,trusted_dns_baseline_verified=True,boundary_witness=witness)['guest_isolation_verified'])
  self.assertFalse(m.classify(client,obs,dict(obs),10,30)['guest_isolation_verified'])
  leaking=dict(obs);leaking['source_bound_synthetic_queries']={client['synthetic_query_challenge']:{'UDP':1,'TCP':0}}
  self.assertTrue(m.classify(client,leaking,obs,10,30)['protected_path_nonce_detected'])
  late=dict(obs);late['observation_end_UTC_epoch']=20
  self.assertFalse(m.classify(client,late,obs,10,30)['observation_brackets_guest_test'])
if __name__=='__main__':unittest.main()
