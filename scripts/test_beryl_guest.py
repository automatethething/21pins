import importlib.util,pathlib,unittest
p=pathlib.Path(__file__).with_name('beryl-guest-synchronized-proof.py')
s=importlib.util.spec_from_file_location('guest',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class GuestChecks(unittest.TestCase):
 def test_silence_is_not_boundary_proof(self):
  public={'status':'NOERROR','transport_completed':True,'answer_present':True};negative={'status':'unverified','transport_completed':False}
  client={'owner_attested_client_network':'guest','synthetic_query_challenge':'pins-0123456789abcdef.invalid','UTC_start':'1970-01-01T00:00:15+00:00','UTC_end':'1970-01-01T00:00:25+00:00','default_public_DNS':public,'public_Internet_HTTPS_works':True,'private_DNS':{x:{k:negative for k in ['allowed_control','blocked_control','challenge']} for x in ['UDP','TCP']},'private_admin_TCP':{str(x):{'reachable':False} for x in [22,5380]},'private_resolver_advertised_as_DNS_or_failover':False}
  obs={'observer_closed':True,'source_bound_synthetic_queries':{},'observation_start_UTC_epoch':12,'observation_end_UTC_epoch':28}
  r=m.classify(client,obs,dict(obs),10,30)
  self.assertTrue(r['public_controls_pass'])
  self.assertTrue(r['private_DNS_no_completed_transport'])
  self.assertTrue(r['no_observed_protected_path_nonce'])
  self.assertFalse(r['intended_boundary_rejection_verified'])
  self.assertFalse(r['guest_isolation_verified'])
  leaking=dict(obs);leaking['source_bound_synthetic_queries']={client['synthetic_query_challenge']:{'UDP':1,'TCP':0}}
  self.assertTrue(m.classify(client,leaking,obs,10,30)['protected_path_nonce_detected'])
  late=dict(obs);late['observation_end_UTC_epoch']=20
  self.assertFalse(m.classify(client,late,obs,10,30)['observation_brackets_guest_test'])
if __name__=='__main__':unittest.main()
