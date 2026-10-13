import importlib.util,pathlib,struct,unittest
ROOT=pathlib.Path(__file__).parent
def load(name,file):
 s=importlib.util.spec_from_file_location(name,ROOT/file);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
client=load('client','beryl-client-proof.py')
class Checks(unittest.TestCase):
 def test_wire_policy_not_nxdomain_alone(self):
  question=b'\x02ad\x0bdoubleclick\x03net\0'+struct.pack('!HH',1,1)
  base=struct.pack('!HHHHHH',42,0x8183,1,0,0,1)+question
  opt=b'\0'+struct.pack('!HHIH',41,1232,0,6)+struct.pack('!HHH',15,2,15)
  self.assertTrue(client.wire_result(base+opt,42,'ad.doubleclick.net')['explicit_block_or_filter_EDE'])
  self.assertFalse(client.wire_result(struct.pack('!HHHHHH',42,0x8183,1,0,0,0)+question,42,'ad.doubleclick.net')['explicit_block_or_filter_EDE'])
  with self.assertRaises(ValueError):client.wire_result(base+opt,43,'ad.doubleclick.net')
  with self.assertRaises(ValueError):client.wire_result(base+opt[:-1],42,'ad.doubleclick.net')
  with self.assertRaises(ValueError):client.wire_result(base+opt,42,'example.com')
 def test_nonce_and_evidence_gate(self):
  sync=load('sync','beryl-synchronized-proof.py')
  self.assertFalse(sync.correlated({}, {}, {}, {})['trusted_network_E2E_verified'])
  nonce='pins-0123456789abcdef.invalid'
  b={'pinned_source_mapping_verified':True,'UTC_epoch':10,'pinned_peer_rx_bytes':1,'pinned_peer_tx_bytes':1,'pinned_peer_handshake_epoch':9}
  p={'pinned_source_mapping_verified':True,'UTC_epoch':30,'pinned_peer_rx_bytes':20,'pinned_peer_tx_bytes':40,'pinned_peer_handshake_epoch':21}
  ok={'transport_completed':True,'status':'NOERROR','answer_present':True};blocked={'transport_completed':True,'status':'NXDOMAIN','explicit_block_or_filter_EDE':True}
  c={'owner_attested_client_network':'trusted','synthetic_query_challenge':nonce,'UTC_start':'1970-01-01T00:00:15+00:00','UTC_end':'1970-01-01T00:00:25+00:00','default_public_DNS':ok,'public_Internet_HTTPS_works':True,'private_DNS':{x:{'allowed_control':ok,'blocked_control':blocked,'challenge':{'transport_completed':True,'status':'NXDOMAIN'}} for x in ['UDP','TCP']}}
  o={'observer_closed':True,'technitium_active':True,'source_bound_synthetic_queries':{nonce:{'UDP':1,'TCP':1}},'query_UTC_epochs':{nonce:[18,22]}}
  self.assertTrue(sync.correlated(b,p,c,o)['trusted_network_E2E_verified'])
  c['private_DNS']['UDP']['blocked_control']['explicit_block_or_filter_EDE']=False
  self.assertFalse(sync.correlated(b,p,c,o)['trusted_network_E2E_verified'])
  c['private_DNS']['UDP']['blocked_control']['explicit_block_or_filter_EDE']=True
  o['query_UTC_epochs'][nonce]=[35,36]
  self.assertFalse(sync.correlated(b,p,c,o)['trusted_network_E2E_verified'])
if __name__=='__main__':unittest.main()
