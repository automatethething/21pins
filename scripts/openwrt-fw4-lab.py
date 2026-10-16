#!/usr/bin/env python3
"""Single-attempt lab plumbing. No firmware boot except the explicit one-use boot mode."""
import gzip,hashlib,importlib.util,json,os,pathlib,re,shutil,subprocess,sys,tempfile,time,urllib.request,zlib
ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('fw4',ROOT/'scripts/validate-openwrt-fw4.py');fw4=importlib.util.module_from_spec(spec);spec.loader.exec_module(fw4)
NAMES={'owned_profile':'21pins-fw4-retry','context':'colima-21pins-fw4-retry','container':'21pins-fw4-retry-lab'}
IMAGE='openwrt-24.10.4-x86-64-generic-ext4-combined.img.gz'
BASE='https://downloads.openwrt.org/releases/24.10.4/'
PREPARED_LOCAL=None
REVIEW_FILES={'scripts/validate-openwrt-fw4.py','scripts/openwrt-fw4-lab.py','scripts/test_openwrt_checkpoint.py','internal/netpolicy/openwrt_firmware_integration_test.go','docs/superpowers/plans/2026-10-16-openwrt-fw4-checkpointed-retry.md'}
QA_FILES=REVIEW_FILES-{'docs/superpowers/plans/2026-10-16-openwrt-fw4-checkpointed-retry.md'}
def require(ok,reason):
 if not ok:raise ValueError(reason)
def run(args,timeout=100):
 result=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
 if result.returncode:raise RuntimeError('bounded_lab_operation_failed')
 return result.stdout

def freeze():
 files=run(['git','-C',str(ROOT),'ls-tree','-r','--name-only','214aad5','--','internal','cmd','npm','scripts','go.mod','go.sum'],10).splitlines()
 actual=set()
 for directory in ['internal','cmd','npm','scripts']:
  for path in (ROOT/directory).rglob('*'):
   if path.is_symlink():raise ValueError('symlink_build_input')
   if path.is_file() and not ('__pycache__' in path.parts and path.suffix=='.pyc'):actual.add(path.relative_to(ROOT).as_posix())
 require(not actual-set(files)-QA_FILES,'untracked_product_input')
 require(not any(p.name.endswith('.go') or p.name in ['go.work','go.work.sum'] for p in ROOT.iterdir() if p.is_file() and p.name not in files),'unexpected_module_input')
 for name in files:
  path=ROOT/name;require(not path.is_symlink() and path.is_file(),'missing_or_symlink_product_input')
  baseline=subprocess.check_output(['git','-C',str(ROOT),'show','214aad5:'+name],timeout=5)
  if path.read_bytes()!=baseline:raise ValueError('production_source_changed')

def versions_script(expected):
 rows=[]
 for name,version in expected.items():
  if not re.fullmatch(r'[a-zA-Z0-9+_.-]+',name) or not re.fullmatch(r'[a-zA-Z0-9~+_./-]+',version):raise ValueError('unsafe package metadata')
  rows.append('v="$(opkg status '+name+' | awk \'/^Version:/{print $2}\')"; [ "$v" = "'+version+'" ]; json_add_string '+name+' "$v"')
 return '\n'.join(rows)

def environment_script(previous):
 return '''set -e
/etc/init.d/dropbear stop >/dev/null 2>&1 || true
/etc/init.d/dropbear disable >/dev/null 2>&1 || true
mkdir -p /mnt/payload
mount -o ro /dev/vdb /mnt/payload
[ "$(uname -r)" = 6.6.110 ]
[ "$(awk -F\"'\" '/^DISTRIB_RELEASE=/{print $2}' /etc/openwrt_release)" = 24.10.4 ]
[ "$(awk -F\"'\" '/^DISTRIB_REVISION=/{print $2}' /etc/openwrt_release)" = r28959-29397011cc ]
mkdir -p /tmp/pins-original-feeds /tmp/pins-opkg-lists
for f in /etc/opkg/distfeeds.conf /etc/opkg/customfeeds.conf;do if [ -f "$f" ];then mv "$f" /tmp/pins-original-feeds/;fi;done
printf '%s\\n' 'dest root /' 'dest ram /tmp' 'lists_dir ext /tmp/pins-opkg-lists' 'option check_signature' 'arch all 1' 'arch noarch 1' 'arch x86_64 10' 'src/gz pins_core file:///mnt/payload/feeds/core' 'src/gz pins_base file:///mnt/payload/feeds/base' 'src/gz pins_kmods file:///mnt/payload/feeds/kmods' > /tmp/pins-opkg.conf
opkg -f /tmp/pins-opkg.conf update >/tmp/pins-update.log 2>&1
[ "$(grep -c 'Signature check passed' /tmp/pins-update.log)" = 3 ]
opkg -f /tmp/pins-opkg.conf install ip-full kmod-dummy kmod-veth >/tmp/pins-install.log 2>&1
modprobe dummy
modprobe veth
ip -j -4 rule show >/dev/null
nft -j list tables >/dev/null
. /usr/share/libubox/jshn.sh
json_init;json_add_string stage environment_provenance;json_add_string status PASS;json_add_string reason authenticated_pinned_environment;json_add_string source_commit 214aad5
json_add_string release 24.10.4;json_add_string revision r28959-29397011cc;json_add_string kernel 6.6.110;json_add_int signature_checks 3
json_add_object packages
'''+versions_script(previous['native_package_versions'])+'''
json_close_object
json_add_object digests
for p in fw4 nft ip ubus ubusd uci;do f="$(command -v "$p")";v="$(sha256sum "$f" | awk '{print $1}')";json_add_string "$p" "$v";done
json_close_object
printf '\\nPINS_JSON:';json_dump;printf '\\n'
'''

def stage_script(stage):
 return '''set +e
GOMAXPROCS=1 GOMEMLIMIT=128MiB PINS21_REAL_FW4_TEST=1 PINS21_FW4_STAGE='''+stage+''' /mnt/payload/fw4-validation.test -test.run '^TestControlledRealFw4Validation$' -test.v -test.timeout=75s
status=$?
. /usr/share/libubox/jshn.sh
json_init;json_add_string stage resource_sample;json_add_string status OBSERVED
json_add_object observations
json_add_int guest_kernel_oom_events "$(dmesg | grep -c 'Out of memory: Killed process')"
json_add_int guest_available_kib "$(awk '/^MemAvailable:/{print $2}' /proc/meminfo)"
json_close_object
printf '\\nPINS_JSON:';json_dump;printf '\\n'
exit "$status"
'''

def artifacts(journal):
 global PREPARED_LOCAL
 freeze();cache=pathlib.Path.home()/'.cache';cache.mkdir(exist_ok=True);local=pathlib.Path(tempfile.mkdtemp(prefix='21pins-fw4-retry-',dir=cache));local.chmod(0o700);PREPARED_LOCAL=local;(local/'owned-lab-marker').write_text('214aad5')
 original=run(['docker','context','show'],10).strip();config=dict(NAMES,local_root=str(local),original_context=original)
 fw4.atomic_json(local/'config.json',config)
 previous=json.loads((ROOT/'docs/superpowers/reviews/2026-10-15-openwrt-real-fw4-evidence.json').read_text())
 staging=local/'staging';staging.mkdir(mode=0o700);payload=staging/'payload';payload.mkdir(mode=0o700);commands=staging/'commands';commands.mkdir(mode=0o700)
 opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
 def fetch(url,maximum=24<<20):
  with opener.open(url,timeout=25) as response:data=response.read(maximum+1)
  if len(data)>maximum:raise ValueError('artifact_exceeds_bound')
  return data
 def digest(data):return hashlib.sha256(data).hexdigest()
 target=BASE+'targets/x86/64/';sums=fetch(target+'sha256sums',1<<20).decode();expected=previous['image']['compressed_sha256'];require(any(line.split()[0]==expected and line.split()[-1].lstrip('*')==IMAGE for line in sums.splitlines()),'official_checksum_mismatch')
 compressed=fetch(target+IMAGE);require(digest(compressed)==expected,'image_digest_mismatch')
 decoder=zlib.decompressobj(31);image=decoder.decompress(compressed,512<<20)+decoder.flush();require(decoder.eof and digest(image)==previous['image']['base_sha256'],'raw_image_digest_mismatch')
 (staging/'base.img').write_bytes(image);(staging/'base.img').chmod(0o444)
 manifest=fetch(target+'openwrt-24.10.4-x86-64.manifest',1<<20);require(digest(manifest)==previous['image']['base_manifest_sha256'],'manifest_digest_mismatch')
 urls={'core':target+'packages/','base':BASE+'packages/x86_64/base/','kmods':target+'kmods/6.6.110-1-484466e2719a743506c36b4bb2103582/'}
 for name,url in urls.items():
  directory=payload/'feeds'/name;directory.mkdir(parents=True,mode=0o700);packed=fetch(url+'Packages.gz');signature=fetch(url+'Packages.sig',65536);plain=gzip.decompress(packed)
  require(digest(plain)==previous['feed_index_digests'][name]['packages_sha256'] and digest(signature)==previous['feed_index_digests'][name]['signature_sha256'],'signed_feed_tuple_changed')
  for file,data in [('Packages.gz',packed),('Packages',plain),('Packages.sig',signature)]:(directory/file).write_bytes(data)
 for name,p in previous['authenticated_package_payloads'].items():
  data=fetch(urls[p['feed']]+p['file']);require(digest(data)==p['sha256'],'payload_digest_mismatch');(payload/'feeds'/p['feed']/p['file']).write_bytes(data)
 env=dict(os.environ,GOOS='linux',GOARCH='amd64',CGO_ENABLED='0',GOWORK='off',GOFLAGS='',GOENV='off',GOTOOLCHAIN='local');subprocess.run(['go','test','-c','-tags=openwrt_firmware_integration','-o',str(payload/'fw4-validation.test'),'./internal/netpolicy'],cwd=ROOT,env=env,capture_output=True,check=True,timeout=60)
 shutil.copyfile(ROOT/'scripts/validate-openwrt-fw4.py',staging/'controller.py')
 (commands/'environment_provenance.sh').write_text(environment_script(previous))
 for stage in fw4.STAGES[1:]:(commands/(stage+'.sh')).write_text(stage_script(stage))
 (local/'Dockerfile').write_text('FROM debian:bookworm-slim\nRUN apt-get update -qq && apt-get install -y --no-install-recommends qemu-system-x86 qemu-utils python3 e2fsprogs ca-certificates && rm -rf /var/lib/apt/lists/*\nWORKDIR /lab\n')
 (local/'build-context').mkdir(mode=0o700)
 fw4.atomic_json(journal.root/'artifact-provenance.json',{'image_sha256':expected,'raw_image_sha256':digest(image),'binary_sha256':digest((payload/'fw4-validation.test').read_bytes()),'source_commit':'214aad5','driver_sha256':digest((ROOT/'internal/netpolicy/openwrt_firmware_integration_test.go').read_bytes()),'package_digests_match_prior_authenticated_tuple':True,'feed_digests_match_prior_authenticated_tuple':True})
 print(json.dumps({'artifacts_prepared':True,'config_path':str(local/'config.json'),'guest_boots':0}))

def check_review(journal):
 review=json.loads((journal.root/'preboot-review.json').read_text());require(review['approved'] is True,'review_not_approved')
 require(isinstance(review.get('files'),dict) and set(review['files'])==REVIEW_FILES,'incomplete_review_file_set')
 for file,sha in review['files'].items():
  require(isinstance(sha,str) and re.fullmatch(r'[0-9a-f]{64}',sha) is not None,'invalid_review_digest')
  require(hashlib.sha256((ROOT/file).read_bytes()).hexdigest()==sha,'harness_changed_after_review')
 freeze()

def start_guard(config,journal):
 check_review(journal);local=pathlib.Path(config['local_root'])
 require(not (local/'guard.json').exists(),'guard_already_started')
 require(not (pathlib.Path.home()/'.colima'/config['owned_profile']).exists(),'refuse_existing_profile')
 fw4.lease(config,journal,'idle')
 child=subprocess.Popen([sys.executable,str(ROOT/'scripts/validate-openwrt-fw4.py'),'guard','--config',str(local/'config.json'),'--journal',str(journal.root)],cwd=ROOT,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
 fw4.atomic_json(local/'guard.json',{'pid':child.pid})
 deadline=time.monotonic()+5
 while not (journal.root/'guard-ready.json').exists() and time.monotonic()<deadline and child.poll() is None:time.sleep(.05)
 require((journal.root/'guard-ready.json').exists() and child.poll() is None,'guard_failed_to_start')
 fw4.atomic_json(journal.root/'guard-started.json',{'mode':'cleanup_only','boot_authority':False,'started_utc':fw4.utc()})
 print(json.dumps({'cleanup_guard_started':True,'boot_authority':False}))

def operation(mode,config,journal):
 require(not (journal.root/'orchestration-failure.json').exists() and not journal.path('cleanup','result').exists(),'run_closed')
 state=journal.state();require(not state['failed_stage'] and not state['interrupted_stage'],'run_failed_or_interrupted')
 if mode=='guard-start':return start_guard(config,journal)
 local=pathlib.Path(config['local_root']);require((journal.root/'guard-ready.json').exists() and not (journal.root/'guard-stopped.json').exists(),'guard_not_active');os.kill(json.loads((local/'guard.json').read_text())['pid'],0)
 if mode=='boot':
  check_review(journal);local=pathlib.Path(config['local_root']);review=json.loads((journal.root/'preboot-review.json').read_text());artifacts=json.loads((journal.root/'artifact-provenance.json').read_text())
  require(artifacts['driver_sha256']==review['files']['internal/netpolicy/openwrt_firmware_integration_test.go'],'stale_built_driver')
  require(hashlib.sha256((local/'staging/controller.py').read_bytes()).hexdigest()==review['files']['scripts/validate-openwrt-fw4.py'],'stale_staged_controller')
  require(hashlib.sha256((local/'staging/payload/fw4-validation.test').read_bytes()).hexdigest()==artifacts['binary_sha256'],'staged_binary_changed')
  require(not (journal.root/'guard-stopped.json').exists(),'guard_not_active');os.kill(json.loads((local/'guard.json').read_text())['pid'],0)
 fw4.lease(config,journal,'running',mode);local=pathlib.Path(config['local_root']);base=['docker','--context',config['context']]
 try:
  if mode=='runner-start':
   require(not (pathlib.Path.home()/'.colima'/config['owned_profile']).exists(),'refuse_existing_profile')
   run(['colima','start','--profile',config['owned_profile'],'--activate=false','--cpus','2','--memory','3','--disk','12'],100)
  elif mode=='runner-build':run(base+['build','-t','21pins-fw4-retry:local','-f',str(local/'Dockerfile'),str(local/'build-context')],100)
  elif mode=='container-stage':
   run(base+['create','--name',config['container'],'--network','none','21pins-fw4-retry:local','sh','-c','truncate -s 96M /lab/payload.img && mkfs.ext4 -q -d /lab/payload /lab/payload.img && exec python3 /lab/controller.py serve'],10)
   run(base+['cp',str(local/'staging')+'/.',config['container']+':/lab'],40)
  elif mode=='boot':
   journal.reserve_boot();run(base+['start',config['container']],10)
   run(base+['exec',config['container'],'python3','-c','import pathlib,time;end=time.monotonic()+10\nwhile not pathlib.Path("/lab/control.sock").exists() and time.monotonic()<end:time.sleep(.1)\nassert pathlib.Path("/lab/control.sock").exists()'],12)
   response=json.loads(run(base+['exec',config['container'],'python3','/lab/controller.py','rpc','--action','boot'],100));require(response.get('status')=='ready','boot_not_ready')
   fw4.atomic_json(journal.root/'boot-ready.json',fw4.sanitize(response))
  else:raise ValueError('unknown lab operation')
  fw4.lease(config,journal,'idle',mode);print(json.dumps({'operation':mode,'status':'PASS'}))
 except BaseException:
  if not (journal.root/'orchestration-failure.json').exists():fw4.atomic_json(journal.root/'orchestration-failure.json',{'stage':mode,'status':'UNVERIFIED','reason':'lab_operation_failed'})
  raise

if __name__=='__main__':
 import argparse
 parser=argparse.ArgumentParser();parser.add_argument('mode',choices=['artifacts','guard-start','runner-start','runner-build','container-stage','boot']);parser.add_argument('--config');parser.add_argument('--journal',required=True);a=parser.parse_args();journal=fw4.Journal(a.journal)
 try:
  if a.mode=='artifacts':artifacts(journal)
  else:operation(a.mode,json.loads(pathlib.Path(a.config).read_text()),journal)
 except Exception as error:
  if a.mode=='artifacts' and PREPARED_LOCAL is not None:shutil.rmtree(PREPARED_LOCAL,ignore_errors=True)
  print(json.dumps({'status':'UNVERIFIED','failure_class':type(error).__name__,'raw_diagnostics':'withheld'}));raise SystemExit(1)
