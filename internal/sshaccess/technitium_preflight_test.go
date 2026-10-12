package sshaccess

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestTechnitiumReviewedBundle(t *testing.T) {
	raw, e := os.ReadFile("../../docs/ssh-technitium-manifest.json")
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	host, e := DNSAdminHost(digest, "pins-vm220", "fipi")
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	ca := nativeKey(t, dir, "review-ca")
	cfg := Config{Workspace: "local", CA: CA{Mode: "agent", PublicKeyFile: ca + ".pub"}, Hosts: map[string]Host{"dns-primary": host}}
	out := filepath.Join(dir, "bundle")
	if BootstrapBundle(cfg, "dns-primary", out) != nil {
		t.Fatal("review bundle")
	}
	fragment, e := os.ReadFile(filepath.Join(out, "sshd_config.fragment"))
	if e != nil {
		t.Fatal(e)
	}
	force, e := host.Roles["dns-admin"].CommandAuthority.ForcedCommand("local", "dns-primary", "dns-admin", "pins-dns-agent")
	if e != nil || !strings.Contains(string(fragment), force) {
		t.Fatal("scope")
	}
	t.Logf("review manifest SHA256=%s; force=%s", digest, force)
	if os.Getenv("PINS21_VM220_TECHNITIUM_PREFLIGHT") != "1" {
		return
	}
	// Read-only native prospective configuration validation: original/candidate stay in memory.
	params, _ := json.Marshal(map[string]string{"fragment": string(fragment), "force": force})
	script := `import json,subprocess,pathlib,pwd,hashlib,stat
p=json.loads(` + stringMustJSON(string(params)) + `)
original=pathlib.Path('/etc/ssh/sshd_config').read_text()
candidate=original+'\n'+p['fragment']
assert subprocess.run(['/usr/sbin/sshd','-t','-f','/dev/stdin'],input=candidate.encode(),capture_output=True,timeout=5).returncode==0
def effective(user,text):
 r=subprocess.run(['/usr/sbin/sshd','-T','-f','/dev/stdin','-C','user='+user+',host=localhost,addr=127.0.0.1'],input=text.encode(),capture_output=True,timeout=5);assert r.returncode==0
 return dict(line.split(' ',1) for line in r.stdout.decode().lower().splitlines() if ' ' in line)
users=[x.pw_name for x in pwd.getpwall() if x.pw_name!='pins-dns-agent']
assert all(effective(u,original)==effective(u,candidate) for u in users)
a=effective('pins-dns-agent',candidate)
assert a['forcecommand']==p['force'].lower() and a['disableforwarding']=='yes' and a['permittty']=='no' and a['authorizedkeysfile']=='none' and a['permituserenvironment']=='no' and a['acceptenv']=='21pins_unused'
for path in ['/usr/bin/sudo','/usr/bin/dig','/usr/bin/systemctl','/usr/bin/dash']:
 f=pathlib.Path(path);s=f.lstat();assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022
 for parent in f.parents:
  s=parent.lstat();assert stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022
for path in ['/etc/ssh/21pins','/usr/local/bin/21pins','/etc/21pins/dns-admin.json','/var/lib/21pins/dns-admin','/etc/sudoers.d/21pins-dns-agent','/root/21pins-bootstrap-backup']:
 assert not pathlib.Path(path).exists()
assert 'pins-dns-agent' not in [x.pw_name for x in pwd.getpwall()]
unit=pathlib.Path('/etc/systemd/system/dns.service').read_bytes()
assert hashlib.sha256(unit).hexdigest()=='5f5c27393fb97cbcc579927f49570d4a6f6610462d5d20d558c4dfa00b9c67a4'
r=subprocess.run(['systemctl','show','--property=DropInPaths','--value','dns.service'],capture_output=True,timeout=5);assert r.returncode==0 and not r.stdout.strip()
print(json.dumps({'prospective_native_ssh_valid':True,'recovery_contexts_preserved':len(users),'Technitium_unit_pin_and_no_dropins_verified':True,'required_native_tools_trusted':True,'no_role_account_or_trust_installed':True,'VM220_unchanged':True}))
`
	cmd := exec.Command("ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ForwardAgent=no", "-o", "ConnectTimeout=10", "fipi", "sudo -n /usr/sbin/qm guest exec 220 --pass-stdin 1 --timeout 80 -- /usr/bin/python3 -")
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=" + os.Getenv("HOME")}
	cmd.Stdin = strings.NewReader(script)
	result, e := cmd.Output()
	if e != nil {
		t.Fatal("native read-only preflight transport failed")
	}
	var r struct {
		Exit   int    `json:"exitcode"`
		Output string `json:"out-data"`
	}
	if json.Unmarshal(result, &r) != nil || r.Exit != 0 {
		t.Fatal("native prospective policy denied; no raw output disclosed")
	}
	var safe map[string]any
	if json.Unmarshal([]byte(r.Output), &safe) != nil || safe["VM220_unchanged"] != true {
		t.Fatal("native receipt invalid")
	}
	t.Logf("PASS: %s", r.Output)
}
func stringMustJSON(s string) string { b, _ := json.Marshal(s); return string(b) }
