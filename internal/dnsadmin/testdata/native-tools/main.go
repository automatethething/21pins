// Isolated chroot fixture ONLY. Never included in the production CLI or target bundle.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func main() {
	a := os.Args[1:]
	dir := "/var/lib/21pins/dns-admin"
	if filepath.Base(os.Args[0]) == "wg" {
		dir = "/var/lib/21pins/wg-beryl"
	}
	b, _ := os.ReadFile(dir + "/fixture.json")
	var m struct {
		Peer    string
		Other   string
		Control string
		Blocked string
	}
	json.Unmarshal(b, &m)
	switch filepath.Base(os.Args[0]) {
	case "wg":
		p := dir + "/live.json"
		b, _ := os.ReadFile(p)
		live := map[string]string{}
		json.Unmarshal(b, &live)
		if len(a) == 3 && a[0] == "show" && a[1] == "wg0" {
			switch a[2] {
			case "allowed-ips":
				for k, v := range live {
					fmt.Println(k + "\t" + v)
				}
				return
			case "latest-handshakes":
				for k := range live {
					fmt.Printf("%s\t%d\n", k, time.Now().Unix())
				}
				return
			}
		}
		if len(a) == 6 && strings.Join(a[:3], " ") == "set wg0 peer" && a[3] == m.Peer && a[4] == "allowed-ips" && a[5] == "10.66.66.5/32" {
			if _, e := os.Stat(dir + "/kill-before-live"); e == nil {
				os.Remove(dir + "/kill-before-live")
				syscall.Kill(os.Getppid(), syscall.SIGKILL)
				os.Exit(1)
			}
			live[m.Peer] = a[5]
			b, _ = json.Marshal(live)
			os.WriteFile(p, b, 0600)
			return
		}
		if len(a) == 5 && a[3] == m.Peer && a[4] == "remove" {
			delete(live, m.Peer)
			b, _ = json.Marshal(live)
			os.WriteFile(p, b, 0600)
			return
		}
	case "systemctl":
		if strings.Join(a, " ") == "show --property=DropInPaths --value dns.service" {
			return
		}
		if strings.Join(a, " ") == "is-active --quiet dns.service" {
			return
		}
	case "dig":
		if (len(a) == 8 || len(a) == 9) && a[0] == "@10.77.0.53" {
			if a[1] == m.Control {
				fmt.Println(";; ->>HEADER<<- status: NOERROR,\n" + m.Control + ". 30 IN A 10.77.0.53")
				return
			}
			if a[1] == m.Blocked {
				fmt.Println(";; ->>HEADER<<- status: NXDOMAIN,")
				return
			}
		}
	case "nft":
		if strings.Join(a, " ") == "--stateless --json list ruleset" {
			fmt.Print("fixture-pinned-rules")
			return
		}
	}
	os.Exit(1)
}
