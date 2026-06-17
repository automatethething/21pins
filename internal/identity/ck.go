package identity

import (
	"errors"
	"os/exec"
	"regexp"
	"strings"
)

type WhoamiRunner func() ([]byte, error)

var ckSubjectPattern = regexp.MustCompile(`ck_sub_[A-Za-z0-9_-]+`)

func ResolveSubject(explicit string, useConsentKeys bool, runner WhoamiRunner) (string, error) {
	explicit = strings.TrimSpace(explicit)
	if explicit != "" {
		return explicit, nil
	}
	if !useConsentKeys {
		return "", errors.New("--sub is required unless --ck-whoami is set")
	}
	if runner == nil {
		runner = func() ([]byte, error) {
			return exec.Command("ck", "whoami").CombinedOutput()
		}
	}
	out, err := runner()
	if err != nil {
		return "", errors.New("ConsentKeys whoami failed; run `ck login` or pass --sub explicitly")
	}
	match := ckSubjectPattern.FindString(string(out))
	if match == "" {
		return "", errors.New("ConsentKeys whoami did not include a ck_sub subject; pass --sub explicitly")
	}
	return match, nil
}
