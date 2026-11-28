package main

import "testing"

func TestLoopbackURLRejectsAUserinfoBypassAndRemoteHosts(t *testing.T) {
	for _, raw := range []string{
		"http://127.0.0.1:18545@review.invalid:8545",
		"http://user@127.0.0.1:18545",
		"http://review.invalid:8545",
		"http://10.0.0.1:8545",
		"https://127.0.0.1:18545",
		"http://127.0.0.1",
		"http://127.0.0.1.review.invalid:8545",
	} {
		if loopbackURL(raw) {
			t.Errorf("accepted %q", raw)
		}
	}
	for _, raw := range []string{"http://127.0.0.1:18545", "http://127.0.0.2:18545", "http://[::1]:18545", "http://localhost:18545"} {
		if !loopbackURL(raw) {
			t.Errorf("refused %q", raw)
		}
	}
}
