package conf

import "testing"

func TestPlaintextECHDNSServer(t *testing.T) {
	cases := map[string]string{
		// plaintext DNS: warn, and name the server
		"udp://1.1.1.1":                  "udp://1.1.1.1",
		"example.com+udp://1.1.1.1":      "udp://1.1.1.1",
		"example.com+udp://1.1.1.1:5353": "udp://1.1.1.1:5353",

		// authenticated or offline sources: stay quiet
		"https://1.1.1.1/dns-query":             "",
		"example.com+https://1.1.1.1/dns-query": "",
		"h2c://1.1.1.1/dns-query":               "",
		"probe":                                 "",
		"probe://cloudflare-ech.com":            "",
		"probe://example.com@1.2.3.4:443":       "",
		"":                                      "",
		"AEX+DQBBPwAgACC4NVWryOzBZvA4AWpGdMEQ":  "", // pinned base64 config
	}
	for in, want := range cases {
		if got := plaintextECHDNSServer(in); got != want {
			t.Errorf("plaintextECHDNSServer(%q) = %q, want %q", in, got, want)
		}
	}
}
