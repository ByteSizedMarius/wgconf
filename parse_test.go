package wgconf

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const testIface = `[Interface]
# RoutingMode = full
# IPv4Interface = eth0
PrivateKey = cHJpdmF0ZQ==
Address = 10.0.0.1/24
ListenPort = 51820
`

func testKey(seed byte) string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = seed + byte(i)
	}
	return base64.StdEncoding.EncodeToString(b)
}

var (
	keyPhone  = testKey(0x01)
	keyLaptop = testKey(0x21)
	keyTablet = testKey(0x41)

	phoneSection = "[Peer]\nPublicKey = " + keyPhone + "\nAllowedIPs = 10.0.0.2/32\n"
	phonePeer    = Peer{PublicKey: keyPhone, AllowedIPs: []string{"10.0.0.2/32"}}

	// nulValid is the content each NUL case inserts its byte into.
	nulValid = passthroughIface + "\n# iface note\n\n# phone\n" + phoneSection + "# peer note\n"
)

func writeAndRead(t *testing.T, iface string, peers []Peer) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "wg0.conf")
	if err := WritePeers(path, iface, peers); err != nil {
		t.Fatalf("WritePeers: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read written config: %v", err)
	}
	return string(data)
}

func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "wg0.conf")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// assertStableRoundTrip fails unless a second parse and write of path change nothing.
func assertStableRoundTrip(t *testing.T, path string) string {
	t.Helper()
	iface1, peers1, err := ParsePeers(path)
	if err != nil {
		t.Fatalf("first ParsePeers: %v", err)
	}
	if err := WritePeers(path, iface1, peers1); err != nil {
		t.Fatalf("first WritePeers: %v", err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read first write: %v", err)
	}
	iface2, peers2, err := ParsePeers(path)
	if err != nil {
		t.Fatalf("second ParsePeers: %v", err)
	}
	if iface2 != iface1 || !reflect.DeepEqual(peers2, peers1) {
		t.Errorf("second parse gave %q and %+v, first gave %q and %+v", iface2, peers2, iface1, peers1)
	}
	if err := WritePeers(path, iface2, peers2); err != nil {
		t.Fatalf("second WritePeers: %v", err)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read second write: %v", err)
	}
	if string(second) != string(first) {
		t.Errorf("second write differs:\n%s\nfirst write:\n%s", second, first)
	}
	return string(first)
}

func assertHeaderSpelling(t *testing.T, ifaceHead, peerHead string) {
	t.Helper()
	input := ifaceHead + "\nPrivateKey = k\n\n" + peerHead + "\nPublicKey = " + keyPhone + "\nAllowedIPs = 10.0.0.2/32"
	gotIface, peers, err := ParsePeersFromString(input)
	if err != nil {
		t.Fatalf("ParsePeersFromString: %v", err)
	}
	if len(peers) != 1 || peers[0].PublicKey != keyPhone || !reflect.DeepEqual(peers[0].AllowedIPs, []string{"10.0.0.2/32"}) {
		t.Errorf("peers = %+v, want one peer with the section's key and AllowedIPs", peers)
	}
	if want := ifaceHead + "\nPrivateKey = k"; gotIface != want {
		t.Errorf("interface block = %q, want %q", gotIface, want)
	}
}

// assertNULRejected requires both parsers to reject content whole while the same text without its NUL parses.
func assertNULRejected(t *testing.T, content string) {
	t.Helper()
	control := strings.ReplaceAll(content, "\x00", "")
	if control != nulValid {
		t.Fatalf("case differs from the valid content by more than its NUL")
	}
	iface, peers, err := ParsePeersFromString(control)
	if err != nil || len(peers) != 1 || peers[0].Name != "phone" {
		t.Fatalf("control: ParsePeersFromString = %q, %+v, %v, want one peer named phone", iface, peers, err)
	}

	iface, peers, err = ParsePeersFromString(content)
	if err == nil || iface != "" || peers != nil {
		t.Errorf("ParsePeersFromString = %q, %q, %v, want \"\", nil and an error", iface, peers, err)
	}

	iface, peers, err = ParsePeers(writeTempConfig(t, content))
	if err == nil || iface != "" || peers != nil {
		t.Errorf("ParsePeers = %q, %q, %v, want \"\", nil and an error", iface, peers, err)
	}
}

func TestParseWriteRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		input string
		check func(t *testing.T, iface string, peers []Peer, out string)
	}{
		{
			name:  "named first peer",
			input: testIface + "\n# phone\n[Peer]\nPublicKey = " + keyPhone + "\nAllowedIPs = 10.0.0.2/32\n",
			check: func(t *testing.T, iface string, peers []Peer, out string) {
				want := []Peer{{Name: "phone", PublicKey: keyPhone, AllowedIPs: []string{"10.0.0.2/32"}}}
				if !reflect.DeepEqual(peers, want) {
					t.Errorf("peers = %+v, want %+v", peers, want)
				}
				if iface != strings.TrimSuffix(testIface, "\n") {
					t.Errorf("interface block = %q", iface)
				}
			},
		},
		{
			name:  "unnamed first peer",
			input: testIface + "\n[Peer]\nPublicKey = " + keyPhone + "\nAllowedIPs = 10.0.0.2/32\n",
			check: func(t *testing.T, iface string, peers []Peer, out string) {
				if len(peers) != 1 || peers[0].Name != "" {
					t.Errorf("peers = %+v, want one unnamed peer", peers)
				}
			},
		},
		{
			name:  "zero peers",
			input: testIface + "\n\n",
			check: func(t *testing.T, iface string, peers []Peer, out string) {
				if len(peers) != 0 {
					t.Errorf("peers = %+v, want none", peers)
				}
				if out != testIface {
					t.Errorf("output = %q, want %q", out, testIface)
				}
			},
		},
		{
			name:  "name comment at top of interface",
			input: "[Interface]\n# server\nPrivateKey = cHJpdmF0ZQ==\n\n# phone\n[Peer]\nPublicKey = " + keyPhone + "\nAllowedIPs = 10.0.0.2/32\n",
			check: func(t *testing.T, iface string, peers []Peer, out string) {
				if !strings.Contains(iface, "# server") {
					t.Errorf("interface block lost its comment: %q", iface)
				}
				if peers[0].Name != "phone" {
					t.Errorf("name = %q, want phone", peers[0].Name)
				}
			},
		},
		{
			name:  "non-name comment above name comment",
			input: testIface + "\n# clients below\n# phone\n[Peer]\nPublicKey = " + keyPhone + "\nAllowedIPs = 10.0.0.2/32\n",
			check: func(t *testing.T, iface string, peers []Peer, out string) {
				if !strings.HasSuffix(iface, "\n# clients below") {
					t.Errorf("interface block = %q, want it to end with the non-name comment", iface)
				}
				if peers[0].Name != "phone" {
					t.Errorf("name = %q, want phone", peers[0].Name)
				}
			},
		},
		{
			name:  "metadata comment directly above peer",
			input: "[Interface]\nPrivateKey = cHJpdmF0ZQ==\n# RoutingMode = split\n[Peer]\nPublicKey = " + keyPhone + "\nAllowedIPs = 10.0.0.2/32\n",
			check: func(t *testing.T, iface string, peers []Peer, out string) {
				if !strings.HasSuffix(iface, "\n# RoutingMode = split") {
					t.Errorf("interface block = %q, want it to keep the metadata comment", iface)
				}
				if peers[0].Name != "" {
					t.Errorf("name = %q, want empty", peers[0].Name)
				}
			},
		},
		{
			name:  "keepalive and comment inside peer",
			input: testIface + "\n# phone\n[Peer]\nPublicKey = " + keyPhone + "\n# roams between networks\nAllowedIPs = 10.0.0.2/32\nPersistentKeepalive = 25\n",
			check: func(t *testing.T, iface string, peers []Peer, out string) {
				want := []string{"# roams between networks", "PersistentKeepalive = 25"}
				if !reflect.DeepEqual(peers[0].Extra, want) {
					t.Errorf("extra = %q, want %q", peers[0].Extra, want)
				}
			},
		},
		{
			name:  "lines before interface",
			input: "# managed by wg-relay\n\n" + testIface + "\n[Peer]\nPublicKey = " + keyPhone + "\nAllowedIPs = 10.0.0.2/32\n",
			check: func(t *testing.T, iface string, peers []Peer, out string) {
				if !strings.HasPrefix(out, "# managed by wg-relay\n\n[Interface]\n") {
					t.Errorf("output lost the leading lines: %q", out)
				}
				if peers[0].Name != "" {
					t.Errorf("name = %q, want empty", peers[0].Name)
				}
			},
		},
		{
			name:  "lowercase headers and keys",
			input: "[interface]\nPrivateKey = cHJpdmF0ZQ==\n\n# phone\n[peer]\npublickey = " + keyPhone + "\nallowedips = 10.0.0.2/32\nendpoint = phone.example:51820\n",
			check: func(t *testing.T, iface string, peers []Peer, out string) {
				want := []Peer{{Name: "phone", PublicKey: keyPhone, AllowedIPs: []string{"10.0.0.2/32"}, Endpoint: "phone.example:51820"}}
				if !reflect.DeepEqual(peers, want) {
					t.Errorf("peers = %+v, want %+v", peers, want)
				}
			},
		},
		{
			name:  "tabs around equals",
			input: testIface + "\n# phone\n[Peer]\nPublicKey\t=\t" + keyPhone + "\nPresharedKey\t=\t" + keyPSK + "\nAllowedIPs = 10.0.0.2/32\n",
			check: func(t *testing.T, iface string, peers []Peer, out string) {
				want := []Peer{{Name: "phone", PublicKey: keyPhone, PresharedKey: keyPSK, AllowedIPs: []string{"10.0.0.2/32"}}}
				if !reflect.DeepEqual(peers, want) {
					t.Errorf("peers = %+v, want %+v", peers, want)
				}
			},
		},
		{
			name:  "allowed ips with inline comment and trailing comma",
			input: testIface + "\n[Peer]\nPublicKey = " + keyPhone + "\nAllowedIPs = 10.0.0.2/32 # phone\nAllowedIPs = 10.0.1.0/24, \n",
			check: func(t *testing.T, iface string, peers []Peer, out string) {
				want := []string{"10.0.0.2/32", "10.0.1.0/24"}
				if !reflect.DeepEqual(peers[0].AllowedIPs, want) {
					t.Errorf("allowed ips = %q, want %q", peers[0].AllowedIPs, want)
				}
			},
		},
		{
			name:  "unnamed peer after peer with inner comment",
			input: testIface + "\n# laptop\n[Peer]\nPublicKey = " + keyLaptop + "\n# was laptop\nAllowedIPs = 10.0.0.3/32\n\n[Peer]\nPublicKey = " + keyTablet + "\nAllowedIPs = 10.0.0.4/32\n",
			check: func(t *testing.T, iface string, peers []Peer, out string) {
				if len(peers) != 2 {
					t.Fatalf("got %d peers, want 2", len(peers))
				}
				if peers[1].Name != "" {
					t.Errorf("second peer name = %q, want empty", peers[1].Name)
				}
				if !reflect.DeepEqual(peers[0].Extra, []string{"# was laptop"}) {
					t.Errorf("first peer extra = %q", peers[0].Extra)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iface, peers, err := ParsePeersFromString(tt.input)
			if err != nil {
				t.Fatalf("first parse: %v", err)
			}
			first := writeAndRead(t, iface, peers)

			iface2, peers2, err := ParsePeersFromString(first)
			if err != nil {
				t.Fatalf("second parse: %v", err)
			}
			second := writeAndRead(t, iface2, peers2)

			if first != second {
				t.Fatalf("round trip is unstable\nfirst:\n%s\nsecond:\n%s", first, second)
			}
			if len(peers) > 0 && peers[0].Name != "" {
				if n := strings.Count(first, "# "+peers[0].Name+"\n"); n != 1 {
					t.Errorf("first peer name %q appears %d times in output", peers[0].Name, n)
				}
			}
			if strings.Contains(tt.input, "# RoutingMode = full") {
				for _, meta := range []string{"# RoutingMode = full\n", "# IPv4Interface = eth0\n"} {
					if !strings.Contains(first, meta) {
						t.Errorf("output lost metadata comment %q", meta)
					}
				}
			}
			tt.check(t, iface, peers, first)
		})
	}
}

func TestParsePeersHeaderSpellings(t *testing.T) {
	tests := []struct {
		name      string
		ifaceHead string
		peerHead  string
	}{
		{"canonical", "[Interface]", "[Peer]"},
		{"upper case", "[Interface]", "[PEER]"},
		{"peer header with comment", "[Interface]", "[Peer] # phone"},
		{"peer header with inner whitespace", "[Interface]", " [ peer ] "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertHeaderSpelling(t, tt.ifaceHead, tt.peerHead)
		})
	}
}

func TestParsePeersRejectsInterfaceAfterPeer(t *testing.T) {
	const head = "[Interface]\nPrivateKey = k\n\n[Peer]\nPublicKey = k\n"

	for _, c := range []struct{ label, tail string }{
		{"control without second interface", "PostUp = id"},
		{"comment holding interface header", "# [Interface]\nPostUp = id"},
	} {
		t.Run(c.label, func(t *testing.T) {
			_, peers, err := ParsePeersFromString(head + c.tail)
			if err != nil || len(peers) != 1 {
				t.Fatalf("got %d peers, err %v, want one peer and no error", len(peers), err)
			}
		})
	}

	for _, header := range []string{"[Interface]", "[interface] # x", " [ Interface ] "} {
		t.Run(header, func(t *testing.T) {
			iface, peers, err := ParsePeersFromString(head + header + "\nPostUp = id")
			if err == nil {
				t.Fatalf("ParsePeersFromString accepted %q after [Peer], interface block = %q", header, iface)
			}
			if iface != "" || peers != nil {
				t.Errorf("got interface block %q and %d peers alongside the error, want zero values", iface, len(peers))
			}
		})
	}
}

// assertMetadataCommentInInterfaceBlock requires comment above the first peer to stay in the interface block.
func assertMetadataCommentInInterfaceBlock(t *testing.T, comment string) {
	t.Helper()
	iface := passthroughIface + "\n" + comment
	path := writeTempConfig(t, iface+"\n"+phoneSection)

	gotIface, peers, err := ParsePeers(path)
	if err != nil {
		t.Fatalf("ParsePeers: %v", err)
	}
	if gotIface != iface {
		t.Errorf("interface block = %q, want %q", gotIface, iface)
	}
	if want := []Peer{phonePeer}; !reflect.DeepEqual(peers, want) {
		t.Errorf("peers = %+v, want %+v", peers, want)
	}
	assertStableRoundTrip(t, path)
}

// assertMetadataCommentNamesNoPeer requires comment above the second peer to stay in the first peer's Extra.
func assertMetadataCommentNamesNoPeer(t *testing.T, comment string) {
	t.Helper()
	content := passthroughIface + "\n\n" + phoneSection + comment + "\n[Peer]\nPublicKey = " + keyLaptop + "\nAllowedIPs = 10.0.0.3/32\n"
	path := writeTempConfig(t, content)

	_, peers, err := ParsePeers(path)
	if err != nil {
		t.Fatalf("ParsePeers: %v", err)
	}
	first := phonePeer
	first.Extra = []string{comment}
	want := []Peer{first, {PublicKey: keyLaptop, AllowedIPs: []string{"10.0.0.3/32"}}}
	if !reflect.DeepEqual(peers, want) {
		t.Errorf("peers = %+v, want %+v", peers, want)
	}
	assertStableRoundTrip(t, path)
}

func TestParsePeersKeepsMetadataCommentInInterfaceBlockInAnyCase(t *testing.T) {
	for _, comment := range []string{"# ROUTINGMODE=full", "#  ipv4interface = eth1"} {
		t.Run(comment, func(t *testing.T) {
			assertMetadataCommentInInterfaceBlock(t, comment)
		})
	}
}

func TestParsePeersMetadataCommentInPeerSectionNamesNoPeer(t *testing.T) {
	assertMetadataCommentNamesNoPeer(t, "# ROUTINGMODE=full")
}

func TestParsePeersRejectsNUL(t *testing.T) {
	t.Run("inside peer header", func(t *testing.T) {
		assertNULRejected(t, strings.Replace(nulValid, "[Peer]", "[Pe\x00er]", 1))
	})
}

func TestParsePeersCommentBeforeBlankLineIsNotAName(t *testing.T) {
	iface := passthroughIface + "\n# phone"
	content := iface + "\n\n" + phoneSection
	path := writeTempConfig(t, content)

	gotIface, peers, err := ParsePeers(path)
	if err != nil {
		t.Fatalf("ParsePeers: %v", err)
	}
	if gotIface != iface {
		t.Errorf("interface block = %q, want %q", gotIface, iface)
	}
	if want := []Peer{phonePeer}; !reflect.DeepEqual(peers, want) {
		t.Errorf("peers = %+v, want %+v", peers, want)
	}
	if written := assertStableRoundTrip(t, path); written != content {
		t.Errorf("written config:\n%s\nwant the input unchanged:\n%s", written, content)
	}
}

func TestParsePeersTrimsWhitespaceAroundExtraLines(t *testing.T) {
	_, peers, err := ParsePeersFromString(passthroughIface + "\n\n" + phoneSection + "\t# roams \t\n  PersistentKeepalive = 25  \n")
	if err != nil {
		t.Fatalf("ParsePeersFromString: %v", err)
	}
	want := phonePeer
	want.Extra = []string{"# roams", "PersistentKeepalive = 25"}
	if !reflect.DeepEqual(peers, []Peer{want}) {
		t.Errorf("peers = %+v, want %+v", peers, []Peer{want})
	}
}

func TestParseKeyValue(t *testing.T) {
	tests := []struct {
		name, line, key, value string
	}{
		{"spaces around equals", "Endpoint = vpn.example.org:51820", "Endpoint", "vpn.example.org:51820"},
		{"value holding equals", "PresharedKey = " + keyPSK, "PresharedKey", keyPSK},
		{"no equals", "PersistentKeepalive 25", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if key, value := ParseKeyValue(tt.line); key != tt.key || value != tt.value {
				t.Errorf("ParseKeyValue(%q) = %q, %q, want %q, %q", tt.line, key, value, tt.key, tt.value)
			}
		})
	}
}
