package wgconf

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

var (
	keyIface  = testKey(0x51)
	keyBase   = testKey(0x61)
	keyPSK    = testKey(0x81)
	keyClient = testKey(0xa1)
	keyServer = testKey(0xc1)
	keyLeak   = testKey(0xe1)

	// fixtureKeys are the keys no validation error may echo.
	fixtureKeys = []string{keyIface, keyBase, keyPhone, keyPSK, keyClient, keyServer, keyLeak}

	seedIface  = "[Interface]\nPrivateKey = " + keyIface + "\nAddress = 10.0.0.1/24\nListenPort = 51820"
	seedConfig = seedIface + "\n\n# base\n[Peer]\nPublicKey = " + keyBase + "\nAllowedIPs = 10.0.0.9/32\n"

	host253 = strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	host255 = strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 63)
	label64 = strings.Repeat("a", 64)

	urlSafeKey = base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{0xff}, 32))
	shortKey   = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, 31))
)

type fieldCase struct {
	label string
	// field holds a Go struct field name, such as PublicKey.
	field string
	value string
}

type peerWriter struct {
	name  string
	write func(path string, p Peer) error
}

var (
	writePeersWriter = peerWriter{"WritePeers", func(path string, p Peer) error { return WritePeers(path, seedIface, []Peer{basePeer(), p}) }}
	appendPeerWriter = peerWriter{"AppendPeer", AppendPeer}
	peerWriters      = []peerWriter{writePeersWriter, appendPeerWriter}
)

func basePeer() Peer {
	return Peer{Name: "base", PublicKey: keyBase, AllowedIPs: []string{"10.0.0.9/32"}}
}

func validPeer() Peer {
	return Peer{
		Name:         "phone",
		PublicKey:    keyPhone,
		PresharedKey: keyPSK,
		AllowedIPs:   []string{"10.0.0.2/32", "fd00::2/128"},
		Endpoint:     "vpn.example.org:51820",
		Extra:        []string{"PersistentKeepalive = 25", "# roams"},
	}
}

func withPeerField(field, value string) Peer {
	p := validPeer()
	switch field {
	case "Name":
		p.Name = value
	case "PublicKey":
		p.PublicKey = value
	case "PresharedKey":
		p.PresharedKey = value
	case "AllowedIPs":
		p.AllowedIPs = []string{value}
	case "Endpoint":
		p.Endpoint = value
	case "Extra":
		p.Extra = []string{value}
	default:
		panic("unknown Peer field " + field)
	}
	return p
}

func validClientParams() ClientConfigParams {
	return ClientConfigParams{
		Name:           "laptop",
		PrivateKey:     keyClient,
		Address:        "10.0.0.2/32, fd00::2/128",
		DNS:            "1.1.1.1, corp.example",
		ServerPubKey:   keyServer,
		ServerEndpoint: "vpn.example.org:51820",
		AllowedIPs:     "0.0.0.0/0, ::/0",
		PresharedKey:   keyPSK,
	}
}

func withClientField(field, value string) ClientConfigParams {
	c := validClientParams()
	switch field {
	case "Name":
		c.Name = value
	case "PrivateKey":
		c.PrivateKey = value
	case "Address":
		c.Address = value
	case "DNS":
		c.DNS = value
	case "ServerPubKey":
		c.ServerPubKey = value
	case "ServerEndpoint":
		c.ServerEndpoint = value
	case "AllowedIPs":
		c.AllowedIPs = value
	case "PresharedKey":
		c.PresharedKey = value
	default:
		panic("unknown ClientConfigParams field " + field)
	}
	return c
}

// flipTrailingBits sets an unused low bit in the last base64 character of a 32-byte key.
func flipTrailingBits(key string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	i := strings.IndexByte(alphabet, key[42])
	return key[:42] + string(alphabet[i+1]) + key[43:]
}

func injected(valid, r string) string {
	return valid + r + "[Interface]" + r + "PostUp = id"
}

func controlRuneCase(field, valid, r string) fieldCase {
	return fieldCase{fmt.Sprintf("%s %U", field, []rune(r)[0]), field, injected(valid, r)}
}

func seedConfigFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "wg0.conf")
	if err := os.WriteFile(path, []byte(seedConfig), 0o600); err != nil {
		t.Fatalf("write seed config: %v", err)
	}
	return path
}

// assertCleanValidationError checks that err names field and holds neither value nor the first, second or last 16 bytes of a fixture key or a long value.
func assertCleanValidationError(t *testing.T, err error, field, value string) {
	t.Helper()
	msg := err.Error()
	if !strings.Contains(msg, field) {
		t.Errorf("error %q does not name field %s", msg, field)
	}
	if value != "" && strings.Contains(msg, value) {
		t.Errorf("error %q echoes the rejected value", msg)
	}
	for _, s := range append([]string{value}, fixtureKeys...) {
		if len(s) < 32 {
			continue
		}
		for _, frag := range []string{s[:16], s[16:32], s[len(s)-16:]} {
			if strings.Contains(msg, frag) {
				t.Errorf("error %q echoes a fragment of a key or the rejected value", msg)
			}
		}
	}
}

// assertPeerAccepted writes p over the seed config and checks it parses back unchanged.
func assertPeerAccepted(t *testing.T, write func(string, Peer) error, p Peer) {
	t.Helper()
	path := seedConfigFile(t)
	if err := write(path, p); err != nil {
		t.Fatalf("write: %v", err)
	}
	iface, peers, err := ParsePeers(path)
	if err != nil {
		t.Fatalf("ParsePeers: %v", err)
	}
	if want := []Peer{basePeer(), p}; iface != seedIface || !reflect.DeepEqual(peers, want) {
		t.Errorf("parsed back interface %q and peers %+v, want %q and %+v", iface, peers, seedIface, want)
	}
}

// assertPeerRejected checks that writing p fails, leaves the file unchanged and leaves no temp file.
func assertPeerRejected(t *testing.T, write func(string, Peer) error, p Peer, field, value string) {
	t.Helper()
	path := seedConfigFile(t)
	err := write(path, p)
	if err == nil {
		t.Fatalf("%s %q accepted, want error", field, value)
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("read config: %v", readErr)
	}
	if string(got) != seedConfig {
		t.Errorf("rejected write changed the file:\n%s", got)
	}
	entries, dirErr := os.ReadDir(filepath.Dir(path))
	if dirErr != nil {
		t.Fatalf("read dir: %v", dirErr)
	}
	if len(entries) != 1 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("dir holds %q, want only wg0.conf", names)
	}
	assertCleanValidationError(t, err, field, value)
}

func runPeerAcceptances(t *testing.T, writers []peerWriter, cases []fieldCase) {
	t.Helper()
	for _, w := range writers {
		for _, c := range cases {
			t.Run(w.name+"/"+c.label, func(t *testing.T) {
				assertPeerAccepted(t, w.write, withPeerField(c.field, c.value))
			})
		}
	}
}

func runPeerRejections(t *testing.T, writers []peerWriter, cases []fieldCase) {
	t.Helper()
	for _, w := range writers {
		for _, c := range cases {
			t.Run(w.name+"/"+c.label, func(t *testing.T) {
				assertPeerRejected(t, w.write, withPeerField(c.field, c.value), c.field, c.value)
			})
		}
	}
}

// assertOneClientConfig checks that out parses to one peer under exactly two section headers and holds no PostUp line.
func assertOneClientConfig(t *testing.T, out string) {
	t.Helper()
	_, peers, err := ParsePeersFromString(out)
	if err != nil || len(peers) != 1 {
		t.Fatalf("parse generated config: %d peers, err %v", len(peers), err)
	}
	headers := 0
	for _, line := range strings.Split(out, "\n") {
		head, _, _ := strings.Cut(line, "#")
		head = strings.ToLower(strings.Join(strings.Fields(head), ""))
		if head == "[peer]" || head == "[interface]" {
			headers++
		}
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "postup") {
			t.Errorf("config holds a hook line %q", line)
		}
	}
	if headers != 2 {
		t.Errorf("config holds %d section headers, want 2:\n%s", headers, out)
	}
}

func runClientConfigAcceptances(t *testing.T, cases []fieldCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			out, err := GenerateClientConfig(withClientField(c.field, c.value))
			if err != nil {
				t.Fatalf("GenerateClientConfig: %v", err)
			}
			if !strings.Contains(out, c.value) {
				t.Errorf("config does not contain %s %q:\n%s", c.field, c.value, out)
			}
			assertOneClientConfig(t, out)
		})
	}
}

func runClientConfigRejections(t *testing.T, cases []fieldCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			out, err := GenerateClientConfig(withClientField(c.field, c.value))
			if err == nil {
				t.Fatalf("%s %q accepted, want error", c.field, c.value)
			}
			if out != "" {
				t.Errorf("returned config text alongside the error:\n%s", out)
			}
			assertCleanValidationError(t, err, c.field, c.value)
		})
	}
}

var validFieldCases = []fieldCase{
	{"tab in Name", "Name", "phone\t(old)"},
	{"empty Name", "Name", ""},
	{"Name shaped like peer header", "Name", "[Peer]"},
	{"Name with metadata key prefix", "Name", "RoutingModeX = full"},
	{"empty PresharedKey", "PresharedKey", ""},
	{"bare IPv4", "AllowedIPs", "10.0.0.2"},
	{"empty Endpoint", "Endpoint", ""},
	{"IPv4 Endpoint", "Endpoint", "203.0.113.7:51820"},
	{"trailing-dot hostname", "Endpoint", "vpn.example.org.:51820"},
	{"underscore hostname", "Endpoint", "my_host.duckdns.org:51820"},
	{"253-byte hostname", "Endpoint", host253 + ":51820"},
	{"port 65535", "Endpoint", "vpn.example.org:65535"},
	{"upper-case keepalive OFF", "Extra", "PERSISTENTKEEPALIVE = OFF"},
	{"keepalive 65535", "Extra", "PersistentKeepalive = 65535"},
	{"keepalive with comment", "Extra", "PersistentKeepalive = 25 # note"},
}

func TestPeerWritersRoundTripValidFields(t *testing.T) {
	for _, w := range peerWriters {
		t.Run(w.name+"/valid peer", func(t *testing.T) {
			assertPeerAccepted(t, w.write, validPeer())
		})
	}
	t.Run("WritePeers/no AllowedIPs", func(t *testing.T) {
		p := validPeer()
		p.AllowedIPs = nil
		assertPeerAccepted(t, writePeersWriter.write, p)
	})
	runPeerAcceptances(t, []peerWriter{writePeersWriter}, validFieldCases)
}

var controlRuneFieldCases = []fieldCase{
	controlRuneCase("Name", "phone", "\n"),
	controlRuneCase("Name", "phone", "\u2028"),
	controlRuneCase("PublicKey", keyPhone, "\n"),
	controlRuneCase("PresharedKey", keyPSK, "\n"),
	controlRuneCase("AllowedIPs", "10.0.0.2/32", "\n"),
	controlRuneCase("Endpoint", "vpn.example.org:51820", "\n"),
	controlRuneCase("Extra", "# roams", "\n"),
}

func TestPeerWritersRejectControlRunes(t *testing.T) {
	runPeerRejections(t, []peerWriter{writePeersWriter}, controlRuneFieldCases)
}

var nameCases = []fieldCase{
	{"surrounding spaces", "Name", " padded-name "},
	{"trailing ideographic space", "Name", "phone\u3000"},
	{"metadata key", "Name", "RoutingMode = full"},
	{"lower-case metadata key", "Name", "routingmode=full"},
}

func TestPeerWritersRejectNameThatDoesNotRoundTrip(t *testing.T) {
	runPeerRejections(t, []peerWriter{writePeersWriter}, nameCases)
}

var malformedKeyCases = []fieldCase{
	{"PublicKey not base64", "PublicKey", "not-a-key"},
	{"PublicKey URL-safe alphabet", "PublicKey", urlSafeKey},
	{"PublicKey 31 bytes", "PublicKey", shortKey},
	{"PublicKey non-zero trailing bits", "PublicKey", flipTrailingBits(keyPhone)},
	{"PresharedKey not base64", "PresharedKey", "psk-not-base64"},
}

func TestPeerWritersRejectMalformedKeys(t *testing.T) {
	runPeerRejections(t, []peerWriter{writePeersWriter}, malformedKeyCases)
}

var malformedAllowedIPCases = []fieldCase{
	{"two prefixes in one element", "AllowedIPs", "10.0.0.2/32, 0.0.0.0/0"},
	{"zoned address", "AllowedIPs", "fe80::1%eth0"},
}

func lastAllowedIPInvalid() Peer {
	p := validPeer()
	p.AllowedIPs = []string{"10.0.0.2/32", "fd00::2/128", "10.0.0.3/33"}
	return p
}

func TestPeerWritersRejectMalformedAllowedIPs(t *testing.T) {
	runPeerRejections(t, []peerWriter{writePeersWriter}, malformedAllowedIPCases)
	t.Run("WritePeers/only last element invalid", func(t *testing.T) {
		assertPeerRejected(t, writePeersWriter.write, lastAllowedIPInvalid(), "AllowedIPs", "10.0.0.3/33")
	})
}

var malformedEndpointCases = []fieldCase{
	{"missing port", "Endpoint", "1.2.3.4"},
	{"port zero", "Endpoint", "1.2.3.4:0"},
	{"port above 65535", "Endpoint", "1.2.3.4:70000"},
	{"space in host", "Endpoint", "a b:1"},
	{"label starts with hyphen", "Endpoint", "-bad.example:1"},
	{"label ends with hyphen", "Endpoint", "bad-.example:51820"},
	{"empty label", "Endpoint", "a..example:51820"},
	{"64-byte label", "Endpoint", label64 + ".example.org:51820"},
	{"legacy octal IPv4", "Endpoint", "010.010.010.010:51820"},
	{"legacy hex IPv4", "Endpoint", "0x7f000001:51820"},
	{"zoned IPv6", "Endpoint", "[fe80::1%eth0]:51820"},
	{"255-byte hostname", "Endpoint", host255 + ":51820"},
}

func TestPeerWritersRejectMalformedEndpoint(t *testing.T) {
	runPeerRejections(t, []peerWriter{writePeersWriter}, malformedEndpointCases)
}

var unsafeExtraLineCases = []fieldCase{
	{"modelled key", "Extra", "PublicKey = " + keyLeak},
	{"interface header", "Extra", "[Interface]"},
	{"keepalive out of range", "Extra", "PersistentKeepalive = 70000"},
	{"keepalive key with space", "Extra", "Persistent Keepalive = 25"},
	{"Kelvin sign keepalive key", "Extra", "Persistent\u212aeepalive = 25"},
}

func lastExtraLineInvalid() Peer {
	p := validPeer()
	p.Extra = []string{"PersistentKeepalive = 25", "# roams", "PostUp = id"}
	return p
}

func TestPeerWritersRejectUnsafeExtraLines(t *testing.T) {
	runPeerRejections(t, []peerWriter{writePeersWriter}, unsafeExtraLineCases)
	t.Run("WritePeers/only last line invalid", func(t *testing.T) {
		assertPeerRejected(t, writePeersWriter.write, lastExtraLineInvalid(), "Extra", "PostUp = id")
	})
}

// The missing directory fails any write that gets past validation.
func TestWritePeersValidatesBeforeCreatingTempFile(t *testing.T) {
	bad := withPeerField("Name", injected("phone", "\n"))
	err := WritePeers(filepath.Join(t.TempDir(), "missing", "wg0.conf"), seedIface, []Peer{bad})
	if err == nil {
		t.Fatal("WritePeers accepted an injected Name, want error")
	}
	assertCleanValidationError(t, err, "Name", bad.Name)
}

func TestWritePeersFailedRenameKeepsOriginal(t *testing.T) {
	peers := []Peer{basePeer(), validPeer()}

	path := seedConfigFile(t)
	if err := WritePeers(path, seedIface, peers); err != nil {
		t.Fatalf("WritePeers with a working rename: %v", err)
	}
	if _, got, err := ParsePeers(path); err != nil || !reflect.DeepEqual(got, peers) {
		t.Fatalf("after a working rename ParsePeers = %+v, %v, want %+v", got, err, peers)
	}

	errRename := errors.New("rename failed")
	orig := renameFile
	renameFile = func(string, string) error { return errRename }
	t.Cleanup(func() { renameFile = orig })

	path = seedConfigFile(t)
	if err := WritePeers(path, seedIface, peers); !errors.Is(err, errRename) {
		t.Fatalf("WritePeers with a failing rename returned %v, want the rename error", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if string(got) != seedConfig {
		t.Errorf("failed write changed the file:\n%s", got)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 1 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("dir holds %q, want only wg0.conf", names)
	}
}

// The missing file fails any append that gets past validation.
func TestAppendPeerValidatesBeforeOpening(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wg0.conf")
	bad := withPeerField("Name", injected("phone", "\n"))
	err := AppendPeer(path, bad)
	if err == nil {
		t.Fatal("AppendPeer accepted an injected Name, want error")
	}
	assertCleanValidationError(t, err, "Name", bad.Name)
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Errorf("rejected AppendPeer left a file at %s (stat: %v)", path, statErr)
	}
}

func TestAppendPeerMatchesWritePeers(t *testing.T) {
	p := validPeer()

	appended := filepath.Join(t.TempDir(), "wg0.conf")
	if err := WritePeers(appended, seedIface, []Peer{basePeer()}); err != nil {
		t.Fatalf("WritePeers seed: %v", err)
	}
	if err := AppendPeer(appended, p); err != nil {
		t.Fatalf("AppendPeer: %v", err)
	}
	written := filepath.Join(t.TempDir(), "wg0.conf")
	if err := WritePeers(written, seedIface, []Peer{basePeer(), p}); err != nil {
		t.Fatalf("WritePeers: %v", err)
	}

	got, err := os.ReadFile(appended)
	if err != nil {
		t.Fatalf("read appended: %v", err)
	}
	want, err := os.ReadFile(written)
	if err != nil {
		t.Fatalf("read written: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("AppendPeer output:\n%s\nWritePeers output:\n%s", got, want)
	}
}

// AppendPeer onto a file without a final newline does not turn its last line into the new peer's Name.
func TestAppendPeerTerminatesUnfinishedLastLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wg0.conf")
	content := seedIface + "\n\n# laptop\n[Peer]\nPublicKey = " + keyBase + "\nAllowedIPs = 10.0.0.3/32\n# was laptop"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	added := Peer{PublicKey: keyPhone, AllowedIPs: []string{"10.0.0.4/32"}}
	if err := AppendPeer(path, added); err != nil {
		t.Fatalf("AppendPeer: %v", err)
	}

	_, peers, err := ParsePeers(path)
	if err != nil {
		t.Fatalf("ParsePeers: %v", err)
	}
	want := []Peer{
		{Name: "laptop", PublicKey: keyBase, AllowedIPs: []string{"10.0.0.3/32"}, Extra: []string{"# was laptop"}},
		added,
	}
	if !reflect.DeepEqual(peers, want) {
		t.Errorf("peers = %+v, want %+v", peers, want)
	}
}

func TestGenerateClientConfig(t *testing.T) {
	cfg := validClientParams()
	out, err := GenerateClientConfig(cfg)
	if err != nil {
		t.Fatalf("GenerateClientConfig: %v", err)
	}
	iface, peers, err := ParsePeersFromString(out)
	if err != nil || len(peers) != 1 {
		t.Fatalf("parse generated config: %d peers, err %v", len(peers), err)
	}

	lines := strings.Split(iface, "\n")
	if lines[0] != "[Interface]" {
		t.Fatalf("config starts with %q, want the [Interface] header", lines[0])
	}
	var comments []string
	values := map[string]string{}
	for _, line := range lines[1:] {
		if comment, ok := strings.CutPrefix(line, "#"); ok {
			comments = append(comments, strings.TrimSpace(comment))
			continue
		}
		key, value := ParseKeyValue(line)
		values[key] = value
	}
	if !slices.Equal(comments, []string{cfg.Name}) {
		t.Errorf("interface comments = %q, want only the Name %q", comments, cfg.Name)
	}
	for key, want := range map[string]string{"PrivateKey": cfg.PrivateKey, "Address": cfg.Address, "DNS": cfg.DNS} {
		if values[key] != want {
			t.Errorf("interface %s = %q, want %q", key, values[key], want)
		}
	}

	p := peers[0]
	if p.PublicKey != cfg.ServerPubKey || p.PresharedKey != cfg.PresharedKey || p.Endpoint != cfg.ServerEndpoint {
		t.Errorf("peer = %+v, want PublicKey %q, PresharedKey %q and Endpoint %q", p, cfg.ServerPubKey, cfg.PresharedKey, cfg.ServerEndpoint)
	}
	if want := []string{"0.0.0.0/0", "::/0"}; !slices.Equal(p.AllowedIPs, want) {
		t.Errorf("peer AllowedIPs = %q, want %q", p.AllowedIPs, want)
	}
}

func TestGenerateClientConfigAcceptsValidFields(t *testing.T) {
	runClientConfigAcceptances(t, []fieldCase{
		{"tab in Name", "Name", "laptop\t(old)"},
		{"empty Name", "Name", ""},
		{"Name shaped like peer header", "Name", "[Peer]"},
		{"empty PresharedKey", "PresharedKey", ""},
		{"AllowedIPs tabs around comma", "AllowedIPs", "0.0.0.0/0\t,\t::/0"},
		{"empty DNS", "DNS", ""},
	})
}

func TestGenerateClientConfigRejectsInvalidFields(t *testing.T) {
	runClientConfigRejections(t, []fieldCase{
		controlRuneCase("Name", "laptop", "\n"),
		controlRuneCase("Name", "laptop", "\u2028"),
		controlRuneCase("PrivateKey", keyClient, "\n"),
		controlRuneCase("Address", "10.0.0.2/32", "\n"),
		controlRuneCase("DNS", "1.1.1.1", "\n"),
		controlRuneCase("ServerPubKey", keyServer, "\n"),
		controlRuneCase("ServerEndpoint", "vpn.example.org:51820", "\n"),
		controlRuneCase("AllowedIPs", "0.0.0.0/0", "\n"),
		controlRuneCase("PresharedKey", keyPSK, "\n"),
		{"Name surrounding spaces", "Name", " padded-name "},
		{"Name metadata key", "Name", "RoutingMode = full"},
		{"PrivateKey not base64", "PrivateKey", "not-a-key"},
		{"PrivateKey non-zero trailing bits", "PrivateKey", flipTrailingBits(keyClient)},
		{"empty ServerPubKey", "ServerPubKey", ""},
		{"PresharedKey not base64", "PresharedKey", "psk-not-base64"},
		{"Address trailing comma", "Address", "10.0.0.2/32,"},
		{"zoned Address", "Address", "fe80::1%eth0/64"},
		{"AllowedIPs space separated", "AllowedIPs", "10.0.0.0/24 0.0.0.0/0"},
		{"ServerEndpoint port above 65535", "ServerEndpoint", "1.2.3.4:70000"},
		{"legacy hex ServerEndpoint", "ServerEndpoint", "0x7f.0.0.1:51820"},
		{"DNS trailing comma", "DNS", "1.1.1.1,"},
		{"DNS legacy hex address", "DNS", "0x7f.0.0.1"},
	})
}
