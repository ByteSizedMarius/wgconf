package wgconf

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
)

var (
	passthroughIface     = "[Interface]\nPrivateKey = " + keyIface + "\nAddress = 10.0.0.1/24"
	passthroughLegacyPSK = flipTrailingBits(keyPSK)

	// The phone peer here holds values the writer grammar rejects.
	passthroughLegacyLines = []string{
		"[Interface]",
		"PrivateKey = " + keyIface,
		"Address = 10.0.0.1/24",
		"",
		"# phone",
		"[Peer] # phone",
		"PublicKey = " + keyPhone,
		"PresharedKey = " + passthroughLegacyPSK,
		"AllowedIPs = 10.0.0.2/32, 10.0.0.3/32 # phone lan",
		"Endpoint = 010.0.0.1:51820",
		"Persistent Keepalive = 25",
		"# roams",
		"",
		"# laptop",
		"[Peer]",
		"PublicKey = " + keyLaptop,
		"AllowedIPs = 10.0.0.4/32",
	}
	passthroughLegacy     = strings.Join(passthroughLegacyLines, "\r\n") + "\r\n"
	passthroughLegacySpan = strings.Join(passthroughLegacyLines[5:12], "\r\n") + "\r\n"

	passthroughKeylessSpan = "[Peer]\nallowedips=10.0.0.7/32\n"
	passthroughKeyless     = passthroughIface + "\n\n# ghost\n" + passthroughKeylessSpan +
		"\n# laptop\n[Peer]\nPublicKey = " + keyLaptop + "\nAllowedIPs = 10.0.0.4/32\n"

	passthroughLegacyEndpointSection = "# phone\n[Peer]\nPublicKey = " + keyPhone + "\nAllowedIPs = 10.0.0.2/32\nEndpoint = 010.0.0.1:51820\n"
	passthroughOneK                  = passthroughIface + "\n\n" + passthroughLegacyEndpointSection
	passthroughDupK                  = Peer{Name: "phone2", PublicKey: keyPhone, AllowedIPs: []string{"10.0.0.5/32"}, Endpoint: "vpn.example.org:51820"}
	passthroughTwoK                  = passthroughOneK + "\n# phone2\n[Peer]\nPublicKey = " + keyPhone + "\nAllowedIPs = 10.0.0.5/32\nEndpoint = vpn.example.org:51820\n"

	// passthroughTwoLegacy holds two sections that share a PublicKey and both carry a legacy Endpoint.
	passthroughTwoLegacy = passthroughOneK + "\n# phone-b\n[Peer]\nPublicKey = " + keyPhone + "\nAllowedIPs = 10.0.0.5/32\nEndpoint = 010.0.0.5:51820\n"

	// passthroughSameA and passthroughSameB parse to equal peers.
	passthroughSameA    = "[Peer]\nPublicKey = " + keyPhone + "\nAllowedIPs = 10.0.0.2/32\nEndpoint = 010.0.0.1:51820\n"
	passthroughSameB    = "[Peer]\npublickey=" + keyPhone + "\nallowedips=10.0.0.2/32\nendpoint=010.0.0.1:51820\n"
	passthroughSame     = passthroughIface + "\n\n" + passthroughSameA + "\n" + passthroughSameB
	passthroughSamePeer = Peer{PublicKey: keyPhone, AllowedIPs: []string{"10.0.0.2/32"}, Endpoint: "010.0.0.1:51820"}

	passthroughNextName = passthroughIface + "\n\n[Peer]\nPublicKey = " + keyPhone + "\nAllowedIPs = 10.0.0.2/32\nEndpoint = 010.0.0.1:1\n# note\n# next\n[Peer]\nPublicKey = " + keyLaptop + "\nAllowedIPs = 10.0.0.3/32\n"

	passthroughShadowSpan = "[Peer]\nPublic Key = " + keyTablet + "\nPublicKey = " + keyPhone + "\nAllowedIPs = 10.0.0.2/32\n"
	passthroughShadow     = passthroughIface + "\n\n" + passthroughShadowSpan

	// passthroughLowerSpan is a phone section in a spelling the writer never emits.
	passthroughLowerSpan = "[Peer]\npublickey=" + keyPhone + "\nallowedips = 10.0.0.2/32\nendpoint = 010.0.0.1:51820\n"
	passthroughBareSpan  = "[Peer]\npublickey=" + keyLaptop + "\nendpoint = 010.0.0.3:51820\n"
	passthroughVerbatim  = passthroughIface + "\n\n# phone\n" + passthroughLowerSpan + "\n" + passthroughBareSpan

	passthroughZoned = "fe80::1%eth0/128"
	passthroughTrust = passthroughIface + "\n\n# phone\n[Peer]\npublickey=" + keyPhone +
		"\nallowedips = " + passthroughZoned + ", 10.0.0.2/32\nendpoint = 010.0.0.1:51820\nPersistent Keepalive = 25\n" +
		"\n# laptop\n[Peer]\nPublicKey = " + keyLaptop + "\nAllowedIPs = 10.0.0.4/32\nEndpoint = 0x7f.0.0.1:51820\n# laptop note\n"

	passthroughTablet     = Peer{Name: "tablet", PublicKey: keyTablet, AllowedIPs: []string{"10.0.0.6/32"}}
	passthroughLaptopOnly = passthroughIface + "\n\n# laptop\n[Peer]\nPublicKey = " + keyLaptop + "\nAllowedIPs = 10.0.0.4/32\n"

	passthroughValidLaptop = Peer{Name: "laptop", PublicKey: keyLaptop, PresharedKey: keyPSK, AllowedIPs: []string{"10.0.0.4/32"}}
	passthroughLegacyPhone = Peer{Name: "phone", PublicKey: keyPhone, AllowedIPs: []string{"10.0.0.2/32"}, Endpoint: "010.0.0.1:51820"}

	spanEOF           = passthroughIface + "\n\n# phone\n[Peer]\nPublicKey = " + keyPhone + "\nAllowedIPs = 10.0.0.2/32\nEndpoint = 010.0.0.1:51820"
	spanInlineComment = "[Peer]\nPublicKey = " + keyPhone + " # phone key\nAllowedIPs = 10.0.0.2/32\nEndpoint = 010.0.0.1:51820\n"

	trustLegacyName = "a\x1bb"
	trustLegacyKey  = flipTrailingBits(keyLaptop)
	trustLegacy     = passthroughIface + "\n\n# " + trustLegacyName + "\n[Peer]\nPublicKey = " + keyPhone + "\nAllowedIPs = 10.0.0.2/32\n" +
		"\n# laptop\n[Peer]\nPublicKey = " + trustLegacyKey + "\nAllowedIPs = 10.0.0.3/32\n"
)

// passthroughSamePeers compares peers field by field with nil and empty slices equal.
func passthroughSamePeers(a, b []Peer) bool {
	norm := func(p Peer) Peer {
		if len(p.AllowedIPs) == 0 {
			p.AllowedIPs = nil
		}
		if len(p.Extra) == 0 {
			p.Extra = nil
		}
		return p
	}
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !reflect.DeepEqual(norm(a[i]), norm(b[i])) {
			return false
		}
	}
	return true
}

func passthroughParse(t *testing.T, path string) (string, []Peer) {
	t.Helper()
	iface, peers, err := ParsePeers(path)
	if err != nil {
		t.Fatalf("ParsePeers: %v", err)
	}
	return iface, peers
}

// passthroughWrite requires the written peers to parse back unchanged.
func passthroughWrite(t *testing.T, path, iface string, peers []Peer) string {
	t.Helper()
	if err := WritePeers(path, iface, peers); err != nil {
		t.Fatalf("WritePeers rejected, want success: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read written config: %v", err)
	}
	if _, got := passthroughParse(t, path); !passthroughSamePeers(got, peers) {
		t.Errorf("parsed back %+v, want %+v", got, peers)
	}
	return string(data)
}

func passthroughDirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("read dir: %v", err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// passthroughAssertRejected requires write to fail and leave path and its directory unchanged.
func passthroughAssertRejected(t *testing.T, path string, write func() error, field string, index int, absent ...string) {
	t.Helper()
	before, beforeErr := os.ReadFile(path)
	dirBefore := passthroughDirNames(t, filepath.Dir(path))
	err := write()
	if err == nil {
		t.Fatalf("accepted, want an error naming %s", field)
	}
	after, afterErr := os.ReadFile(path)
	if (beforeErr == nil) != (afterErr == nil) || !bytes.Equal(before, after) {
		t.Errorf("rejected write changed %s:\n%s", path, after)
	}
	if dirAfter := passthroughDirNames(t, filepath.Dir(path)); !slices.Equal(dirAfter, dirBefore) {
		t.Errorf("dir holds %q after the rejected write, want %q", dirAfter, dirBefore)
	}
	msg := err.Error()
	if index >= 0 && !strings.Contains(msg, strconv.Itoa(index)) {
		t.Errorf("error %q does not name peer index %d", msg, index)
	}
	assertCleanValidationError(t, err, field, "")
	for _, s := range absent {
		if strings.Contains(msg, s) {
			t.Errorf("error %q contains %q", msg, s)
		}
	}
}

// passthroughWriterSection is the text WritePeers writes for a peer it does not copy from the file.
func passthroughWriterSection(p Peer) string {
	var sb strings.Builder
	sb.WriteString("\n")
	if p.Name != "" {
		sb.WriteString("# " + p.Name + "\n")
	}
	sb.WriteString("[Peer]\nPublicKey = " + p.PublicKey + "\n")
	if p.PresharedKey != "" {
		sb.WriteString("PresharedKey = " + p.PresharedKey + "\n")
	}
	sb.WriteString("AllowedIPs = " + strings.Join(p.AllowedIPs, ", ") + "\n")
	if p.Endpoint != "" {
		sb.WriteString("Endpoint = " + p.Endpoint + "\n")
	}
	for _, line := range p.Extra {
		sb.WriteString(line + "\n")
	}
	return sb.String()
}

func passthroughClone(peers []Peer) []Peer {
	out := make([]Peer, len(peers))
	for i, p := range peers {
		p.AllowedIPs = slices.Clone(p.AllowedIPs)
		p.Extra = slices.Clone(p.Extra)
		out[i] = p
	}
	return out
}

func passthroughSetup(t *testing.T, content string, want []Peer) (string, string, []Peer) {
	t.Helper()
	path := writeTempConfig(t, content)
	iface, peers := passthroughParse(t, path)
	if want != nil && !passthroughSamePeers(peers, want) {
		t.Fatalf("fixture parsed to %+v, want %+v", peers, want)
	}
	return path, iface, passthroughClone(peers)
}

func passthroughReject(t *testing.T, path, iface string, peers []Peer, field string, index int, absent ...string) {
	t.Helper()
	passthroughAssertRejected(t, path, func() error { return WritePeers(path, iface, peers) }, field, index, absent...)
}

// passthroughFixpoint writes peers twice with identical arguments and requires byte-identical files.
func passthroughFixpoint(t *testing.T, path, iface string, peers []Peer) string {
	t.Helper()
	first := passthroughWrite(t, path, iface, peers)
	if second := passthroughWrite(t, path, iface, passthroughClone(peers)); second != first {
		t.Errorf("second identical write differs:\n%q\nfirst:\n%q", second, first)
	}
	return first
}

func passthroughAssertContains(t *testing.T, out, want string) {
	t.Helper()
	if !strings.Contains(out, want) {
		t.Errorf("written file lacks %q:\n%q", want, out)
	}
}

func passthroughVerbatimPeers() []Peer {
	return []Peer{
		{Name: "phone", PublicKey: keyPhone, AllowedIPs: []string{"10.0.0.2/32"}, Endpoint: "010.0.0.1:51820"},
		{PublicKey: keyLaptop, Endpoint: "010.0.0.3:51820"},
	}
}

func assertVerbatimSpans(t *testing.T, out string) {
	t.Helper()
	passthroughAssertContains(t, out, "\n# phone\n"+passthroughLowerSpan)
	passthroughAssertContains(t, out, "\n"+passthroughBareSpan)
}

// fieldTrustAccept applies edit to the phone peer of passthroughLegacy and requires the write to succeed in writer format.
func fieldTrustAccept(t *testing.T, edit func(k *Peer)) {
	t.Helper()
	path, iface, peers := passthroughSetup(t, passthroughLegacy, nil)
	edit(&peers[0])
	out := passthroughWrite(t, path, iface, peers)
	if !strings.Contains(out, passthroughWriterSection(peers[0])) {
		t.Errorf("phone is not in writer format:\n%q", out)
	}
	if strings.Contains(out, "[Peer] # phone") {
		t.Errorf("edited phone kept its original span:\n%q", out)
	}
}

func fieldTrustReject(t *testing.T, field string, index int, edit func(peers []Peer) []Peer, absent ...string) {
	t.Helper()
	path, iface, peers := passthroughSetup(t, passthroughLegacy, nil)
	passthroughReject(t, path, iface, edit(peers), field, index, absent...)
}

func passthroughTrustPeers() []Peer {
	return []Peer{
		{Name: "phone", PublicKey: keyPhone, AllowedIPs: []string{passthroughZoned, "10.0.0.2/32"}, Endpoint: "010.0.0.1:51820", Extra: []string{"Persistent Keepalive = 25"}},
		{Name: "laptop", PublicKey: keyLaptop, AllowedIPs: []string{"10.0.0.4/32"}, Endpoint: "0x7f.0.0.1:51820", Extra: []string{"# laptop note"}},
	}
}

// elementTrustAccept applies edit to the peers of passthroughTrust and requires the phone to be written in writer format.
func elementTrustAccept(t *testing.T, edit func(peers []Peer) []Peer) {
	t.Helper()
	path, iface, peers := passthroughSetup(t, passthroughTrust, passthroughTrustPeers())
	peers = edit(peers)
	out := passthroughWrite(t, path, iface, peers)
	passthroughAssertContains(t, out, passthroughWriterSection(peers[0]))
	if strings.Contains(out, "publickey="+keyPhone) {
		t.Errorf("edited phone kept its original span:\n%q", out)
	}
}

func elementTrustReject(t *testing.T, field string, index int, edit func(peers []Peer) []Peer, absent ...string) {
	t.Helper()
	path, iface, peers := passthroughSetup(t, passthroughTrust, passthroughTrustPeers())
	passthroughReject(t, path, iface, edit(peers), field, index, absent...)
}

func spanTablet() Peer {
	p := passthroughTablet
	p.Name = ""
	return p
}

func extraKeyContent(line string) string {
	return passthroughIface + "\n\n# phone\n[Peer]\nPublicKey = " + keyPhone + "\n" + line + "\nAllowedIPs = 10.0.0.2/32\n"
}

func extraKeyPeers(line string) []Peer {
	return []Peer{{Name: "phone", PublicKey: keyPhone, AllowedIPs: []string{"10.0.0.2/32"}, Extra: []string{strings.TrimSpace(line)}}}
}

func TestPassthroughLegacyFileRoundTrip(t *testing.T) {
	path := writeTempConfig(t, passthroughLegacy)
	iface, peers := passthroughParse(t, path)
	wantK := Peer{
		Name:         "phone",
		PublicKey:    keyPhone,
		PresharedKey: passthroughLegacyPSK,
		AllowedIPs:   []string{"10.0.0.2/32", "10.0.0.3/32"},
		Endpoint:     "010.0.0.1:51820",
		Extra:        []string{"Persistent Keepalive = 25", "# roams"},
	}
	if len(peers) != 2 || !passthroughSamePeers(peers[:1], []Peer{wantK}) {
		t.Fatalf("fixture parsed to %+v, want phone as %+v", peers, wantK)
	}

	t.Run("unchanged write keeps the section bytes and is a fixpoint", func(t *testing.T) {
		first := passthroughWrite(t, path, iface, peers)
		if !strings.Contains(first, "\n# phone\n"+passthroughLegacySpan) {
			t.Errorf("written file lacks the phone section byte for byte:\n%q", first)
		}
		iface2, peers2 := passthroughParse(t, path)
		if iface2 != iface {
			t.Errorf("interface block %q after the write, want %q", iface2, iface)
		}
		second := passthroughWrite(t, path, iface2, peers2)
		if second != first {
			t.Errorf("second write differs:\n%q\nfirst:\n%q", second, first)
		}
	})
	t.Run("rename, repeat, rename back keeps the legacy values", func(t *testing.T) {
		path, iface, peers := passthroughSetup(t, passthroughLegacy, nil)
		renamed := passthroughClone(peers)
		renamed[0].Name = "phone2"
		passthroughFixpoint(t, path, iface, renamed)
		passthroughWrite(t, path, iface, peers)
	})
	t.Run("changed interface block with unchanged peers", func(t *testing.T) {
		path, iface, peers := passthroughSetup(t, passthroughLegacy, nil)
		newIface := iface + "\nListenPort = 51821"
		out := passthroughFixpoint(t, path, newIface, peers)
		passthroughAssertContains(t, out, "\n# phone\n"+passthroughLegacySpan)
		if got, _ := passthroughParse(t, path); got != newIface {
			t.Errorf("interface block %q after the write, want %q", got, newIface)
		}
	})
	t.Run("reordered unchanged peers keep their spans", func(t *testing.T) {
		path, iface, peers := passthroughSetup(t, passthroughVerbatim, passthroughVerbatimPeers())
		assertVerbatimSpans(t, passthroughFixpoint(t, path, iface, []Peer{peers[1], peers[0]}))
	})
	t.Run("empty slices match nil originals verbatim", func(t *testing.T) {
		path, iface, peers := passthroughSetup(t, passthroughVerbatim, passthroughVerbatimPeers())
		for i := range peers {
			peers[i].AllowedIPs = append([]string{}, peers[i].AllowedIPs...)
			peers[i].Extra = []string{}
		}
		assertVerbatimSpans(t, passthroughFixpoint(t, path, iface, peers))
	})
}

func TestWritePeersValidatesOnlyNewValuesOfAChangedPeer(t *testing.T) {
	t.Run("control name change keeps the legacy values", func(t *testing.T) {
		fieldTrustAccept(t, func(k *Peer) { k.Name = "phone2" })
	})

	t.Run("Endpoint changes to another legacy value", func(t *testing.T) {
		fieldTrustReject(t, "Endpoint", 0, func(peers []Peer) []Peer {
			peers[0].Endpoint = "010.0.0.2:51820"
			return peers
		}, "010.0.0.2", passthroughLegacyPSK)
	})
	t.Run("new peer copies the legacy Endpoint", func(t *testing.T) {
		fieldTrustReject(t, "Endpoint", 2, func(peers []Peer) []Peer {
			return append(peers, Peer{Name: "tablet", PublicKey: keyTablet, AllowedIPs: []string{"10.0.0.6/32"}, Endpoint: "010.0.0.1:51820"})
		}, "010.0.0.1", passthroughLegacyPSK)
	})
	t.Run("new Extra line PostUp", func(t *testing.T) {
		fieldTrustReject(t, "Extra", 0, func(peers []Peer) []Peer {
			peers[0].Extra = append(peers[0].Extra, "PostUp = id")
			return peers
		}, "PostUp", passthroughLegacyPSK)
	})
	t.Run("AllowedIPs gains a malformed entry", func(t *testing.T) {
		fieldTrustReject(t, "AllowedIPs", 0, func(peers []Peer) []Peer {
			peers[0].AllowedIPs = append(peers[0].AllowedIPs, "bad")
			return peers
		}, "bad", passthroughLegacyPSK)
	})
}

func TestWritePeersTrustsOnlyExactValuesOfTheBackingOriginal(t *testing.T) {
	t.Run("control renamed phone keeps its legacy values", func(t *testing.T) {
		elementTrustAccept(t, func(peers []Peer) []Peer {
			peers[0].Name = "phone2"
			return peers
		})
	})
	t.Run("reordered AllowedIPs get element trust", func(t *testing.T) {
		elementTrustAccept(t, func(peers []Peer) []Peer {
			peers[0].AllowedIPs = []string{"10.0.0.2/32", passthroughZoned}
			return peers
		})
	})
	t.Run("trusted AllowedIPs entry moved into another original", func(t *testing.T) {
		elementTrustReject(t, "AllowedIPs", 1, func(peers []Peer) []Peer {
			peers[0].AllowedIPs = []string{"10.0.0.2/32"}
			peers[1].AllowedIPs = append(peers[1].AllowedIPs, passthroughZoned)
			return peers
		}, passthroughZoned)
	})
	t.Run("trusted Endpoint in another case", func(t *testing.T) {
		elementTrustReject(t, "Endpoint", 1, func(peers []Peer) []Peer {
			peers[1].Endpoint = "0X7f.0.0.1:51820"
			return peers
		}, "0X7f")
	})
	t.Run("new PublicKey loses trust in the legacy Endpoint", func(t *testing.T) {
		elementTrustReject(t, "Endpoint", 0, func(peers []Peer) []Peer {
			peers[0].PublicKey = keyTablet
			peers[0].AllowedIPs = []string{"10.0.0.2/32"}
			peers[0].Extra = nil
			return peers
		}, "010.0.0.1")
	})
}

func TestWritePeersTrustsExistingNameAndPublicKeyOnlyOnTheirPeer(t *testing.T) {
	want := []Peer{
		{Name: trustLegacyName, PublicKey: keyPhone, AllowedIPs: []string{"10.0.0.2/32"}},
		{Name: "laptop", PublicKey: trustLegacyKey, AllowedIPs: []string{"10.0.0.3/32"}},
	}

	t.Run("control unchanged write", func(t *testing.T) {
		path, iface, peers := passthroughSetup(t, trustLegacy, want)
		passthroughWrite(t, path, iface, peers)
	})
	t.Run("Endpoint edited beside the legacy Name", func(t *testing.T) {
		path, iface, peers := passthroughSetup(t, trustLegacy, want)
		peers[0].Endpoint = "vpn.example.org:51820"
		passthroughWrite(t, path, iface, peers)
	})
	t.Run("legacy Name copied into a new peer", func(t *testing.T) {
		path, iface, peers := passthroughSetup(t, trustLegacy, want)
		peers = append(peers, Peer{Name: trustLegacyName, PublicKey: keyTablet, AllowedIPs: []string{"10.0.0.6/32"}})
		passthroughReject(t, path, iface, peers, "Name", 2, "\x1b", trustLegacyKey)
	})
	t.Run("legacy PublicKey peer renamed", func(t *testing.T) {
		path, iface, peers := passthroughSetup(t, trustLegacy, want)
		peers[1].Name = "laptop2"
		passthroughWrite(t, path, iface, peers)
	})
	t.Run("legacy PublicKey passed twice", func(t *testing.T) {
		path, iface, peers := passthroughSetup(t, trustLegacy, want)
		a, b := peers[1], peers[1]
		a.Name, b.Name = "a", "b"
		passthroughReject(t, path, iface, []Peer{a, b}, "PublicKey", 1, trustLegacyKey, keyLaptop)
	})
}

func TestWritePeersKeepsSectionBytesAtSpanEdges(t *testing.T) {
	t.Run("span at end of file without a newline", func(t *testing.T) {
		path, iface, peers := passthroughSetup(t, spanEOF, []Peer{passthroughLegacyPhone})
		passthroughFixpoint(t, path, iface, peers)
	})
	t.Run("unnamed peer after a trailing comment without a newline", func(t *testing.T) {
		phone := passthroughLegacyPhone
		phone.Extra = []string{"# roams"}
		path, iface, peers := passthroughSetup(t, spanEOF+"\n# roams", []Peer{phone})
		passthroughFixpoint(t, path, iface, append(peers, spanTablet()))
	})
	t.Run("blank lines and a comment inside the span", func(t *testing.T) {
		midSpan := "[Peer]\nPublicKey = " + keyPhone + "\n\n# mid\n\nAllowedIPs = 10.0.0.2/32\nEndpoint = 010.0.0.1:51820\n"
		phone := passthroughLegacyPhone
		phone.Extra = []string{"# mid"}
		laptop := Peer{Name: "laptop", PublicKey: keyLaptop, AllowedIPs: []string{"10.0.0.4/32"}}
		content := passthroughIface + "\n\n# phone\n" + midSpan + "\n# laptop\n[Peer]\nPublicKey = " + keyLaptop + "\nAllowedIPs = 10.0.0.4/32\n"
		path, iface, peers := passthroughSetup(t, content, []Peer{phone, laptop})
		passthroughAssertContains(t, passthroughFixpoint(t, path, iface, peers), "\n# phone\n"+midSpan)
	})
	headerOnly := passthroughOneK + "\n[Peer]"
	t.Run("header-only last peer [Peer] unchanged", func(t *testing.T) {
		path, iface, peers := passthroughSetup(t, headerOnly, []Peer{passthroughLegacyPhone, {}})
		passthroughFixpoint(t, path, iface, peers)
	})
	t.Run("header-only last peer [Peer] renamed", func(t *testing.T) {
		path, iface, peers := passthroughSetup(t, headerOnly, []Peer{passthroughLegacyPhone, {}})
		peers[1].Name = "ghost2"
		passthroughReject(t, path, iface, peers, "PublicKey", 1)
	})
	t.Run("control PublicKey with an inline comment unchanged", func(t *testing.T) {
		path, iface, peers := passthroughSetup(t, passthroughIface+"\n\n# phone\n"+spanInlineComment, []Peer{passthroughLegacyPhone})
		passthroughAssertContains(t, passthroughFixpoint(t, path, iface, peers), "\n# phone\n"+spanInlineComment)
	})
}

func keylessSetup(t *testing.T) (string, string, []Peer) {
	t.Helper()
	path := writeTempConfig(t, passthroughKeyless)
	iface, peers := passthroughParse(t, path)
	if len(peers) != 2 || peers[0].PublicKey != "" {
		t.Fatalf("fixture parsed to %+v, want a keyless ghost and laptop", peers)
	}
	return path, iface, passthroughClone(peers)
}

func TestWritePeersTrustsAKeylessSectionOnlyWhenUnchanged(t *testing.T) {
	t.Run("control unchanged keyless section is written verbatim", func(t *testing.T) {
		path, iface, peers := keylessSetup(t)
		out := passthroughWrite(t, path, iface, peers)
		if !strings.Contains(out, "\n# ghost\n"+passthroughKeylessSpan) {
			t.Errorf("keyless section not written verbatim:\n%q", out)
		}
	})
	t.Run("edited keyless section gets no trust", func(t *testing.T) {
		path, iface, peers := keylessSetup(t)
		peers[0].AllowedIPs = append(peers[0].AllowedIPs, "10.0.0.8/32")
		passthroughReject(t, path, iface, peers, "PublicKey", 0)
	})
}

func TestWritePeersBacksEachPeerWithOneUnusedOriginal(t *testing.T) {
	t.Run("control unchanged legacy peer plus a valid duplicate", func(t *testing.T) {
		path, iface, peers := passthroughSetup(t, passthroughOneK, nil)
		out := passthroughWrite(t, path, iface, append(peers, passthroughDupK))
		if !strings.Contains(out, "\n"+passthroughLegacyEndpointSection) {
			t.Errorf("legacy section not written verbatim:\n%q", out)
		}
	})
	t.Run("renamed legacy peer before the unchanged duplicate", func(t *testing.T) {
		path, iface, peers := passthroughSetup(t, passthroughTwoK, nil)
		if len(peers) != 2 || !passthroughSamePeers(peers[1:], []Peer{passthroughDupK}) {
			t.Fatalf("fixture parsed to %+v, want the legacy peer and %+v", peers, passthroughDupK)
		}
		peers[0].Name = "phone-old"
		out := passthroughWrite(t, path, iface, peers)
		if !strings.Contains(out, passthroughWriterSection(peers[0])) {
			t.Errorf("renamed legacy peer is not in writer format:\n%q", out)
		}
	})
	t.Run("two renamed peers share one legacy original", func(t *testing.T) {
		path, iface, peers := passthroughSetup(t, passthroughOneK, nil)
		a, b := peers[0], peers[0]
		a.Name, b.Name = "a", "b"
		passthroughReject(t, path, iface, []Peer{a, b}, "Endpoint", 1, "010.0.0.1")
	})
	t.Run("unchanged legacy peer passed twice", func(t *testing.T) {
		path, iface, peers := passthroughSetup(t, passthroughOneK, nil)
		passthroughReject(t, path, iface, []Peer{peers[0], peers[0]}, "Endpoint", 1, "010.0.0.1")
	})
	t.Run("both legacy originals with one key renamed", func(t *testing.T) {
		path, iface, peers := passthroughSetup(t, passthroughTwoLegacy, nil)
		peers[0].Name, peers[1].Name = "a", "b"
		passthroughReject(t, path, iface, peers, "Endpoint", 0, "010.0.0.1", "010.0.0.5")
	})
	t.Run("control equal originals with different bytes both kept", func(t *testing.T) {
		path, iface, peers := passthroughSetup(t, passthroughSame, []Peer{passthroughSamePeer, passthroughSamePeer})
		out := passthroughFixpoint(t, path, iface, peers)
		passthroughAssertContains(t, out, "\n"+passthroughSameA)
		passthroughAssertContains(t, out, "\n"+passthroughSameB)
	})
	t.Run("only the legacy peer of two", func(t *testing.T) {
		path, iface, peers := passthroughSetup(t, passthroughTwoK, nil)
		out := passthroughWrite(t, path, iface, peers[:1])
		if strings.Contains(out, "phone2") {
			t.Errorf("dropped duplicate is still in the file:\n%q", out)
		}
	})
}

func TestPassthroughNameCommentStaysWithNextPeer(t *testing.T) {
	path := writeTempConfig(t, passthroughNextName)
	iface, peers := passthroughParse(t, path)
	want := []Peer{
		{PublicKey: keyPhone, AllowedIPs: []string{"10.0.0.2/32"}, Endpoint: "010.0.0.1:1", Extra: []string{"# note"}},
		{Name: "next", PublicKey: keyLaptop, AllowedIPs: []string{"10.0.0.3/32"}},
	}
	if !passthroughSamePeers(peers, want) {
		t.Fatalf("fixture parsed to %+v, want %+v", peers, want)
	}

	t.Run("unchanged write", func(t *testing.T) {
		out := passthroughWrite(t, path, iface, peers)
		if n := strings.Count(out, "# next"); n != 1 {
			t.Errorf("# next occurs %d times, want 1:\n%q", n, out)
		}
	})
}

func TestWritePeersTrustsOnlyTheRegularFileCurrentlyAtPath(t *testing.T) {
	valid, legacy := passthroughValidLaptop, passthroughLegacyPhone

	t.Run("control nonexistent path with a valid peer", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "wg0.conf")
		passthroughWrite(t, path, passthroughIface, []Peer{valid})
	})
	t.Run("path is a directory", func(t *testing.T) {
		parent := t.TempDir()
		path := filepath.Join(parent, "wg0.conf")
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		err := WritePeers(path, passthroughIface, []Peer{valid})
		if err == nil {
			t.Fatal("WritePeers onto a directory succeeded, want error")
		}
		if msg := err.Error(); strings.Contains(msg, "temp file") || strings.Contains(msg, "rename") {
			t.Errorf("error = %q, want the stat or read error before any temp file", msg)
		}
		if names := passthroughDirNames(t, parent); !slices.Equal(names, []string{"wg0.conf"}) {
			t.Errorf("parent holds %q, want only wg0.conf", names)
		}
		if info, statErr := os.Stat(path); statErr != nil || !info.IsDir() {
			t.Errorf("directory target changed (stat: %v)", statErr)
		}
		for _, k := range fixtureKeys {
			if strings.Contains(err.Error(), k) {
				t.Errorf("error %q echoes key %s", err, k)
			}
		}
	})
	t.Run("unreadable file", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("os.Chmod cannot remove read access on Windows")
		}
		path := writeTempConfig(t, passthroughLaptopOnly)
		if err := os.Chmod(path, 0); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
		if _, err := os.ReadFile(path); err == nil {
			t.Skip("file stays readable at mode 0 (running as root)")
		}
		dirBefore := passthroughDirNames(t, filepath.Dir(path))
		err := WritePeers(path, passthroughIface, []Peer{valid})
		if err == nil {
			t.Fatal("WritePeers over an unreadable file succeeded, want error")
		}
		if dirAfter := passthroughDirNames(t, filepath.Dir(path)); !slices.Equal(dirAfter, dirBefore) {
			t.Errorf("dir holds %q after the failed write, want %q", dirAfter, dirBefore)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatalf("chmod back: %v", err)
		}
		if got, readErr := os.ReadFile(path); readErr != nil || string(got) != passthroughLaptopOnly {
			t.Errorf("failed write changed the file (read: %v):\n%s", readErr, got)
		}
	})
	t.Run("nonexistent path with a legacy value", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "wg0.conf")
		passthroughReject(t, path, passthroughIface, []Peer{legacy}, "Endpoint", 0, "010.0.0.1")
	})
	t.Run("legacy Endpoint replaced on disk since the parse", func(t *testing.T) {
		path, iface, peers := passthroughSetup(t, passthroughOneK, nil)
		edited := strings.Replace(passthroughOneK, "010.0.0.1:51820", "vpn.example.org:51820", 1)
		if err := os.WriteFile(path, []byte(edited), 0o600); err != nil {
			t.Fatalf("rewrite config: %v", err)
		}
		passthroughReject(t, path, iface, peers, "Endpoint", 0, "010.0.0.1")
	})
	t.Run("unparsable current file yields no originals", func(t *testing.T) {
		path := writeTempConfig(t, passthroughOneK+"[Interface]\nPostUp = id\n")
		passthroughReject(t, path, passthroughIface, []Peer{legacy}, "Endpoint", 0, "010.0.0.1", "PostUp", "Interface")
	})
	t.Run("symlink to a regular file", func(t *testing.T) {
		target := writeTempConfig(t, passthroughOneK)
		link := filepath.Join(t.TempDir(), "link.conf")
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		iface, peers := passthroughParse(t, link)
		passthroughWrite(t, link, iface, peers)
	})
}

func TestPassthroughAppendPeerStaysStrict(t *testing.T) {
	t.Run("control valid peer appends", func(t *testing.T) {
		path := writeTempConfig(t, passthroughOneK)
		_, peers := passthroughParse(t, path)
		added := Peer{Name: "laptop", PublicKey: keyLaptop, AllowedIPs: []string{"10.0.0.4/32"}}
		if err := AppendPeer(path, added); err != nil {
			t.Fatalf("AppendPeer rejected, want success: %v", err)
		}
		if _, got := passthroughParse(t, path); !passthroughSamePeers(got, append(peers, added)) {
			t.Errorf("parsed back %+v, want %+v", got, append(peers, added))
		}
	})
	t.Run("peer already in the file with a legacy value", func(t *testing.T) {
		path := writeTempConfig(t, passthroughOneK)
		_, peers := passthroughParse(t, path)
		passthroughAssertRejected(t, path, func() error { return AppendPeer(path, peers[0]) }, "Endpoint", -1, "010.0.0.1")
	})
}

func TestPassthroughExtraKeyLineGetsNoTrust(t *testing.T) {
	setup := func(t *testing.T) (string, string, []Peer) {
		t.Helper()
		want := []Peer{{PublicKey: keyPhone, AllowedIPs: []string{"10.0.0.2/32"}, Extra: []string{"Public Key = " + keyTablet}}}
		return passthroughSetup(t, passthroughShadow, want)
	}

	t.Run("control unchanged is written verbatim", func(t *testing.T) {
		path, iface, peers := setup(t)
		out := passthroughWrite(t, path, iface, peers)
		if !strings.Contains(out, "\n"+passthroughShadowSpan) {
			t.Errorf("section not written verbatim:\n%q", out)
		}
	})
	t.Run("renamed", func(t *testing.T) {
		path, iface, peers := setup(t)
		peers[0].Name = "renamed"
		passthroughReject(t, path, iface, peers, "Extra", 0, keyTablet)
	})
	for _, c := range []struct{ label, line, value string }{
		{"upper-case allowed ips", "ALLOWED IPS = 0.0.0.0/0", "0.0.0.0/0"},
		{"split endpoint", "End point = 1.2.3.4:1", "1.2.3.4"},
		{"split preshared key", "Preshared Key = " + keyLeak, keyLeak},
		{"tab inside allowed ips", "Allowed\tIPs = 0.0.0.0/0", "0.0.0.0/0"},
	} {
		t.Run(c.label+" renamed", func(t *testing.T) {
			path, iface, peers := passthroughSetup(t, extraKeyContent(c.line), extraKeyPeers(c.line))
			peers[0].Name = "phone2"
			passthroughReject(t, path, iface, peers, "Extra", 0, c.value)
		})
	}
}
