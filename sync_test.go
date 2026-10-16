package wgconf

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
)

const (
	dumpIface = "privkey=\tIFACEPUB=\t51820\toff"
	dumpPeer1 = "PEER1=\t(none)\t203.0.113.7:51820\t10.0.0.2/32\t1700000000\t1234\t5678\toff"
	dumpPeer2 = "PEER2=\t(none)\t(none)\t10.0.0.3/32\t0\t0\t0\toff"

	// stubLogEnv names the file the stub wg and wg-quick append their calls to.
	stubLogEnv = "WGCONF_STUB_WG_LOG"

	stubStripped = "[Interface]\nListenPort = 51820\n\n[Peer]\nPublicKey = PEER1=\nAllowedIPs = 10.0.0.2/32\n"
	stubDump     = dumpIface + "\n" + dumpPeer1 + "\n" + dumpPeer2 + "\n"
)

type stubCall struct {
	Args  []string
	Stdin string `json:",omitempty"`
}

var (
	stubOnce sync.Once
	stubDir  string
	stubErr  error
)

// TestMain runs the test binary as wg or wg-quick when the stub log variable is set.
func TestMain(m *testing.M) {
	if logPath := os.Getenv(stubLogEnv); logPath != "" {
		os.Exit(runStubWG(logPath))
	}
	code := m.Run()
	if stubDir != "" {
		os.RemoveAll(stubDir)
	}
	os.Exit(code)
}

func runStubWG(logPath string) int {
	tool := strings.TrimSuffix(filepath.Base(os.Args[0]), ".exe")
	args := os.Args[1:]
	call := stubCall{Args: append([]string{tool}, args...)}
	out, code := "", 0
	switch {
	case tool == "wg-quick" && len(args) == 2 && args[0] == "strip":
		out = stubStripped
	case tool == "wg" && len(args) == 3 && args[0] == "syncconf":
		in, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "stub wg: read stdin: %v\n", err)
			code = 1
		}
		call.Stdin = string(in)
	case tool == "wg" && len(args) == 3 && args[0] == "show" && args[2] == "dump":
		out = stubDump
	default:
		fmt.Fprintf(os.Stderr, "stub %s: unexpected arguments %q\n", tool, args)
		code = 1
	}

	line, err := json.Marshal(call)
	if err != nil {
		fmt.Fprintf(os.Stderr, "stub %s: %v\n", tool, err)
		return 1
	}
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "stub %s: %v\n", tool, err)
		return 1
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		f.Close()
		fmt.Fprintf(os.Stderr, "stub %s: %v\n", tool, err)
		return 1
	}
	if err := f.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "stub %s: %v\n", tool, err)
		return 1
	}
	fmt.Print(out)
	return code
}

// installStubWG copies the test binary into a new directory as wg and wg-quick.
func installStubWG() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	bin, err := os.ReadFile(exe)
	if err != nil {
		return "", err
	}
	dir, err := os.MkdirTemp("", "wgconf-stub-wg-")
	if err != nil {
		return "", err
	}
	suffix := ""
	if runtime.GOOS == "windows" {
		suffix = ".exe"
	}
	for _, name := range []string{"wg", "wg-quick"} {
		if err := os.WriteFile(filepath.Join(dir, name+suffix), bin, 0o755); err != nil {
			return dir, err
		}
	}
	return dir, nil
}

// useStubWG puts the stub wg and wg-quick first on PATH and returns the file their calls go to.
func useStubWG(t *testing.T) string {
	t.Helper()
	stubOnce.Do(func() { stubDir, stubErr = installStubWG() })
	if stubErr != nil {
		t.Fatalf("install stub wg: %v", stubErr)
	}
	t.Setenv("PATH", stubDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	for _, name := range []string{"wg", "wg-quick"} {
		if p, err := exec.LookPath(name); err != nil || filepath.Dir(p) != stubDir {
			t.Fatalf("%s resolves to %q (err %v), want the stub in %s", name, p, err, stubDir)
		}
	}
	logPath := filepath.Join(t.TempDir(), "wg-calls.log")
	t.Setenv(stubLogEnv, logPath)
	return logPath
}

func stubCalls(t *testing.T, logPath string) []stubCall {
	t.Helper()
	data, err := os.ReadFile(logPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatalf("read stub log: %v", err)
	}
	var calls []stubCall
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var c stubCall
		if err := json.Unmarshal([]byte(line), &c); err != nil {
			t.Fatalf("decode stub log line %q: %v", line, err)
		}
		calls = append(calls, c)
	}
	return calls
}

func assertDump(t *testing.T, dump string, wantPort int, wantPeers []PeerStatus) {
	t.Helper()
	got, err := parseDump("wg0", []byte(dump))
	if err != nil {
		t.Fatalf("parseDump: %v", err)
	}
	if got.Interface.PublicKey != "IFACEPUB=" || got.Interface.ListenPort != wantPort {
		t.Errorf("interface = %+v, want pub IFACEPUB= port %d", got.Interface, wantPort)
	}
	if len(got.Peers) != len(wantPeers) {
		t.Fatalf("got %d peers, want %d: %+v", len(got.Peers), len(wantPeers), got.Peers)
	}
	for i, want := range wantPeers {
		if got.Peers[i] != want {
			t.Errorf("peer %d = %+v, want %+v", i, got.Peers[i], want)
		}
	}
	if len(wantPeers) == 0 {
		b, err := json.Marshal(got)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if !strings.Contains(string(b), `"peers":[]`) {
			t.Errorf("json = %s, want it to contain \"peers\":[]", b)
		}
	}
}

func TestShowInterfaceParsesDump(t *testing.T) {
	tests := []struct {
		name      string
		dump      string
		wantPort  int
		wantPeers []PeerStatus
	}{
		{
			name:     "captured dump with two peers",
			dump:     stubDump,
			wantPort: 51820,
			wantPeers: []PeerStatus{
				{PublicKey: "PEER1=", Endpoint: "203.0.113.7:51820", LatestHandshake: 1700000000, TransferRx: 1234, TransferTx: 5678},
				{PublicKey: "PEER2=", Endpoint: ""},
			},
		},
		{
			name:      "peer line with fewer than 7 fields is skipped",
			dump:      dumpIface + "\nSHORT=\t(none)\t1.2.3.4:1\t10.0.0.9/32\t0\t0\n" + dumpPeer1,
			wantPort:  51820,
			wantPeers: []PeerStatus{{PublicKey: "PEER1=", Endpoint: "203.0.113.7:51820", LatestHandshake: 1700000000, TransferRx: 1234, TransferTx: 5678}},
		},
		{
			name:      "interface only",
			dump:      dumpIface + "\n",
			wantPort:  51820,
			wantPeers: []PeerStatus{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertDump(t, tc.dump, tc.wantPort, tc.wantPeers)
		})
	}
}

func TestSyncInterfacePipesStrippedConfigIntoSyncconf(t *testing.T) {
	logPath := useStubWG(t)
	if err := SyncInterface("wg0"); err != nil {
		t.Fatalf("SyncInterface: %v", err)
	}
	want := []stubCall{
		{Args: []string{"wg-quick", "strip", "wg0"}},
		{Args: []string{"wg", "syncconf", "wg0", "/dev/stdin"}, Stdin: stubStripped},
	}
	if got := stubCalls(t, logPath); !reflect.DeepEqual(got, want) {
		t.Errorf("calls = %+v, want %+v", got, want)
	}
}
