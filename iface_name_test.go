package wgconf

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// validIfaceName is 15 characters and holds every punctuation character an interface name allows.
const validIfaceName = "wgconf_t.e-s+t="

var ifaceCommands = []struct {
	name string
	run  func(iface string) error
}{
	{"SyncInterface", SyncInterface},
	{"ShowInterface", func(iface string) error {
		_, err := ShowInterface(iface)
		return err
	}},
}

// assertIfaceAccepted runs a command on name under the stub wg and requires it to reach wg with that name.
func assertIfaceAccepted(t *testing.T, run func(string) error, name string) {
	t.Helper()
	logPath := useStubWG(t)
	if err := run(name); err != nil {
		t.Fatalf("%q rejected: %v", name, err)
	}
	if calls := stubCalls(t, logPath); len(calls) == 0 || !slices.Contains(calls[0].Args, name) {
		t.Errorf("calls = %+v, want a wg call for %q", calls, name)
	}
}

// assertIfaceRejected runs a command on name under the stub wg and requires ErrInvalidInterfaceName, without the name in its text and with no wg call.
func assertIfaceRejected(t *testing.T, run func(string) error, name string) {
	t.Helper()
	logPath := useStubWG(t)
	err := run(name)
	if !errors.Is(err, ErrInvalidInterfaceName) {
		t.Errorf("%q: err = %v, want ErrInvalidInterfaceName", name, err)
	}
	if name != "" && err != nil && strings.Contains(err.Error(), name) {
		t.Errorf("%q: error %q contains the rejected name", name, err)
	}
	if calls := stubCalls(t, logPath); len(calls) != 0 {
		t.Errorf("%q ran %+v before it was rejected", name, calls)
	}
}

var invalidIfaceNames = []struct{ label, name string }{
	{"empty", ""},
	{"wg show keyword all", "all"},
	{"wg show keyword interfaces", "interfaces"},
	{"16 characters", validIfaceName + "x"},
	{"path", "/root/x.conf"},
}

func TestInterfaceCommandsRejectInvalidNames(t *testing.T) {
	for _, c := range ifaceCommands {
		t.Run(c.name+"/control 15-character name", func(t *testing.T) {
			assertIfaceAccepted(t, c.run, validIfaceName)
		})
		t.Run(c.name+"/leading hyphen", func(t *testing.T) {
			assertIfaceRejected(t, c.run, "-h")
		})
	}
	show := ifaceCommands[1]
	for _, r := range invalidIfaceNames {
		t.Run(show.name+"/"+r.label, func(t *testing.T) {
			assertIfaceRejected(t, show.run, r.name)
		})
	}
}

// CWE-636: a nil ErrInvalidInterfaceName must not let a rejected name through.
func TestInterfaceCommandsRejectWithNilSentinel(t *testing.T) {
	saved := ErrInvalidInterfaceName
	ErrInvalidInterfaceName = nil
	t.Cleanup(func() { ErrInvalidInterfaceName = saved })

	for _, c := range ifaceCommands {
		assertIfaceAccepted(t, c.run, validIfaceName)
	}
	logPath := useStubWG(t)
	if err := SyncInterface("-h"); err == nil {
		t.Error("SyncInterface(\"-h\") = nil, want an error")
	}
	if _, err := ShowInterface("all"); err == nil {
		t.Error("ShowInterface(\"all\") = nil error, want an error")
	}
	if calls := stubCalls(t, logPath); len(calls) != 0 {
		t.Errorf("rejected names reached wg: %+v", calls)
	}
}
