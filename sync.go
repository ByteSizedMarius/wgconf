package wgconf

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// ErrInvalidInterfaceName is the error SyncInterface and ShowInterface return for a name they refuse to pass to wg.
var ErrInvalidInterfaceName error = ifaceNameError{}

// Reassigning ErrInvalidInterfaceName cannot switch off the name check.
type ifaceNameError struct{}

func (ifaceNameError) Error() string { return "invalid interface name" }

// ifaceNamePattern matches the names wg-quick resolves to /etc/wireguard/<name>.conf.
var ifaceNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_=+.-]{1,15}$`)

func checkIfaceName(name string) error {
	// all and interfaces are wg show keywords.
	if !ifaceNamePattern.MatchString(name) || name[0] == '-' || name == "all" || name == "interfaces" {
		return ifaceNameError{}
	}
	return nil
}

// SyncInterface applies the interface's config file to the running interface without disrupting current peer sessions.
func SyncInterface(name string) error {
	if err := checkIfaceName(name); err != nil {
		return err
	}
	stripCmd := exec.Command("wg-quick", "strip", name)
	strippedConfig, err := stripCmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return fmt.Errorf("wg-quick strip %s: %s: %w", name, strings.TrimSpace(string(ee.Stderr)), err)
		}
		return fmt.Errorf("wg-quick strip %s: %w", name, err)
	}

	syncCmd := exec.Command("wg", "syncconf", name, "/dev/stdin")
	syncCmd.Stdin = bytes.NewReader(strippedConfig)
	if out, err := syncCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("wg syncconf %s: %s: %w", name, strings.TrimSpace(string(out)), err)
	}
	return nil
}

// ShowInterface returns the live status that "wg show <name> dump" reports.
func ShowInterface(name string) (*InterfaceShow, error) {
	if err := checkIfaceName(name); err != nil {
		return nil, err
	}
	out, err := exec.Command("wg", "show", name, "dump").Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return nil, fmt.Errorf("wg show %s dump: %s: %w", name, strings.TrimSpace(string(ee.Stderr)), err)
		}
		return nil, fmt.Errorf("wg show %s dump: %w", name, err)
	}
	return parseDump(name, out)
}

// Line 1: private-key \t public-key \t listen-port \t fwmark
// Lines 2+: public-key \t preshared-key \t endpoint \t allowed-ips \t latest-handshake \t transfer-rx \t transfer-tx \t persistent-keepalive
func parseDump(name string, out []byte) (*InterfaceShow, error) {
	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" {
		return nil, fmt.Errorf("wg show %s dump: empty output", name)
	}

	lines := strings.Split(trimmed, "\n")
	ifFields := strings.Split(lines[0], "\t")
	if len(ifFields) < 3 {
		return nil, fmt.Errorf("wg show %s dump: unexpected interface line format", name)
	}

	port, _ := strconv.Atoi(ifFields[2])
	status := &InterfaceShow{
		Interface: InterfaceStatus{
			PublicKey:  ifFields[1],
			ListenPort: port,
		},
		Peers: []PeerStatus{},
	}

	for _, line := range lines[1:] {
		fields := strings.Split(line, "\t")
		if len(fields) < 7 {
			continue
		}

		endpoint := fields[2]
		if endpoint == "(none)" {
			endpoint = ""
		}

		handshake, _ := strconv.ParseInt(fields[4], 10, 64)
		rx, _ := strconv.ParseInt(fields[5], 10, 64)
		tx, _ := strconv.ParseInt(fields[6], 10, 64)

		status.Peers = append(status.Peers, PeerStatus{
			PublicKey:       fields[0],
			Endpoint:        endpoint,
			LatestHandshake: handshake,
			TransferRx:      rx,
			TransferTx:      tx,
		})
	}

	return status, nil
}
