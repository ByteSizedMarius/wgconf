package wgconf

import (
	"encoding/base64"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

// Errors leave out field values because some are private keys.

// orig is p's section in the current config file.
func validatePeer(p Peer, orig *Peer) error {
	var o Peer
	if orig != nil {
		o = *orig
	}
	kept := func(v, ov string) bool { return orig != nil && v == ov }
	checkIP := func(ip string) bool { return slices.Contains(o.AllowedIPs, ip) || validIP(ip) }
	checkExtra := func(line string) bool {
		// Kept Extra lines move below the modelled keys.
		return (slices.Contains(o.Extra, line) && !setsModelledKey(line)) || validExtra(line)
	}
	switch {
	case !kept(p.Name, o.Name) && !validName(p.Name):
		return errors.New("invalid Name")
	case !kept(p.PublicKey, o.PublicKey) && !validKey(p.PublicKey):
		return errors.New("invalid PublicKey")
	case p.PresharedKey != "" && !kept(p.PresharedKey, o.PresharedKey) && !validKey(p.PresharedKey):
		return errors.New("invalid PresharedKey")
	case !all(p.AllowedIPs, checkIP):
		return errors.New("invalid AllowedIPs")
	case p.Endpoint != "" && !kept(p.Endpoint, o.Endpoint) && !validEndpoint(p.Endpoint):
		return errors.New("invalid Endpoint")
	case !all(p.Extra, checkExtra):
		return errors.New("invalid Extra")
	}
	return nil
}

func setsModelledKey(line string) bool {
	key, _, ok := strings.Cut(line, "=")
	if !ok {
		return false
	}
	switch strings.ToLower(strings.Join(strings.Fields(key), "")) {
	case "publickey", "presharedkey", "allowedips", "endpoint":
		return true
	}
	return false
}

func validateClientConfig(c ClientConfigParams) error {
	switch {
	case !validName(c.Name):
		return errors.New("invalid Name")
	case !validKey(c.PrivateKey):
		return errors.New("invalid PrivateKey")
	case !validList(c.Address, validIP):
		return errors.New("invalid Address")
	case c.DNS != "" && !validList(c.DNS, validHost):
		return errors.New("invalid DNS")
	case !validKey(c.ServerPubKey):
		return errors.New("invalid ServerPubKey")
	case !validEndpoint(c.ServerEndpoint):
		return errors.New("invalid ServerEndpoint")
	case !validList(c.AllowedIPs, validIP):
		return errors.New("invalid AllowedIPs")
	case c.PresharedKey != "" && !validKey(c.PresharedKey):
		return errors.New("invalid PresharedKey")
	}
	return nil
}

// singleLine reports whether s has no control rune other than tab and no Unicode line or paragraph separator.
func singleLine(s string) bool {
	return !strings.ContainsFunc(s, func(r rune) bool {
		return (unicode.IsControl(r) && r != '\t') || r == '\u2028' || r == '\u2029'
	})
}

// validName accepts only names that parse back as the same Name from their "# name" line.
func validName(s string) bool {
	return singleLine(s) && strings.TrimSpace(s) == s && !isMetadata(s)
}

func validKey(s string) bool {
	if !singleLine(s) {
		return false
	}
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	return err == nil && len(b) == 32
}

func validIP(s string) bool {
	if !singleLine(s) {
		return false
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Addr().Zone() == ""
	}
	addr, err := netip.ParseAddr(s)
	return err == nil && addr.Zone() == ""
}

func validEndpoint(s string) bool {
	if !singleLine(s) {
		return false
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return false
	}
	n, err := strconv.ParseUint(port, 10, 16)
	return err == nil && n > 0 && validHost(host)
}

func validHost(s string) bool {
	if !singleLine(s) {
		return false
	}
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr.Zone() == ""
	}
	s = strings.TrimSuffix(s, ".")
	if len(s) > 253 {
		return false
	}
	labels := strings.Split(s, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' || strings.ContainsFunc(l, notLabelRune) {
			return false
		}
	}
	// glibc getaddrinfo resolves 010.0.0.1 to 8.0.0.1, and 0x7f.0.0.1, 0x7f000001 and 127.0x1 to 127.0.0.1.
	last := strings.ToLower(labels[len(labels)-1])
	if digits, ok := strings.CutPrefix(last, "0x"); ok && strings.Trim(digits, "0123456789abcdef") == "" {
		return false
	}
	return strings.ContainsFunc(last, isLetter)
}

func notLabelRune(r rune) bool {
	return !isLetter(r) && !('0' <= r && r <= '9') && r != '_' && r != '-'
}

func isLetter(r rune) bool {
	return ('a' <= r && r <= 'z') || ('A' <= r && r <= 'Z')
}

// validExtra reports whether line is a comment or a PersistentKeepalive line.
func validExtra(line string) bool {
	if !singleLine(line) {
		return false
	}
	// wg strips only ASCII whitespace.
	line = strings.Trim(line, " \t")
	if strings.HasPrefix(line, "#") {
		return true
	}
	setting, _, _ := strings.Cut(line, "#")
	key, value, ok := strings.Cut(setting, "=")
	if !ok || lowerASCII(strings.Trim(key, " \t")) != "persistentkeepalive" {
		return false
	}
	value = strings.Trim(value, " \t")
	if lowerASCII(value) == "off" {
		return true
	}
	_, err := strconv.ParseUint(value, 10, 16)
	return err == nil
}

// Unlike strings.ToLower, this leaves U+212A (Kelvin sign) as is.
func lowerASCII(s string) string {
	return strings.Map(func(r rune) rune {
		if 'A' <= r && r <= 'Z' {
			return r + 'a' - 'A'
		}
		return r
	}, s)
}

func validList(s string, valid func(string) bool) bool {
	return all(strings.Split(s, ","), func(e string) bool { return valid(strings.Trim(e, " \t")) })
}

func all(values []string, valid func(string) bool) bool {
	for _, v := range values {
		if !valid(v) {
			return false
		}
	}
	return true
}
