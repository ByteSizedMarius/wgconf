package wgconf

import (
	"fmt"
	"os"
	"strings"
)

// A "# Key = Value" comment with one of these keys is metadata, never a peer name.
var metadataKeys = map[string]bool{
	"RoutingMode":   true,
	"IPv4Interface": true,
}

// ParsePeers reads a WireGuard config file and parses it like ParsePeersFromString.
func ParsePeers(path string) (interfaceBlock string, peers []Peer, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", nil, fmt.Errorf("read config: %w", err)
	}
	return ParsePeersFromString(string(data))
}

// ParsePeersFromString parses WireGuard config content.
// interfaceBlock holds the [Interface] section and any lines before it, verbatim and without trailing blank lines.
// A bare comment directly above a [Peer] header becomes that peer's Name and appears nowhere else.
// An [Interface] header after a [Peer] header, or a NUL byte anywhere, is an error.
func ParsePeersFromString(content string) (interfaceBlock string, peers []Peer, err error) {
	interfaceBlock, peers, _, err = parse(content)
	return interfaceBlock, peers, err
}

// parse is ParsePeersFromString plus each peer's section text from its [Peer] header on, without the next peer's name comment and trailing blank lines.
func parse(content string) (interfaceBlock string, peers []Peer, spans []string, err error) {
	if i := strings.IndexByte(content, 0); i >= 0 {
		return "", nil, nil, fmt.Errorf("line %d: NUL byte", strings.Count(content[:i], "\n")+1)
	}
	lines := strings.Split(content, "\n")
	join := func(from, to int) string {
		for to > from && strings.TrimSpace(lines[to-1]) == "" {
			to--
		}
		return strings.Join(lines[from:to], "\n")
	}
	var currentPeer *Peer
	// start is the header line of currentPeer.
	var start int
	// pending is a name comment on the previous line.
	var pending string

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		head := header(line)

		if strings.EqualFold(head, "[Peer]") {
			end := i
			if pending != "" {
				end--
			}
			if currentPeer == nil {
				interfaceBlock = join(0, end)
			} else {
				peers = append(peers, *currentPeer)
				spans = append(spans, join(start, end)+"\n")
			}
			currentPeer = &Peer{Name: commentName(pending)}
			start = i
			pending = ""
			continue
		}

		if currentPeer == nil {
			pending = ""
			if commentName(trimmed) != "" {
				pending = trimmed
			}
			continue
		}

		if pending != "" {
			currentPeer.Extra = append(currentPeer.Extra, pending)
			pending = ""
		}

		switch {
		case trimmed == "":
		case strings.EqualFold(head, "[Interface]"):
			return "", nil, nil, fmt.Errorf("line %d: [Interface] header after a [Peer] section", i+1)
		case commentName(trimmed) != "":
			pending = trimmed
		case strings.HasPrefix(trimmed, "#"):
			currentPeer.Extra = append(currentPeer.Extra, trimmed)
		default:
			parsePeerLine(currentPeer, trimmed)
		}
	}

	if currentPeer == nil {
		return join(0, len(lines)), nil, nil, nil
	}
	if pending != "" {
		currentPeer.Extra = append(currentPeer.Extra, pending)
	}
	peers = append(peers, *currentPeer)
	spans = append(spans, join(start, len(lines))+"\n")
	return interfaceBlock, peers, spans, nil
}

// wg compares section headers after cutting the line at '#' and removing its whitespace.
func header(line string) string {
	before, _, _ := strings.Cut(line, "#")
	return strings.Join(strings.Fields(before), "")
}

// commentName returns the text of a non-empty, non-metadata comment line, or "" for any other line.
func commentName(trimmed string) string {
	comment, ok := strings.CutPrefix(trimmed, "#")
	if !ok {
		return ""
	}
	comment = strings.TrimSpace(comment)
	if isMetadata(comment) {
		return ""
	}
	return comment
}

func isMetadata(s string) bool {
	key, _ := ParseKeyValue(s)
	for k := range metadataKeys {
		if strings.EqualFold(key, k) {
			return true
		}
	}
	return false
}

func parsePeerLine(p *Peer, trimmed string) {
	kv, _, _ := strings.Cut(trimmed, "#")
	key, val := ParseKeyValue(kv)
	switch strings.ToLower(key) {
	case "publickey":
		p.PublicKey = val
	case "presharedkey":
		p.PresharedKey = val
	case "allowedips":
		for _, ip := range strings.Split(val, ",") {
			if ip = strings.TrimSpace(ip); ip != "" {
				p.AllowedIPs = append(p.AllowedIPs, ip)
			}
		}
	case "endpoint":
		p.Endpoint = val
	default:
		p.Extra = append(p.Extra, trimmed)
	}
}

// ParseKeyValue splits a "Key = Value" line.
func ParseKeyValue(line string) (key, value string) {
	parts := strings.SplitN(line, "=", 2)
	if len(parts) != 2 {
		return "", ""
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
}
