// Package wgconf parses and writes WireGuard config files and manages live interfaces through the wg tools.
// Callers serialize ParsePeers, WritePeers and AppendPeer calls on one config file.
package wgconf

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

var renameFile = os.Rename

// WritePeers atomically replaces the file at path with interfaceBlock, written verbatim, followed by one section per peer.
// A peer equal to a section of the file keeps that section's lines.
// A value the file did not already hold for that peer must be one line of wg syntax, and a new Extra line must be a comment or a PersistentKeepalive line.
func WritePeers(path, interfaceBlock string, peers []Peer) error {
	originals, spans, err := readOriginals(path)
	if err != nil {
		return err
	}
	copies, backing := matchOriginals(peers, originals, spans)
	var sb strings.Builder
	sb.WriteString(interfaceBlock)
	sb.WriteString("\n")
	for i, p := range peers {
		if copies[i] != "" {
			sb.WriteString(sectionHead(p.Name))
			sb.WriteString(copies[i])
			continue
		}
		section, err := peerSection(p, backing[i])
		if err != nil {
			return fmt.Errorf("peer %d: %w", i, err)
		}
		sb.WriteString(section)
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".wg-conf-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()

	if _, err := tmp.WriteString(sb.String()); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := renameFile(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

func readOriginals(path string) ([]Peer, []string, error) {
	info, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("read config: %w", err)
	}
	// os.Open blocks on a FIFO that has no writer.
	if !info.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("read config: %s is not a regular file", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read config: %w", err)
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, nil, fmt.Errorf("read config: %w", err)
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, nil, fmt.Errorf("read config: %s is not a regular file", path)
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, nil, fmt.Errorf("read config: %w", err)
	}
	_, peers, spans, err := parse(string(data))
	if err != nil {
		// A file the parser rejects backs no peer.
		return nil, nil, nil
	}
	return peers, spans, nil
}

// matchOriginals gives a peer the span of an equal unused original, or else backs it with the only unused original holding its non-empty PublicKey.
func matchOriginals(peers, originals []Peer, spans []string) (copies []string, backing []*Peer) {
	copies = make([]string, len(peers))
	backing = make([]*Peer, len(peers))
	used := make([]bool, len(originals))
	for i, p := range peers {
		for j, o := range originals {
			if !used[j] && samePeer(p, o) {
				copies[i], used[j] = spans[j], true
				break
			}
		}
	}
	for i, p := range peers {
		if copies[i] != "" || p.PublicKey == "" {
			continue
		}
		match, n := -1, 0
		for j, o := range originals {
			if !used[j] && o.PublicKey == p.PublicKey {
				match, n = j, n+1
			}
		}
		if n == 1 {
			backing[i], used[match] = &originals[match], true
		}
	}
	return copies, backing
}

func samePeer(a, b Peer) bool {
	return a.Name == b.Name && a.PublicKey == b.PublicKey && a.PresharedKey == b.PresharedKey &&
		slices.Equal(a.AllowedIPs, b.AllowedIPs) && a.Endpoint == b.Endpoint && slices.Equal(a.Extra, b.Extra)
}

func sectionHead(name string) string {
	// The blank line keeps a comment above from becoming this peer's Name.
	head := "\n"
	if name != "" {
		head += "# " + name + "\n"
	}
	return head
}

func peerSection(p Peer, orig *Peer) (string, error) {
	if err := validatePeer(p, orig); err != nil {
		return "", err
	}
	var sb strings.Builder
	sb.WriteString(sectionHead(p.Name))
	sb.WriteString("[Peer]\n")
	sb.WriteString("PublicKey = ")
	sb.WriteString(p.PublicKey)
	sb.WriteString("\n")
	if p.PresharedKey != "" {
		sb.WriteString("PresharedKey = ")
		sb.WriteString(p.PresharedKey)
		sb.WriteString("\n")
	}
	sb.WriteString("AllowedIPs = ")
	sb.WriteString(strings.Join(p.AllowedIPs, ", "))
	sb.WriteString("\n")
	if p.Endpoint != "" {
		sb.WriteString("Endpoint = ")
		sb.WriteString(p.Endpoint)
		sb.WriteString("\n")
	}
	for _, line := range p.Extra {
		sb.WriteString(line)
		sb.WriteString("\n")
	}
	return sb.String(), nil
}

// GenerateClientConfig builds a complete WireGuard client configuration string.
// It rejects any field that is not one line of wg syntax, except an empty Name, DNS or PresharedKey.
func GenerateClientConfig(cfg ClientConfigParams) (string, error) {
	if err := validateClientConfig(cfg); err != nil {
		return "", err
	}
	var sb strings.Builder
	sb.WriteString("[Interface]\n")
	if cfg.Name != "" {
		sb.WriteString("# ")
		sb.WriteString(cfg.Name)
		sb.WriteString("\n")
	}
	sb.WriteString("PrivateKey = ")
	sb.WriteString(cfg.PrivateKey)
	sb.WriteString("\n")
	sb.WriteString("Address = ")
	sb.WriteString(cfg.Address)
	sb.WriteString("\n")
	if cfg.DNS != "" {
		sb.WriteString("DNS = ")
		sb.WriteString(cfg.DNS)
		sb.WriteString("\n")
	}
	sb.WriteString("\n[Peer]\n")
	sb.WriteString("PublicKey = ")
	sb.WriteString(cfg.ServerPubKey)
	sb.WriteString("\n")
	if cfg.PresharedKey != "" {
		sb.WriteString("PresharedKey = ")
		sb.WriteString(cfg.PresharedKey)
		sb.WriteString("\n")
	}
	sb.WriteString("AllowedIPs = ")
	sb.WriteString(cfg.AllowedIPs)
	sb.WriteString("\n")
	sb.WriteString("Endpoint = ")
	sb.WriteString(cfg.ServerEndpoint)
	sb.WriteString("\n")
	sb.WriteString("PersistentKeepalive = 25\n")
	return sb.String(), nil
}

// AppendPeer appends peer to an existing config file the way WritePeers writes a new peer.
func AppendPeer(configPath string, peer Peer) error {
	section, err := peerSection(peer, nil)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(configPath, os.O_APPEND|os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open config: %w", err)
	}
	if err := appendSection(f, section); err != nil {
		f.Close()
		return fmt.Errorf("append peer: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("append peer: %w", err)
	}
	return nil
}

func appendSection(f *os.File, section string) error {
	info, err := f.Stat()
	if err != nil {
		return err
	}
	size := info.Size()
	if size > 0 {
		last := make([]byte, 1)
		if _, err := f.ReadAt(last, size-1); err != nil {
			return err
		}
		if last[0] != '\n' {
			section = "\n" + section
		}
	}
	if _, err := f.WriteString(section); err != nil {
		return errors.Join(err, f.Truncate(size))
	}
	return nil
}
