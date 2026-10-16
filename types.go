package wgconf

// Peer represents a WireGuard peer section with its name comment.
type Peer struct {
	Name         string
	PublicKey    string
	PresharedKey string
	AllowedIPs   []string
	Endpoint     string
	// Extra holds the section's unmodelled key lines and comment lines, whitespace-trimmed and in order.
	Extra []string
}

// InterfaceStatus holds runtime info about a WireGuard interface from wg show.
type InterfaceStatus struct {
	PublicKey  string `json:"public_key"`
	ListenPort int    `json:"listen_port"`
}

// PeerStatus holds runtime info about a single peer from wg show.
type PeerStatus struct {
	PublicKey       string `json:"public_key"`
	Endpoint        string `json:"endpoint,omitempty"`
	LatestHandshake int64  `json:"latest_handshake"`
	TransferRx      int64  `json:"transfer_rx"`
	TransferTx      int64  `json:"transfer_tx"`
}

// InterfaceShow holds the combined runtime status from wg show dump.
type InterfaceShow struct {
	Interface InterfaceStatus `json:"interface"`
	Peers     []PeerStatus    `json:"peers"`
}

// ClientConfigParams holds parameters for generating a client WireGuard config.
type ClientConfigParams struct {
	Name           string
	PrivateKey     string
	Address        string
	DNS            string
	ServerPubKey   string
	ServerEndpoint string
	AllowedIPs     string
	PresharedKey   string
}
