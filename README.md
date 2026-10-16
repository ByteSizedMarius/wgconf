# wgconf

Reads and rewrites the peer sections of a WireGuard config file without disturbing anything else in it, generates client configs and keys, and applies the file to a running interface.

```
go get github.com/ByteSizedMarius/wgconf
```

## Example

Add a peer to the server config, apply it, and build the matching client config:

```go
const path = "/etc/wireguard/wg0.conf"

iface, peers, err := wgconf.ParsePeers(path)
if err != nil {
	return err
}

clientPriv, clientPub, err := wgconf.GenerateKeyPair()
if err != nil {
	return err
}
peers = append(peers, wgconf.Peer{
	Name:       "phone",
	PublicKey:  clientPub,
	AllowedIPs: []string{"10.0.0.7/32"},
})
if err := wgconf.WritePeers(path, iface, peers); err != nil {
	return err
}
if err := wgconf.SyncInterface("wg0"); err != nil {
	return err
}

status, err := wgconf.ShowInterface("wg0")
if err != nil {
	return err
}
clientConf, err := wgconf.GenerateClientConfig(wgconf.ClientConfigParams{
	Name:           "phone",
	PrivateKey:     clientPriv,
	Address:        "10.0.0.7/32",
	ServerPubKey:   status.Interface.PublicKey,
	ServerEndpoint: "vpn.example.com:51820",
	AllowedIPs:     "0.0.0.0/0",
})
```

## Reading and writing

- Parsing a file and writing it back unchanged reproduces it byte for byte. The interface block and every peer you leave alone keep their original lines.
- A peer's `Name` is the comment line directly above its `[Peer]` header.
- New and changed values must be valid wg syntax, and an error names the rejected field.
- Serialize calls on the same file.

## Live interfaces

`SyncInterface` and `ShowInterface` need `wg` and `wg-quick` on PATH, usually as root. `SyncInterface` keeps existing peer sessions up.
