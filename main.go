package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/crypto/curve25519"
)

func main() {
	if len(os.Args) < 2 {
		printTopHelp()
		os.Exit(0)
	}

	switch os.Args[1] {
	case "-h", "--help", "help":
		printTopHelp()
	case "generate":
		if len(os.Args) < 3 {
			printGenerateHelp()
			os.Exit(1)
		}
		switch os.Args[2] {
		case "new":
			cmdNew(os.Args[3:])
		case "add":
			cmdAdd(os.Args[3:])
		case "-h", "--help":
			printGenerateHelp()
		default:
			printGenerateHelp()
			os.Exit(1)
		}
	default:
		printTopHelp()
		os.Exit(1)
	}
}

func printTopHelp() {
	fmt.Println("wgconfig - WireGuard configuration generator")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  wgconfig generate new [flags]        Create new WireGuard configs")
	fmt.Println("  wgconfig generate add [flags] SERVER  Add peers to an existing server config")
	fmt.Println()
	fmt.Println("  wgconfig -h                          Show this help")
	fmt.Println("  wgconfig generate -h                 Show generate command help")
}

func printGenerateHelp() {
	fmt.Println("Usage:")
	fmt.Println()
	fmt.Println("  wgconfig generate new [flags]")
	fmt.Println("    Create new server and client WireGuard configuration files.")
	fmt.Println()
	fmt.Println("  wgconfig generate add [flags] <server.conf>")
	fmt.Println("    Add new peers to an existing server config and generate new client configs.")
	fmt.Println()
	fmt.Println("Flags:")
	fmt.Println("  -peer int     Number of peer (client) configs (default 1)")
	fmt.Println("  -mtu int      MTU size, 0 to omit (default 0)")
	fmt.Println("  -server string Server address in CIDR notation (default \"10.0.0.1/24\") - new only")
	fmt.Println("  -dest string  Destination endpoint IP/hostname (required)")
	fmt.Println("  -port int     WireGuard listen port (default 51820)")
	fmt.Println("  -ips string   Allowed IPs for client configs (default \"0.0.0.0/0\")")
	fmt.Println("  -timeout int  Persistent keepalive in seconds, 0 to omit (default 0)")
	fmt.Println("  -P            Generate preshared keys, use -P=false to disable (default true)")
	fmt.Println("  -h            Show this help")
}

func cmdNew(args []string) {
	fs := flag.NewFlagSet("new", flag.ExitOnError)
	peers := fs.Int("peer", 1, "Number of peer (client) configs")
	mtu := fs.Int("mtu", 0, "MTU size (omitted if 0)")
	serverAddr := fs.String("server", "10.0.0.1/24", "Server address in CIDR notation")
	dest := fs.String("dest", "", "Destination endpoint IP/hostname (required)")
	usePSK := fs.Bool("P", true, "Generate preshared keys (-P=true/false)")
	port := fs.Int("port", 51820, "WireGuard listen port")
	allowedIPs := fs.String("ips", "0.0.0.0/0", "Allowed IPs for client configs")
	keepalive := fs.Int("timeout", 0, "Persistent keepalive in seconds (0 to disable)")

	fs.Parse(args)

	if *dest == "" {
		fmt.Fprintln(os.Stderr, "Error: -dest is required")
		fs.Usage()
		os.Exit(1)
	}
	if *peers < 1 {
		fmt.Fprintln(os.Stderr, "Error: -peer must be at least 1")
		os.Exit(1)
	}

	serverIP, ipNet, err := parseCIDR(*serverAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid -server address: %v\n", err)
		os.Exit(1)
	}

	serverPriv, err := genKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating server key: %v\n", err)
		os.Exit(1)
	}
	serverPub, err := pubKey(serverPriv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error deriving server public key: %v\n", err)
		os.Exit(1)
	}

	clientKeys := make([]struct{ priv, pub, psk string }, *peers)
	for i := 0; i < *peers; i++ {
		priv, err := genKey()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating client key %d: %v\n", i+1, err)
			os.Exit(1)
		}
		pub, err := pubKey(priv)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error deriving client public key %d: %v\n", i+1, err)
			os.Exit(1)
		}
		var psk string
		if *usePSK {
			psk, err = genPSK()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error generating PSK %d: %v\n", i+1, err)
				os.Exit(1)
			}
		}
		clientKeys[i] = struct{ priv, pub, psk string }{priv, pub, psk}
	}

	serverConfig := buildServerConfig(serverPriv, *serverAddr, *port, *mtu, serverIP, ipNet, clientKeys, *usePSK)
	if err := os.WriteFile("server.conf", []byte(serverConfig), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing server.conf: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Wrote server.conf")

	for i, k := range clientKeys {
		clientAddr := clientIP(serverIP, ipNet, i+1)
		clientConfig := buildClientConfig(k.priv, clientAddr, *mtu, serverPub, *dest, *port, k.psk, *usePSK, *allowedIPs, *keepalive)
		fname := fmt.Sprintf("client%d.conf", i+1)
		if err := os.WriteFile(fname, []byte(clientConfig), 0600); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", fname, err)
			os.Exit(1)
		}
		fmt.Printf("Wrote %s\n", fname)
	}
}

func cmdAdd(args []string) {
	fs := flag.NewFlagSet("add", flag.ExitOnError)
	peers := fs.Int("peer", 1, "Number of peers to add")
	dest := fs.String("dest", "", "Destination endpoint IP/hostname (required)")
	port := fs.Int("port", 51820, "WireGuard listen port")
	mtu := fs.Int("mtu", 0, "MTU size (omitted if 0)")
	allowedIPs := fs.String("ips", "0.0.0.0/0", "Allowed IPs for client configs")
	keepalive := fs.Int("timeout", 0, "Persistent keepalive in seconds (0 to disable)")
	usePSK := fs.Bool("P", true, "Generate preshared keys (-P=true/false)")

	fs.Parse(args)

	if *dest == "" {
		fmt.Fprintln(os.Stderr, "Error: -dest is required")
		fs.Usage()
		os.Exit(1)
	}
	if *peers < 1 {
		fmt.Fprintln(os.Stderr, "Error: -peer must be at least 1")
		os.Exit(1)
	}

	posArgs := fs.Args()
	if len(posArgs) < 1 {
		fmt.Fprintln(os.Stderr, "Error: server config path is required")
		fs.Usage()
		os.Exit(1)
	}
	serverPath := posArgs[0]

	serverCfg, err := parseServerConfig(serverPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading server config: %v\n", err)
		os.Exit(1)
	}

	serverIP, ipNet, err := parseCIDR(serverCfg.Address)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing server address: %v\n", err)
		os.Exit(1)
	}

	existingPeers := len(serverCfg.Peers)

	newKeys := make([]struct{ priv, pub, psk string }, *peers)
	for i := 0; i < *peers; i++ {
		priv, err := genKey()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating client key: %v\n", err)
			os.Exit(1)
		}
		pub, err := pubKey(priv)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error deriving client public key: %v\n", err)
			os.Exit(1)
		}
		var psk string
		if *usePSK {
			psk, err = genPSK()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error generating PSK: %v\n", err)
				os.Exit(1)
			}
		}
		newKeys[i] = struct{ priv, pub, psk string }{priv, pub, psk}
	}

	peerBlocks := make([]string, *peers)
	for i, k := range newKeys {
		peerIndex := existingPeers + i + 1
		peerIP := clientIP(serverIP, ipNet, peerIndex)
		peerBlocks[i] = fmt.Sprintf("\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s/32\n",
			k.pub, k.psk, strings.TrimSuffix(peerIP, "/"+strconv.Itoa(maskSize(ipNet))))
	}

	serverContent, err := os.ReadFile(serverPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading server config file: %v\n", err)
		os.Exit(1)
	}
	newServerContent := strings.TrimRight(string(serverContent), "\n") + strings.Join(peerBlocks, "") + "\n"
	if err := os.WriteFile(serverPath, []byte(newServerContent), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing server config: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Added %d peer(s) to %s\n", *peers, serverPath)

	serverPub, err := pubKey(serverCfg.PrivateKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error deriving server public key: %v\n", err)
		os.Exit(1)
	}

	for i, k := range newKeys {
		peerIndex := existingPeers + i + 1
		clientAddr := clientIP(serverIP, ipNet, peerIndex)
		clientConfig := buildClientConfig(k.priv, clientAddr, *mtu, serverPub, *dest, *port, k.psk, *usePSK, *allowedIPs, *keepalive)
		fname := fmt.Sprintf("client%d.conf", peerIndex)
		fpath := filepath.Join(filepath.Dir(serverPath), fname)
		if err := os.WriteFile(fpath, []byte(clientConfig), 0600); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", fname, err)
			os.Exit(1)
		}
		fmt.Printf("Wrote %s\n", fname)
	}
}

func genKey() (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

func genPSK() (string, error) {
	return genKey()
}

func pubKey(priv string) (string, error) {
	privBytes, err := base64.StdEncoding.DecodeString(priv)
	if err != nil {
		return "", err
	}
	var key [32]byte
	copy(key[:], privBytes)
	key = clampKey(key)

	pub, err := curve25519.X25519(key[:], curve25519.Basepoint)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(pub), nil
}

func clampKey(key [32]byte) [32]byte {
	key[0] &= 248
	key[31] &= 127
	key[31] |= 64
	return key
}

func parseCIDR(addr string) (net.IP, *net.IPNet, error) {
	ip, ipNet, err := net.ParseCIDR(addr)
	if err != nil {
		return nil, nil, err
	}
	return ip, ipNet, nil
}

func clientIP(serverIP net.IP, ipNet *net.IPNet, index int) string {
	ip4 := serverIP.To4()
	if ip4 == nil {
		return ""
	}
	val := uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
	val += uint32(index)

	newIP := net.IPv4(byte(val>>24), byte(val>>16), byte(val>>8), byte(val))

	ones, _ := ipNet.Mask.Size()
	return fmt.Sprintf("%s/%d", newIP.String(), ones)
}

func maskSize(ipNet *net.IPNet) int {
	ones, _ := ipNet.Mask.Size()
	return ones
}

func buildServerConfig(serverPriv, serverAddr string, port, mtu int, serverIP net.IP, ipNet *net.IPNet, clients []struct{ priv, pub, psk string }, usePSK bool) string {
	var sb strings.Builder
	sb.WriteString("[Interface]\n")
	sb.WriteString(fmt.Sprintf("Address = %s\n", serverAddr))
	sb.WriteString(fmt.Sprintf("ListenPort = %d\n", port))
	sb.WriteString(fmt.Sprintf("PrivateKey = %s\n", serverPriv))
	if mtu > 0 {
		sb.WriteString(fmt.Sprintf("MTU = %d\n", mtu))
	}

	for i, c := range clients {
		sb.WriteString("\n[Peer]\n")
		sb.WriteString(fmt.Sprintf("PublicKey = %s\n", c.pub))
		if usePSK && c.psk != "" {
			sb.WriteString(fmt.Sprintf("PresharedKey = %s\n", c.psk))
		}
		ip := clientIP(serverIP, ipNet, i+1)
		sb.WriteString(fmt.Sprintf("AllowedIPs = %s/32\n", strings.TrimSuffix(ip, fmt.Sprintf("/%d", maskSize(ipNet)))))
	}

	return sb.String()
}

func buildClientConfig(priv, addr string, mtu int, serverPub, dest string, port int, psk string, usePSK bool, allowedIPs string, keepalive int) string {
	var sb strings.Builder
	sb.WriteString("[Interface]\n")
	sb.WriteString(fmt.Sprintf("Address = %s\n", addr))
	sb.WriteString(fmt.Sprintf("PrivateKey = %s\n", priv))
	if mtu > 0 {
		sb.WriteString(fmt.Sprintf("MTU = %d\n", mtu))
	}

	sb.WriteString("\n[Peer]\n")
	sb.WriteString(fmt.Sprintf("PublicKey = %s\n", serverPub))
	if usePSK && psk != "" {
		sb.WriteString(fmt.Sprintf("PresharedKey = %s\n", psk))
	}
	sb.WriteString(fmt.Sprintf("AllowedIPs = %s\n", allowedIPs))
	sb.WriteString(fmt.Sprintf("Endpoint = %s:%d\n", dest, port))
	if keepalive > 0 {
		sb.WriteString(fmt.Sprintf("PersistentKeepalive = %d\n", keepalive))
	}

	return sb.String()
}

type ServerParsed struct {
	PrivateKey string
	Address    string
	Port       int
	MTU        int
	Peers      []ParsedPeer
}

type ParsedPeer struct {
	PublicKey    string
	PresharedKey string
	AllowedIPs   string
}

func parseServerConfig(path string) (*ServerParsed, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfg := &ServerParsed{MTU: 0}
	var currentPeer *ParsedPeer

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if line == "[Peer]" {
				cfg.Peers = append(cfg.Peers, ParsedPeer{})
				currentPeer = &cfg.Peers[len(cfg.Peers)-1]
			}
			continue
		}
		if currentPeer != nil {
			key, val := parseKV(line)
			switch key {
			case "PublicKey":
				currentPeer.PublicKey = val
			case "PresharedKey":
				currentPeer.PresharedKey = val
			case "AllowedIPs":
				currentPeer.AllowedIPs = val
			}
		} else {
			key, val := parseKV(line)
			switch key {
			case "PrivateKey":
				cfg.PrivateKey = val
			case "Address":
				cfg.Address = val
			case "ListenPort":
				cfg.Port, _ = strconv.Atoi(val)
			case "MTU":
				cfg.MTU, _ = strconv.Atoi(val)
			}
		}
	}

	if cfg.PrivateKey == "" {
		return nil, fmt.Errorf("server config missing PrivateKey in [Interface]")
	}

	return cfg, nil
}

func parseKV(line string) (key, value string) {
	idx := strings.Index(line, "=")
	if idx < 0 {
		return "", ""
	}
	key = strings.TrimSpace(line[:idx])
	value = strings.TrimSpace(line[idx+1:])
	return
}
