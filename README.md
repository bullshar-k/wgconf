# DISCLAIMER
This was entirely written by AI. All it does it generate wireguard keys and automatically spit different parameters into a wireguard config file based on the flags you use. I wanted it to automate that task without using website variants because I don't trust that the websites are keeping all key generation local. 

# Prerequisites
- wireguard-tools
- iptables
- go
## Use
```
git clone https://github.com/bullshar-k/wgconf
cd wgconf
go build main.go
./main
```
The help pages will show you the use flags but they're below anyways

### ./main generate new
#### Basic example
```
./main generate new -dest 192.168.1.1 -peer 3
```

This will create a server config and 3 peer configs. The server will have address 192.168.1.1/24.
The peers will increment by 1 on the last octet. 
Preshared key is on by default but can be disabled with the flag.

### ./main generate add
To use the add command you use it as the previous command but define the previous server.conf file at the end. All this does different is add new peers. 
If you generate new with conditions A, B, and C. Then you generate add with conditions A and B it will adhere to that. If you want the exact same settings for new peers you must define that.

## Help outputs
./main
```
Usage:
  wgconfig generate new [flags]        Create new WireGuard configs
  wgconfig generate add [flags] SERVER  Add peers to an existing server config

  wgconfig -h                          Show this help
  wgconfig generate -h                 Show generate command help
```
./main generate
```
Usage:

  wgconfig generate new [flags]
    Create new server and client WireGuard configuration files.

  wgconfig generate add [flags] <server.conf>
    Add new peers to an existing server config and generate new client configs.

Flags:
  -peer int     Number of peer (client) configs (default 1)
  -mtu int      MTU size, 0 to omit (default 0)
  -server string Server address in CIDR notation (default "10.0.0.1/24") - new only
  -dest string  Destination endpoint IP/hostname (required)
  -port int     WireGuard listen port (default 51820)
  -ips string   Allowed IPs for client configs (default "0.0.0.0/0")
  -timeout int  Persistent keepalive in seconds, 0 to omit (default 0)
  -P            Generate preshared keys, use -P=false to disable (default true)
  -h            Show this help
```
./main generate new && ./main generate add
```
Usage of new:
  -P	Generate preshared keys (-P=true/false) (default true)
  -dest string
    	Destination endpoint IP/hostname (required)
  -ips string
    	Allowed IPs for client configs (default "0.0.0.0/0")
  -mtu int
    	MTU size (omitted if 0)
  -peer int
    	Number of peer (client) configs (default 1)
  -port int
    	WireGuard listen port (default 51820)
  -server string
    	Server address in CIDR notation (default "10.0.0.1/24")
  -timeout int
    	Persistent keepalive in seconds (0 to disable)
```
*Final note*:
I wrote this only for myself, web alternatives exist, I'm sure there's an electron app for this, etc. I wanted a fast one command wireguard config generator with minimal defaults and the ability to add new peers to an existing config. It's simply and slapping numbers and keys where they need to go so I used AI to write it. This is only on github in case other people find it useful or were wanting the same thing.