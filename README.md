# ASSH - Advanced SSH Manager

A modern, single-command SSH server management tool that replaces the legacy shell script system with a clean, organized approach.

## Features

- **Server Management**: Add, delete, and list SSH servers with ease
- **Multiple Connection Types**: SSH, SOCKS5, Sing-box, and Xray support
- **Secure Authentication**: SSH key generation and password authentication
- **Beautiful CLI**: Colorful output and interactive prompts
- **Cross-platform**: Works on macOS, Linux, and Windows with Bun

## Installation

### Global Installation (Recommended)

Install globally via npm:
```bash
npm install -g assh
```

Now you can use `assh` from anywhere:
```bash
assh ls
assh add
assh ssh myserver
```

### Local Development

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd assh
   ```

2. **Install dependencies**:
   ```bash
   npm install
   ```

3. **Make the script executable**:
   ```bash
   chmod +x sm.js
   ```

4. **Run locally**:
   ```bash
   node sm.js ls
   ```

## Usage

### Server Management

#### Add a Server
```bash
assh add
```
This will prompt you for:
- Server name (unique identifier)
- IP address
- Username (default: root)
- SSH port (default: 22)
- Authentication method (generate SSH key, use existing SSH key, or password)
- SSH key path (if using existing key, default: ~/.ssh/id_rsa)

#### List Servers
```bash
assh ls
```
Shows a beautiful table with all your servers and their details.

#### Delete a Server
```bash
assh delete
```
Interactively select and delete a server (includes SSH key cleanup).

#### Ping a Server
```bash
assh ping <server-name>
```
Test connectivity to a server by pinging its IP address.

### Connection Methods

#### SSH Connection
```bash
assh ssh <server-name>
```
Connects directly to the server via SSH.

#### SOCKS5 Proxy
```bash
assh socks5 <server-name>
```
Creates a SOCKS5 proxy tunnel. Options:
- `-p, --port <port>`: Local port for SOCKS5 proxy (default: 8090)

Example:
```bash
assh socks5 myserver -p 8080
```

#### Sing-box (Shadowsocks)
```bash
assh sing-box <server-name>
```
Starts sing-box with TUN interface for system-wide VPN.
- Requires `sing-box` to be installed
- Requires sudo privileges for TUN interface
- Prompts for shadowsocks password

#### Xray (VLESS)
```bash
assh xray <server-name>
```
Starts Xray with VLESS protocol.
- Requires `xray` to be installed
- Prompts for UUID
- Provides both SOCKS5 (8090) and HTTP (8091) proxies

## Configuration

Server configurations are stored in `~/.server-manager/servers.json`. Each server includes:
- IP address and port
- Username
- Authentication method (SSH key path or password)
- Creation timestamp

Generated SSH keys are stored in `~/.server-manager/` directory with the naming pattern `{server-name}_key`.

## Migration from Legacy System

The new system replaces these legacy scripts:
- `setup.sh` → `assh add`
- `ssh.sh` → `assh ssh <server-name>`
- `socks5.sh` → `assh socks5 <server-name>`
- `sing.sh` → `assh sing-box <server-name>`
- `xray.sh` → `assh xray <server-name>`

## Dependencies

### Required for basic functionality:
- `node` (JavaScript runtime, v16+ required)
- `ssh` (SSH client)
- `ssh-keygen` (SSH key generation)

### Optional for advanced features:
- `sshpass` (password authentication)
- `sing-box` (for sing-box command)
- `xray` (for xray command)

## Examples

### Complete workflow:
```bash
# Add a server
assh add

# List servers
assh ls

# Ping a server
assh ping myserver

# Connect via SSH
assh ssh myserver

# Create SOCKS5 proxy
assh socks5 myserver -p 8080

# Start sing-box VPN
assh sing-box myserver

# Start Xray proxy
assh xray myserver
```

### Adding a server with SSH key:
```bash
assh add
# Follow prompts:
# - Server name: myserver
# - IP: 1.2.3.4
# - Username: root
# - Port: 22
# - Auth: Generate SSH Key (or Use existing SSH Key)
# - Key path: ~/.ssh/id_rsa (if using existing key)
# - Install key: Yes (if generating new key)
# - Password: [your-server-password] (if installing new key)
```

## Security

- SSH keys are automatically generated using RSA 2048-bit encryption
- Keys are stored locally in the `./servers/` directory
- Password authentication is supported but SSH keys are recommended
- All SSH connections use `StrictHostKeyChecking=no` for convenience

## Troubleshooting

### Common Issues:

1. **Permission denied (publickey)**:
   - Make sure the SSH key was properly installed on the server
   - Check if the server allows SSH key authentication

2. **Connection refused**:
   - Verify the server IP and port are correct
   - Check if the SSH service is running on the server

3. **sing-box/xray not found**:
   - Install the required tools first
   - Make sure they're in your PATH

### Getting Help:
```bash
assh --help
assh <command> --help
```

## License

MIT License - feel free to modify and distribute.