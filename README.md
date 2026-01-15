<h1 align="center">rip</h1>

<p align="center">
  <i>Fuzzy find and kill processes from your terminal</i>
</p>

<p align="center">
  <img src="public/screenshot.png" alt="rip demo" width="700">
</p>

<p align="center">
  <a href="https://crates.io/crates/rip-cli"><img src="https://img.shields.io/crates/v/rip-cli.svg" alt="Crates.io"></a>
  <a href="https://crates.io/crates/rip-cli"><img src="https://img.shields.io/crates/d/rip-cli.svg" alt="Downloads"></a>
  <a href="https://github.com/cesarferreira/rip/blob/main/LICENSE"><img src="https://img.shields.io/crates/l/rip-cli.svg" alt="License"></a>
  <a href="https://github.com/cesarferreira/rip"><img src="https://img.shields.io/github/stars/cesarferreira/rip?style=social" alt="GitHub Stars"></a>
</p>

## Installation

### Homebrew (macOS)

```bash
brew install cesarferreira/tap/rip
```

### Cargo

```bash
cargo install rip-cli
```

### From source

```bash
cargo install --path .
```

### Nix
#### Test with nix run:
```bash
nix run github:cesarferreira/rip --no-write-lock-file
```

#### Install via flake
```nix
# In your local flake.nix file
inputs = {
  rip = {
    url = "github:cesarferreira/rip";
    inputs.nixpkgs.follows = "nixpkgs";
  };
};

# Your output packages + rip
outputs = {
#  self,
#  nixpkgs,
  rip,
#  ...
};

# In your configuration.nix
{  inputs, ...}:{
# Your other configurations 
  environment.systemPackages = with pkgs; [
    # inputs.rip.packages.${$system}.default #<-old
    inputs.rip.packages.${pkgs.stdenv.hostPlatform.system}.default #<- current
  ];
}


```

## Usage

```bash
# Open fuzzy finder with all processes (sorted by CPU)
rip

# Pre-filter by process name
rip -f chrome

# Use a different signal (default: SIGKILL)
rip -s SIGTERM

# Sort by memory usage
rip --sort mem

# Sort by PID
rip --sort pid

# Sort by name
rip --sort name

# Live mode with auto-refreshing process list
rip --live
```

### Ports Mode

Show and filter by processes listening on network ports:

```bash
# Show all processes with open ports
rip --ports

# Filter to a specific port (e.g., kill whatever is using port 3000)
rip --port 3000

# Combine with live mode
rip --ports --live

# Sort by port number
rip --ports --sort port
```

### Options

| Flag | Description |
|------|-------------|
| `-f, --filter <name>` | Pre-filter processes by name |
| `-s, --signal <signal>` | Signal to send (default: KILL) |
| `--sort <field>` | Sort by: cpu (default), mem, pid, name, port |
| `-l, --live` | Live mode with auto-refreshing process list |
| `--ports` | Show only processes with open ports |
| `--port <PORT>` | Filter by specific port number (implies --ports) |

### Controls

| Key | Action |
|-----|--------|
| `Space` | Select/deselect process |
| `Enter` | Kill selected processes |
| `Esc` / `Ctrl+C` | Cancel |
| Type | Fuzzy search |

### Signals

| Signal | Number | Description |
|--------|--------|-------------|
| `KILL` | 9 | Force kill (default) |
| `TERM` | 15 | Graceful termination |
| `INT` | 2 | Interrupt |
| `HUP` | 1 | Hangup |
| `QUIT` | 3 | Quit |

## Examples

```bash
# Kill all matching Chrome processes
rip -f chrome

# Gracefully terminate a process
rip -s TERM

# Kill node processes
rip -f node

# Kill whatever is using port 3000
rip --port 3000

# View all processes with open ports in live mode
rip --ports --live
```

## License

MIT
