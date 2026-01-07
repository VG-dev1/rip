# rip

> Fuzzy find and kill processes from your terminal

<p align="center">
  <img src="demo.gif" alt="rip demo" width="600">
</p>

## Installation

### From source

```bash
cargo install --path .
```

### Cargo

```bash
cargo install rip-cli
```

## Usage

```bash
# Open fuzzy finder with all processes
rip

# Pre-filter by process name
rip -f chrome

# Use a different signal (default: SIGKILL)
rip -s SIGTERM
```

### Controls

| Key | Action |
|-----|--------|
| `Tab` | Select/deselect process |
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
```

## License

MIT
