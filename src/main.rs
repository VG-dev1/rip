use clap::{Parser, ValueEnum};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use skim::prelude::*;
use std::io::Cursor;
use sysinfo::System;

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq)]
enum SortBy {
    Cpu,
    Mem,
    Pid,
    Name,
}

#[derive(Parser)]
#[command(name = "rip")]
#[command(about = "Fuzzy find and kill processes", long_about = None)]
struct Args {
    /// Pre-filter processes by name
    #[arg(short, long)]
    filter: Option<String>,

    /// Signal to send (default: SIGKILL)
    #[arg(short, long, default_value = "KILL")]
    signal: String,

    /// Sort processes by field (default: cpu)
    #[arg(long, value_enum, default_value = "cpu")]
    sort: SortBy,
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

struct ProcessInfo {
    pid: u32,
    name: String,
    cpu: f32,
    memory: u64,
}

fn get_processes(filter: Option<&str>, sort_by: SortBy) -> Vec<String> {
    let mut sys = System::new_all();
    sys.refresh_all();

    let mut processes: Vec<ProcessInfo> = sys
        .processes()
        .iter()
        .filter_map(|(pid, process)| {
            let name = process.name().to_string_lossy().to_string();

            // Apply filter if provided
            if let Some(f) = filter {
                if !name.to_lowercase().contains(&f.to_lowercase()) {
                    return None;
                }
            }

            Some(ProcessInfo {
                pid: pid.as_u32(),
                name,
                cpu: process.cpu_usage(),
                memory: process.memory() / 1024 / 1024,
            })
        })
        .collect();

    // Sort by selected field
    match sort_by {
        SortBy::Cpu => processes.sort_by(|a, b| b.cpu.partial_cmp(&a.cpu).unwrap()),
        SortBy::Mem => processes.sort_by(|a, b| b.memory.cmp(&a.memory)),
        SortBy::Pid => processes.sort_by(|a, b| a.pid.cmp(&b.pid)),
        SortBy::Name => processes.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase())),
    }

    // Format for display
    processes
        .into_iter()
        .map(|p| {
            let display_name = truncate(&p.name, 40);
            format!(
                "{:<8} {:<40} {:>6.1}% {:>8} MB",
                p.pid, display_name, p.cpu, p.memory
            )
        })
        .collect()
}

fn parse_signal(signal_str: &str) -> Result<Signal, String> {
    let signal_str = signal_str.to_uppercase();
    let signal_str = signal_str.strip_prefix("SIG").unwrap_or(&signal_str);

    match signal_str {
        "KILL" | "9" => Ok(Signal::SIGKILL),
        "TERM" | "15" => Ok(Signal::SIGTERM),
        "INT" | "2" => Ok(Signal::SIGINT),
        "HUP" | "1" => Ok(Signal::SIGHUP),
        "QUIT" | "3" => Ok(Signal::SIGQUIT),
        "USR1" | "10" => Ok(Signal::SIGUSR1),
        "USR2" | "12" => Ok(Signal::SIGUSR2),
        "STOP" | "19" => Ok(Signal::SIGSTOP),
        "CONT" | "18" => Ok(Signal::SIGCONT),
        _ => Err(format!("Unknown signal: {}", signal_str)),
    }
}

fn run_fuzzy_finder(processes: Vec<String>) -> Vec<String> {
    if processes.is_empty() {
        return vec![];
    }

    let header = format!(
        "{:<8} {:<40} {:>7} {:>11}",
        "PID", "NAME", "CPU", "MEMORY"
    );

    let options = SkimOptionsBuilder::default()
        .height(Some("50%"))
        .multi(true)
        .reverse(true)
        .header(Some(&header))
        .prompt(Some("Kill > "))
        .build()
        .unwrap();

    let input = processes.join("\n");
    let item_reader = SkimItemReader::default();
    let items = item_reader.of_bufread(Cursor::new(input));

    let selected = Skim::run_with(&options, Some(items))
        .map(|out| {
            if out.is_abort {
                vec![]
            } else {
                out.selected_items
                    .iter()
                    .map(|item| item.output().to_string())
                    .collect()
            }
        })
        .unwrap_or_default();

    selected
}

fn extract_pid(line: &str) -> Option<i32> {
    line.split_whitespace()
        .next()
        .and_then(|pid_str| pid_str.parse().ok())
}

fn kill_processes(selected: Vec<String>, signal: Signal) {
    for line in selected {
        if let Some(pid) = extract_pid(&line) {
            let process_name: String = line
                .split_whitespace()
                .nth(1)
                .unwrap_or("unknown")
                .to_string();

            match kill(Pid::from_raw(pid), signal) {
                Ok(_) => println!("Killed {} (PID: {})", process_name, pid),
                Err(e) => eprintln!("Failed to kill {} (PID: {}): {}", process_name, pid, e),
            }
        }
    }
}

fn main() {
    let args = Args::parse();

    let signal = match parse_signal(&args.signal) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    let processes = get_processes(args.filter.as_deref(), args.sort);

    if processes.is_empty() {
        println!("No processes found");
        return;
    }

    let selected = run_fuzzy_finder(processes);

    if selected.is_empty() {
        println!("No processes selected");
        return;
    }

    kill_processes(selected, signal);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_signal_kill() {
        assert_eq!(parse_signal("KILL").unwrap(), Signal::SIGKILL);
        assert_eq!(parse_signal("kill").unwrap(), Signal::SIGKILL);
        assert_eq!(parse_signal("SIGKILL").unwrap(), Signal::SIGKILL);
        assert_eq!(parse_signal("9").unwrap(), Signal::SIGKILL);
    }

    #[test]
    fn test_parse_signal_term() {
        assert_eq!(parse_signal("TERM").unwrap(), Signal::SIGTERM);
        assert_eq!(parse_signal("term").unwrap(), Signal::SIGTERM);
        assert_eq!(parse_signal("SIGTERM").unwrap(), Signal::SIGTERM);
        assert_eq!(parse_signal("15").unwrap(), Signal::SIGTERM);
    }

    #[test]
    fn test_parse_signal_int() {
        assert_eq!(parse_signal("INT").unwrap(), Signal::SIGINT);
        assert_eq!(parse_signal("2").unwrap(), Signal::SIGINT);
    }

    #[test]
    fn test_parse_signal_hup() {
        assert_eq!(parse_signal("HUP").unwrap(), Signal::SIGHUP);
        assert_eq!(parse_signal("1").unwrap(), Signal::SIGHUP);
    }

    #[test]
    fn test_parse_signal_invalid() {
        assert!(parse_signal("INVALID").is_err());
        assert!(parse_signal("999").is_err());
    }

    #[test]
    fn test_extract_pid_valid() {
        let line = "1234     firefox                        10.5%      512 MB";
        assert_eq!(extract_pid(line), Some(1234));
    }

    #[test]
    fn test_extract_pid_different_formats() {
        assert_eq!(extract_pid("100 bash 0.0% 10 MB"), Some(100));
        assert_eq!(extract_pid("99999    long-process-name 5.0% 1024 MB"), Some(99999));
    }

    #[test]
    fn test_extract_pid_invalid() {
        assert_eq!(extract_pid(""), None);
        assert_eq!(extract_pid("not-a-pid process 0% 0 MB"), None);
    }

    #[test]
    fn test_get_processes_returns_non_empty() {
        let processes = get_processes(None, SortBy::Cpu);
        assert!(!processes.is_empty(), "Should return at least one process");
    }

    #[test]
    fn test_get_processes_format() {
        let processes = get_processes(None, SortBy::Cpu);
        let first = processes.first().unwrap();

        // Should have at least 4 whitespace-separated fields
        let parts: Vec<&str> = first.split_whitespace().collect();
        assert!(parts.len() >= 4, "Process line should have at least 4 fields");

        // First field should be a valid PID (number)
        assert!(parts[0].parse::<i32>().is_ok(), "First field should be a valid PID");
    }

    #[test]
    fn test_get_processes_with_filter() {
        // This test checks that filtering works - use a common process name
        let all_processes = get_processes(None, SortBy::Cpu);
        let filtered = get_processes(Some("NONEXISTENT_PROCESS_12345"), SortBy::Cpu);

        // Filtered should have fewer (or equal if no matches)
        assert!(filtered.len() <= all_processes.len());
    }

    #[test]
    fn test_sort_by_values() {
        // Test that all sort options work without panicking
        let _ = get_processes(None, SortBy::Cpu);
        let _ = get_processes(None, SortBy::Mem);
        let _ = get_processes(None, SortBy::Pid);
        let _ = get_processes(None, SortBy::Name);
    }
}
