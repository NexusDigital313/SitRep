use clap::{Parser, Subcommand};

/// The default look-back window differs by platform because the logs do.
/// journald at priority<=warning over a whole boot is small and fast; the macOS
/// unified log over the same span is hundreds of thousands of lines and takes
/// tens of seconds, so it defaults to a recent window instead. `--since boot`
/// still works on macOS — it is just slower.
#[cfg(target_os = "macos")]
pub const DEFAULT_SINCE: &str = "1h";
#[cfg(not(target_os = "macos"))]
pub const DEFAULT_SINCE: &str = "boot";

#[derive(Parser, Debug)]
#[command(
    name = "sitrep",
    version,
    about = "Reads your system logs and tells you what's wrong, in English.",
    long_about = "sitrep reads the logs your operating system already keeps — journalctl, \
systemctl and dmesg on Linux; the unified log, launchd and crash reports on macOS — \
and turns them into a ranked report of what is actually wrong, written for a human.\n\n\
With no arguments it reports on the machine it is running on. Piped input is detected \
automatically, so this works too:\n\n  ssh web01 journalctl -b -o json | sitrep"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// How far back to look: "boot", "1h", "2 days ago"
    #[arg(long, short = 's', default_value = DEFAULT_SINCE, global = true)]
    pub since: String,

    /// Read from this file instead of the live system ("-" for stdin)
    #[arg(long, short = 'f', global = true)]
    pub file: Option<String>,

    /// Include notice and info level, not just warnings and worse
    #[arg(long, short = 'a', global = true)]
    pub all: bool,

    /// Emit machine-readable JSON instead of a report
    #[arg(long, global = true)]
    pub json: bool,

    /// Never colourize, even on a terminal
    #[arg(long, global = true)]
    pub no_color: bool,

    /// Load extra .toml rule files from this directory
    #[arg(long, global = true)]
    pub rules_dir: Option<String>,

    /// Exit 1 if degraded, 2 if critical — for monitoring and CI
    #[arg(long, global = true)]
    pub exit_code: bool,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Explain a single log line pasted on the command line
    Explain {
        /// The log line. Quote it, or pipe it in on stdin.
        text: Vec<String>,
    },
    /// Follow the log live, translating lines as they arrive
    Watch,
    /// Draft rule stubs for whatever this machine logs that sitrep cannot explain
    Learn {
        /// Append the stubs to ~/.config/sitrep/rules/learned.toml instead of printing
        #[arg(long)]
        write: bool,
    },
    /// List every rule currently loaded
    Rules {
        /// Only rules carrying this tag (memory, disk, network, security…)
        #[arg(long)]
        tag: Option<String>,
    },
}
