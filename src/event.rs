//! The one shape every collector produces, whatever platform it came from.

use serde::{Deserialize, Serialize};

/// Syslog severity, which both journald and the macOS unified log map onto
/// cleanly enough for our purposes. Ordered most severe first so that
/// `#[derive(Ord)]` sorts the scary things to the top.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Emergency,
    Alert,
    Critical,
    Error,
    Warning,
    Notice,
    Info,
    Debug,
}

impl Severity {
    /// journalctl PRIORITY field, and `dmesg --level` names.
    pub fn from_syslog(n: u8) -> Self {
        match n {
            0 => Self::Emergency,
            1 => Self::Alert,
            2 => Self::Critical,
            3 => Self::Error,
            4 => Self::Warning,
            5 => Self::Notice,
            6 => Self::Info,
            _ => Self::Debug,
        }
    }

    /// `log show` prints these words in its `Type` column.
    ///
    /// Deliberately shifted down one step from the obvious mapping. macOS
    /// frameworks log at Error and Fault far more freely than syslog daemons
    /// do — an idle, healthy Mac emits tens of thousands of Fault records an
    /// hour, mostly missing-entitlement chatter from Apple's own code. Mapping
    /// Fault onto Critical made every machine look like it was on fire, which
    /// is worse than useless: it buries the one line that actually matters.
    /// Rules that know better set their own severity and override this.
    pub fn from_macos(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "fault" => Self::Error,
            "error" => Self::Warning,
            "default" => Self::Notice,
            "info" => Self::Info,
            _ => Self::Debug,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Emergency => "EMERGENCY",
            Self::Alert => "ALERT",
            Self::Critical => "CRITICAL",
            Self::Error => "ERROR",
            Self::Warning => "WARNING",
            Self::Notice => "NOTICE",
            Self::Info => "INFO",
            Self::Debug => "DEBUG",
        }
    }

    /// Anything at Warning or worse is worth a human's attention.
    pub fn is_notable(self) -> bool {
        self <= Self::Warning
    }
}

/// Where a line came from. Drives which rule pack gets consulted and how the
/// renderer labels the finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    /// journalctl, general userspace
    Journal,
    /// journalctl -k / dmesg
    Kernel,
    /// systemctl --failed, systemctl status
    Systemd,
    /// macOS `log show`
    UnifiedLog,
    /// macOS `launchctl`
    Launchd,
    /// A crash report or coredump record
    Crash,
    /// Read from a file or stdin, origin unknown
    Piped,
}


/// A single normalized log line.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// RFC3339-ish, as printed by the source. Kept as a string because the
    /// formats vary wildly and we only ever display or compare them.
    pub timestamp: Option<String>,
    /// systemd unit, launchd label, or process name.
    pub unit: Option<String>,
    pub pid: Option<u32>,
    pub severity: Severity,
    pub source: Source,
    /// The message body with the syslog preamble stripped.
    pub message: String,
    /// The untouched line, shown as evidence under a finding.
    pub raw: String,
}

impl Event {
    pub fn new(source: Source, severity: Severity, raw: impl Into<String>) -> Self {
        let raw = raw.into();
        Self {
            timestamp: None,
            unit: None,
            pid: None,
            severity,
            source,
            message: raw.clone(),
            raw,
        }
    }

    pub fn with_message(mut self, message: impl Into<String>) -> Self {
        self.message = message.into();
        self
    }

    pub fn with_timestamp(mut self, ts: Option<String>) -> Self {
        self.timestamp = ts;
        self
    }

    pub fn with_unit(mut self, unit: Option<String>) -> Self {
        self.unit = unit;
        self
    }

    pub fn with_pid(mut self, pid: Option<u32>) -> Self {
        self.pid = pid;
        self
    }
}
