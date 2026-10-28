pub mod addr;
pub mod command;
pub mod container;
pub mod dns;
pub mod exec;
pub mod file;
pub mod group;
pub mod http;
pub mod interface;
pub mod kernel;
pub mod matcher;
pub mod mount;
pub mod package;
pub mod parallel;
pub mod port;
pub mod process;
pub mod runner;
pub mod service;
pub mod template;
pub mod user;

/// Canonical hardened system PATH for command and exec execution.
pub const SECURE_SYSTEM_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// Deterministic standard C locale.
pub const SECURE_LOCALE: &str = "C";

/// Sanitizes execution environment for Command and Exec child processes.
/// Clears all inherited environment variables and injects minimal, secure defaults.
pub fn sanitize_cmd_env(cmd: &mut std::process::Command, user: Option<&str>) {
    cmd.env_clear();
    cmd.env("PATH", SECURE_SYSTEM_PATH);
    cmd.env("LC_ALL", SECURE_LOCALE);
    cmd.env("LANG", SECURE_LOCALE);
    if let Some(u) = user {
        cmd.env("USER", u);
        cmd.env("LOGNAME", u);
    }
}
