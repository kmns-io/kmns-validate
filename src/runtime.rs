use nix::unistd::{getgid, getuid};
use std::env;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Runtime {
    pub workdir: PathBuf,
    pub uid: u32,
    pub gid: u32,
    pub privileged: bool,
    pub os: Os,
    pub package_manager: String,
    pub vldid: String,
}

#[derive(Debug, Clone)]
pub struct Os {
    pub name: String,
    pub version: String,
    pub arch: String,
    pub cpus: usize,
    pub load_average: (f64, f64, f64),
    pub mem_total: u64,
    pub mem_free: u64,
}

impl Runtime {
    /// Detect runtime information
    pub fn startup(dc_id: u32) -> Self {
        let uid = getuid().as_raw();
        let gid = getgid().as_raw();
        let wd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let os = detect_os();
        let package_manager = detect_package_manager(&os.name);

        Runtime {
            workdir: wd,
            uid,
            gid,
            privileged: uid == 0,
            os,
            package_manager,
            vldid: generate_vld_id(dc_id),
        }
    }
}

fn generate_vld_id(dc_id: u32) -> String {
    // feat: Generate VldId used in distributed validation (Snowflake analog)
    use std::time::{SystemTime, UNIX_EPOCH};

    // Custom epoch: 2026-01-01T00:00:00Z
    const EPOCH_MS: u64 = 1735689600000;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis() as u64;

    let timestamp = now.saturating_sub(EPOCH_MS);

    // Snowflake 64-bit ID layout:
    // [1 bit unused] | [41 bits timestamp] | [5 bits datacenter_id] | [5 bits worker_id] | [12 bits sequence]

    // 5 bits for datacenter_id (max 31)
    let dc_bits = (dc_id as u64) & 0x1F;

    // 5 bits for worker_id (max 31) - derive from PID and UID
    let pid = nix::unistd::getpid().as_raw() as u64;
    let uid = nix::unistd::getuid().as_raw() as u64;
    let worker_bits = (pid ^ uid) & 0x1F;

    // 12 bits for sequence (max 4095) - 0 because we're at startup
    let sequence = 0u64;

    let id = ((timestamp & 0x1FFFFFFFFFF) << 22) | (dc_bits << 17) | (worker_bits << 12) | sequence;
    id.to_string()
}

fn detect_os() -> Os {
    // Detect OS - https://crates.io/crates/os_info
    let os_info = os_info::get();
    let sys_info = detect_sys_info();

    Os {
        name: os_info.os_type().to_string(),
        version: os_info.version().to_string(),
        arch: os_info.architecture().unwrap_or("unknown").to_string(),
        cpus: std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1),
        load_average: sys_info.0,
        mem_total: sys_info.1,
        mem_free: sys_info.2,
    }
}

fn detect_sys_info() -> ((f64, f64, f64), u64, u64) {
    #[cfg(target_os = "linux")]
    {
        if let Ok(info) = nix::sys::sysinfo::sysinfo() {
            let load = info.load_average();
            // In nix 0.31.2, these methods return values already in bytes
            let total = info.ram_total();
            let free = info.ram_unused();
            return (load, total, free);
        }
    }
    ((0.0, 0.0, 0.0), 0, 0)
}

fn detect_package_manager(os_name: &str) -> String {
    match os_name.to_lowercase().as_str() {
        // apt-based
        "debian" | "ubuntu" | "mint" | "kali linux" | "pop!_os" | "pop" | "elementary os"
        | "raspberry pi os" | "raspbian" => "apt".to_string(),

        // dnf/yum-based
        "fedora"
        | "centos"
        | "rhel"
        | "red hat linux"
        | "red hat enterprise linux"
        | "oracle linux"
        | "almalinux"
        | "rocky linux"
        | "nobara linux"
        | "ultramarine linux"
        | "openeuler"
        | "euleros"
        | "opencloudos"
        | "amazon linux ami"
        | "mariner"
        | "openeuler (euleros)" => "dnf".to_string(),

        // pacman-based
        "arch linux" | "arch" | "endeavouros" | "manjaro" | "garuda linux" | "artix linux"
        | "cachyos" | "mabox" => "pacman".to_string(),

        // apk-based
        "alpine linux" | "alpaquita linux" => "apk".to_string(),

        // zypper-based
        "opensuse" | "suse linux enterprise server" | "sles" => "zypper".to_string(),

        // pkg-based (BSD)
        "freebsd" | "dragonfly bsd" | "hardenedbsd" | "midnightbsd" | "netbsd" => "pkg".to_string(),

        // xbps-based
        "void linux" | "void" => "xbps".to_string(),

        // nix-based
        "nixos" => "nix".to_string(),

        // gentoo-based
        "gentoo linux" | "gentoo" => "emerge".to_string(),

        // brew-based
        "macos" | "mac os x" | "os x" | "macos (mac os x or os x)" => "brew".to_string(),

        // winget-based
        "windows" => "winget".to_string(),

        // Others
        "openbsd" => "pkg_add".to_string(),
        "solus" => "eopkg".to_string(),
        "aosc os" => "oma".to_string(),
        "redox" => "pkgar".to_string(),
        "illumos" => "pkgsrc".to_string(),
        "android" => "pkg".to_string(),

        _ => "Unknown".to_string(),
    }
}
