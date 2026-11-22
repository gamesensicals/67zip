//! Process sandbox: Landlock (file system and TCP) plus a seccomp filter.
//! Both are applied best-effort: on kernels without Landlock the worker
//! still runs, and the status says so.

use std::collections::BTreeMap;
use std::path::PathBuf;

use landlock::{
    path_beneath_rules, Access, AccessFs, AccessNet, CompatLevel, Compatible, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus, Scope, ABI,
};
use seccompiler::{sock_filter, BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter, SeccompRule, TargetArch};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SandboxStatus {
    /// "full", "partial" or "unavailable".
    pub landlock: String,
    pub seccomp: bool,
    pub no_new_privs: bool,
}

impl SandboxStatus {
    pub fn is_strong(&self) -> bool {
        self.landlock == "full" && self.seccomp
    }
    pub fn describe(&self) -> String {
        match (self.landlock.as_str(), self.seccomp) {
            ("full", true) => "Sandbox active: the worker can only reach the files of this operation and has no network.".into(),
            ("partial", true) => "Sandbox partly active (older kernel): file access is partly restricted, network and programs are blocked.".into(),
            (_, true) => "Sandbox limited: this kernel has no Landlock; network and programs are blocked.".into(),
            _ => "Sandbox unavailable on this system.".into(),
        }
    }
}

/// What the worker may touch.
#[derive(Clone, Debug, Default)]
pub struct Access2 {
    pub read: Vec<PathBuf>,
    pub write: Vec<PathBuf>,
}

const ABI_LATEST: ABI = ABI::V6;

fn landlock(access: &Access2) -> Result<(RulesetStatus, bool), landlock::RulesetError> {
    let abi = ABI_LATEST;
    let mut read: Vec<PathBuf> = access.read.iter().filter(|p| p.exists()).cloned().collect();
    // Time zone data (for zip timestamps) is harmless to read.
    for p in ["/etc/localtime", "/usr/share/zoneinfo"] {
        let p = PathBuf::from(p);
        if p.exists() {
            read.push(p);
        }
    }
    let write: Vec<PathBuf> = access.write.iter().filter(|p| p.exists()).cloned().collect();
    let status = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(abi))?
        .handle_access(AccessNet::from_all(abi))?
        .scope(Scope::from_all(abi))?
        .create()?
        .add_rules(path_beneath_rules(&read, AccessFs::from_read(abi)))?
        .add_rules(path_beneath_rules(&write, AccessFs::from_all(abi)))?
        .restrict_self()?;
    Ok((status.ruleset, status.no_new_privs))
}

fn blocked_syscalls() -> Vec<i64> {
    let mut v = vec![
        // Network and starting programs.
        libc::SYS_socket,
        libc::SYS_socketpair,
        libc::SYS_connect,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_execve,
        libc::SYS_execveat,
        // Other processes: debugging, memory, file descriptors, signals.
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_process_madvise,
        libc::SYS_pidfd_open,
        libc::SYS_pidfd_getfd,
        libc::SYS_pidfd_send_signal,
        libc::SYS_kcmp,
        libc::SYS_tkill,
        libc::SYS_rt_sigqueueinfo,
        libc::SYS_rt_tgsigqueueinfo,
        // Mounts, namespaces, kernel and system state.
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_open_tree,
        libc::SYS_move_mount,
        libc::SYS_fsopen,
        libc::SYS_fsconfig,
        libc::SYS_fsmount,
        libc::SYS_fspick,
        libc::SYS_mount_setattr,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_reboot,
        libc::SYS_kexec_load,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_userfaultfd,
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        libc::SYS_open_by_handle_at,
        libc::SYS_name_to_handle_at,
        libc::SYS_acct,
        libc::SYS_quotactl,
        libc::SYS_mknodat,
    ];
    #[cfg(target_arch = "x86_64")]
    v.extend([libc::SYS_iopl, libc::SYS_ioperm, libc::SYS_kexec_file_load, libc::SYS_mknod, libc::SYS_uselib]);
    v
}

fn target_arch() -> Option<TargetArch> {
    if cfg!(target_arch = "x86_64") {
        Some(TargetArch::x86_64)
    } else if cfg!(target_arch = "aarch64") {
        Some(TargetArch::aarch64)
    } else if cfg!(target_arch = "riscv64") {
        Some(TargetArch::riscv64)
    } else {
        None
    }
}

fn cond(arg: u8, len: SeccompCmpArgLen, op: SeccompCmpOp, value: u64) -> Option<SeccompCondition> {
    SeccompCondition::new(arg, len, op, value).ok()
}

/// Rules that only match some arguments.
#[allow(clippy::unnecessary_cast)] // ioctl numbers have different types per architecture
fn conditional_rules() -> Option<Vec<(i64, Vec<SeccompRule>)>> {
    let pid = u64::from(std::process::id());
    // Typing into the terminal (TIOCSTI) or the Linux console (TIOCLINUX)
    // would let a compromised process run commands in the user's shell.
    // The kernel reads the request as 32 bits, so only those are compared.
    let ioctl = vec![
        SeccompRule::new(vec![cond(1, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, libc::TIOCSTI as u64)?]).ok()?,
        SeccompRule::new(vec![cond(1, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, libc::TIOCLINUX as u64)?]).ok()?,
    ];
    // Signals only to this process (kill(-1) would hit every process of
    // the user on kernels without Landlock signal scoping).
    let kill = vec![SeccompRule::new(vec![cond(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Ne, pid)?]).ok()?];
    let tgkill = vec![SeccompRule::new(vec![cond(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Ne, pid)?]).ok()?];
    // Threads are fine; new namespaces are not.
    let ns = [
        libc::CLONE_NEWUSER,
        libc::CLONE_NEWNS,
        libc::CLONE_NEWNET,
        libc::CLONE_NEWPID,
        libc::CLONE_NEWIPC,
        libc::CLONE_NEWUTS,
        libc::CLONE_NEWCGROUP,
    ];
    let mut clone = Vec::new();
    for f in ns {
        let f = f as u64;
        clone.push(SeccompRule::new(vec![cond(0, SeccompCmpArgLen::Qword, SeccompCmpOp::MaskedEq(f), f)?]).ok()?);
    }
    Some(vec![(libc::SYS_ioctl, ioctl), (libc::SYS_kill, kill), (libc::SYS_tgkill, tgkill), (libc::SYS_clone, clone)])
}

fn compile(rules: BTreeMap<i64, Vec<SeccompRule>>, errno: i32, arch: TargetArch) -> Option<BpfProgram> {
    let filter = SeccompFilter::new(rules, SeccompAction::Allow, SeccompAction::Errno(errno as u32), arch).ok()?;
    filter.try_into().ok()
}

/// On x86_64, x32 system calls carry bit 30 in their number and would not
/// match the numbers above: refuse all of them. Inserted right after the
/// architecture check of a compiled filter.
fn reject_x32(prog: &mut BpfProgram) {
    if cfg!(target_arch = "x86_64") && prog.len() >= 3 {
        // BPF_LD|BPF_W|BPF_ABS, BPF_JMP|BPF_JGE|BPF_K, BPF_RET|BPF_K.
        const LD_W_ABS: u16 = 0x20;
        const JGE_K: u16 = 0x35;
        const RET_K: u16 = 0x06;
        let insns = [
            sock_filter { code: LD_W_ABS, jt: 0, jf: 0, k: 0 },
            sock_filter { code: JGE_K, jt: 0, jf: 1, k: 0x4000_0000 },
            sock_filter { code: RET_K, jt: 0, jf: 0, k: libc::SECCOMP_RET_ERRNO | libc::EPERM as u32 },
        ];
        for (i, ins) in insns.into_iter().enumerate() {
            prog.insert(3 + i, ins);
        }
    }
}

fn seccomp() -> bool {
    let Some(arch) = target_arch() else { return false };
    let Some(cond) = conditional_rules() else { return false };
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = blocked_syscalls().into_iter().map(|s| (s, vec![])).collect();
    rules.extend(cond);
    let Some(mut prog) = compile(rules, libc::EPERM, arch) else { return false };
    reject_x32(&mut prog);
    // clone3 hides its flags in memory a filter cannot read: report it as
    // missing, so the C library falls back to clone, which is checked.
    let Some(clone3) = compile([(libc::SYS_clone3, vec![])].into_iter().collect(), libc::ENOSYS, arch) else { return false };
    seccompiler::apply_filter(&prog).is_ok() && seccompiler::apply_filter(&clone3).is_ok()
}

/// Restricts the current process. Call before starting any thread.
pub fn apply(access: &Access2) -> SandboxStatus {
    // Load the time zone now; afterwards /etc may be unreachable.
    let _ = jiff_warmup();
    let (landlock, nnp) = match landlock(access) {
        Ok((RulesetStatus::FullyEnforced, nnp)) => ("full", nnp),
        Ok((RulesetStatus::PartiallyEnforced, nnp)) => ("partial", nnp),
        Ok((RulesetStatus::NotEnforced, nnp)) => ("unavailable", nnp),
        Err(_) => ("unavailable", false),
    };
    let seccomp = seccomp();
    SandboxStatus { landlock: landlock.into(), seccomp, no_new_privs: nnp }
}

fn jiff_warmup() -> Option<()> {
    let (d, t) = zip67_core::util::unix_to_dos(1_700_000_000);
    zip67_core::util::dos_to_unix(d, t).map(|_| ())
}

/// Applies the sandbox allowing only `allowed`, then checks that it holds.
/// Returns (check, passed). Used by `67z --sandbox-selftest`; it locks down
/// the calling process for good, so run it in a throw-away process.
pub fn selftest(allowed: &std::path::Path) -> (SandboxStatus, Vec<(String, bool)>) {
    let status = apply(&Access2 { read: vec![], write: vec![allowed.to_path_buf()] });
    let mut checks = Vec::new();
    let landlock_on = status.landlock != "unavailable";
    let inside = allowed.join("selftest-ok.txt");
    checks.push(("write inside the allowed folder works".into(), std::fs::write(&inside, b"ok").is_ok()));
    let _ = std::fs::remove_file(&inside);
    if landlock_on {
        checks.push(("reading /etc/passwd is blocked".into(), std::fs::read("/etc/passwd").is_err()));
        let base = allowed.canonicalize().ok().and_then(|p| p.parent().map(std::path::Path::to_path_buf)).unwrap_or_else(std::env::temp_dir);
        let outside = base.join(format!("67zip-selftest-{}", std::process::id()));
        let blocked = std::fs::write(&outside, b"x").is_err();
        let _ = std::fs::remove_file(&outside);
        checks.push(("writing outside the allowed folder is blocked".into(), blocked));
    }
    if status.seccomp {
        let net = std::net::TcpStream::connect(("127.0.0.1", 9));
        checks.push(("opening a network connection is blocked".into(), net.as_ref().err().is_some_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied)));
        let exec = std::process::Command::new("/bin/true").status();
        checks.push(("starting another program is blocked".into(), exec.is_err()));
        // Signal probes (signal 0 only checks permission, it sends nothing).
        let parent = rustix::process::getppid().map(rustix::process::test_kill_process);
        checks.push(("signalling the parent process is blocked".into(), parent.is_none_or(|r| r.is_err())));
        let me = rustix::process::test_kill_process(rustix::process::getpid());
        checks.push(("signalling itself still works".into(), me.is_ok()));
    }
    (status, checks)
}
