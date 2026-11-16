//! Linux L2TPv2/PPP backend. L2TPv2 and CHAP do not encrypt traffic.
use cat4igp_shared::control::L2tpV2TunnelInfo;
use std::{ffi::CString, fs::{self, OpenOptions}, io::{self, Write}, net::Ipv4Addr, os::unix::{fs::{DirBuilderExt, OpenOptionsExt}, process::CommandExt}, path::{Path, PathBuf}, sync::{Arc, Mutex}};
use tokio::{process::Command, sync::oneshot, task::JoinHandle};
use rand08::{rngs::OsRng, RngCore};

fn invalid(message: &'static str) -> io::Error { io::Error::new(io::ErrorKind::InvalidInput, message) }

fn validate_runtime_directory(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o7777 != 0o700 {
        return Err(invalid("unsafe L2TPv2 runtime directory"));
    }
    Ok(())
}

fn runtime_directory(value: Option<std::ffi::OsString>) -> io::Result<PathBuf> {
    match value {
        None => Ok(PathBuf::from("/run")),
        Some(value) if value == std::ffi::OsStr::new("/run/cat4igp-client") => {
            let path = PathBuf::from(value);
            validate_runtime_directory(&path)?;
            Ok(path)
        }
        Some(_) => Err(invalid("unsupported L2TPv2 RUNTIME_DIRECTORY")),
    }
}

// Close the race where the parent exits before the death signal is installed.
fn confine_to_parent(parent: libc::pid_t) -> io::Result<()> {
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } == -1 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::getppid() } != parent {
        return Err(io::Error::other("L2TPv2 parent exited during spawn"));
    }
    Ok(())
}

fn address(value: &str) -> io::Result<Ipv4Addr> {
    let ip: Ipv4Addr = value.parse().map_err(|_| invalid("L2TPv2 addresses must be numeric IPv4 addresses"))?;
    if ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() || ip.octets()[0] == 0 || ip.octets()[0] >= 240 {
        return Err(invalid("invalid L2TPv2 unicast IPv4 address"));
    }
    Ok(ip)
}

fn validate(interface: &str, info: &L2tpV2TunnelInfo) -> io::Result<()> {
    if interface.is_empty() || interface.len() >= libc::IFNAMSIZ || !interface.bytes().all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)) {
        return Err(invalid("invalid PPP interface name"));
    }
    let local = address(&info.local_endpoint)?;
    let remote = address(&info.remote_endpoint)?;
    let local_ppp = address(&info.local_address)?;
    let remote_ppp = address(&info.remote_address)?;
    if local == remote || local_ppp == remote_ppp || info.local_port == 0 || info.remote_port == 0 || !(1280..=if info.wireguard_tunnel_id.is_some() { 65000 } else { 1500 }).contains(&info.mtu) {
        return Err(invalid("invalid L2TPv2 endpoints, PPP addresses, ports or MTU"));
    }
    if info.secret.is_empty() || info.secret.len() > 255 || !info.secret.bytes().all(|b| (b'!'..=b'~').contains(&b) && !b"\\\"#".contains(&b)) {
        return Err(invalid("invalid CHAP secret"));
    }
    Ok(())
}

struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}

fn write_private(path: &Path, content: &str) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
    file.write_all(content.as_bytes())
}

fn configuration(parent: &Path, interface: &str, info: &L2tpV2TunnelInfo, userspace: bool) -> io::Result<Directory> {
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    let dir = loop {
        let path = parent.join(format!("cat4igp-l2tpv2-{:016x}", OsRng.next_u64()));
        match builder.create(&path) {
            Ok(()) => break Directory(path),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    };
    let ppp = dir.0.join("ppp");
    builder.create(&ppp)?;
    write_private(&ppp.join("chap-secrets"), &format!("cat4igp cat4igp {} {}\n", info.secret, info.remote_address))?;
    write_private(&ppp.join("options"), "")?;
    let options = format!("name cat4igp\nremotename cat4igp\nrequire-chap\nrefuse-pap\nrefuse-mschap\nrefuse-mschap-v2\nnoipdefault\nnodefaultroute\nnoipv6\nifname {interface}\nmtu {mtu}\nmru {mtu}\n{local}:{remote}\n", mtu=info.mtu, local=info.local_address, remote=info.remote_address);
    write_private(&dir.0.join("options"), &options)?;
    write_private(&dir.0.join("l2tp-secrets"), "")?;
    let section = if info.initiator {
        format!("[lac peer]\nlns = {}:{}\nautodial = yes\nredial = yes\nredial timeout = 5\n", info.remote_endpoint, info.remote_port)
    } else {
        format!("[lns peer]\nlac = {}\nassign ip = no\nexclusive = yes\n", info.remote_endpoint)
    };
    let config = format!("[global]\nlisten-addr = {}\nport = {}\naccess control = yes\nforce userspace = {}\n{}require authentication = yes\nrequire chap = yes\nrefuse pap = yes\npppoptfile = {}\n", info.local_endpoint, info.local_port, if userspace { "yes" } else { "no" }, section, dir.0.join("options").display());
    write_private(&dir.0.join("xl2tpd.conf"), &config)?;
    Ok(dir)
}

fn process_status(path: &Path) -> io::Result<Option<(libc::pid_t, bool)>> {
    let stat = match fs::read_to_string(path) {
        Ok(stat) => stat,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    // comm may contain whitespace and parentheses; the remaining fields cannot.
    let mut fields = stat.rsplit_once(')').ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid process status"))?.1.split_whitespace();
    let state = fields.next().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing process state"))?;
    let group = fields.nth(1).and_then(|field| field.parse().ok()).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid process group"))?;
    Ok(Some((group, !matches!(state, "Z" | "X" | "x"))))
}

fn group_has_running_members(group: libc::pid_t) -> io::Result<bool> {
    for process in fs::read_dir("/proc")? {
        let process = process?;
        if !process.file_name().as_encoded_bytes().iter().all(u8::is_ascii_digit) { continue; }
        let path = process.path();
        let Some((pid_group, running)) = process_status(&path.join("stat"))? else { continue; };
        if pid_group != group { continue; }
        if running { return Ok(true); }
        // A zombie thread-group leader can still have live threads holding PPP FDs.
        let tasks = match fs::read_dir(path.join("task")) {
            Ok(tasks) => tasks,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        for task in tasks {
            if process_status(&task?.path().join("stat"))?.is_some_and(|(_, running)| running) { return Ok(true); }
        }
    }
    Ok(false)
}

struct OwnedProcessGroup {
    child: tokio::process::Child,
    pid: i32,
    unreaped: bool,
}

impl OwnedProcessGroup {
    async fn leader_exited(&mut self) -> io::Result<()> {
        loop {
            let mut status = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
            let result = unsafe { libc::waitid(libc::P_PID, self.pid as libc::id_t,
                status.as_mut_ptr(), libc::WEXITED | libc::WNOWAIT | libc::WNOHANG) };
            if result == -1 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted { continue; }
                return Err(error);
            }
            if unsafe { status.assume_init().si_pid() } != 0 { return Ok(()); }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    async fn wait(&mut self) -> io::Result<()> {
        // Keep the unreaped leader pinning the PGID until every member has closed
        // its resources. Waiting for leader exit alone does not wait for pppd.
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while group_has_running_members(self.pid)? {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            Ok::<_, io::Error>(())
        }).await.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "owned L2TPv2 process group did not exit"))??;
        let result = self.child.wait().await;
        self.unreaped = false;
        result.map(|_| ())
    }
}

impl Drop for OwnedProcessGroup {
    fn drop(&mut self) {
        // Tokio only reaps an owned Child when wait/try_wait is polled, not on SIGCHLD.
        // Keep ownership until after signaling, including cancellation of the worker.
        if self.unreaped && self.child.id() == Some(self.pid as u32) { unsafe { libc::kill(-self.pid, libc::SIGKILL); } }
    }
}

async fn supervise(mut group: OwnedProcessGroup, stopped: oneshot::Receiver<()>, failure: Arc<Mutex<Option<String>>>) {
    if group.child.id() != Some(group.pid as u32) {
        group.unreaped = false;
        *failure.lock().unwrap() = Some("xl2tpd ownership mismatch; refusing process-group cleanup".into());
        return;
    }
    let unexpected = tokio::select! {
        result = group.leader_exited() => {
            match result {
                Ok(()) => Some("xl2tpd exited unexpectedly".to_string()),
                Err(error) => {
                    // Ownership is uncertain; do not signal a potentially reused PGID.
                    group.unreaped = false;
                    *failure.lock().unwrap() = Some(format!("observing xl2tpd exit: {error}"));
                    return;
                }
            }
        }
        _ = stopped => None,
    };
    // WNOWAIT leaves the owned leader unreaped, pinning its PID and PGID while
    // surviving members are signaled. Helpers that escaped the group are not covered.
    let result = if unsafe { libc::kill(-group.pid, libc::SIGKILL) } == -1 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) { Ok(()) } else { Err(error) }
    } else { Ok(()) };
    let result = match result { Ok(()) => group.wait().await, Err(error) => Err(error) };
    *failure.lock().unwrap() = match result {
        Ok(()) => unexpected,
        Err(error) => Some(format!("cleaning up xl2tpd process group: {error}")),
    };
}

/// One independently supervised xl2tpd instance. setup requires root privileges,
/// xl2tpd, pppd, /etc/ppp and Linux mount namespaces. PPP stays in the host
/// network namespace. The caller must explicitly opt in to unencrypted L2TPv2.
/// Cleanup waits for the owned process group to release its resources before
/// reaping the leader, including unexpected leader exit. A pppd that changes
/// groups requires operator cleanup; SIGKILL of the client cannot run this
/// supervisor's cleanup.
pub struct L2tpV2Tunnel {
    interface: String,
    info: L2tpV2TunnelInfo,
    userspace: bool,
    worker: Option<JoinHandle<()>>,
    shutdown: Option<oneshot::Sender<()>>,
    failure: Arc<Mutex<Option<String>>>,
}

impl L2tpV2Tunnel {
    pub fn new(interface: String, info: L2tpV2TunnelInfo, userspace: bool) -> io::Result<Self> {
        validate(&interface, &info)?;
        // xl2tpd uses a 4096-byte userspace packet buffer; leave room for framing.
        if userspace && info.mtu > 4000 {
            return Err(invalid("userspace L2TPv2 MTU must not exceed 4000"));
        }
        Ok(Self { interface, info, userspace, worker: None, shutdown: None, failure: Arc::new(Mutex::new(None)) })
    }

    pub fn interface(&self) -> &str { &self.interface }

    pub fn is_connected(&self) -> io::Result<bool> {
        if let Some(error) = self.failure.lock().unwrap().as_ref() {
            return Err(io::Error::other(error.clone()));
        }
        if self.worker.as_ref().is_none_or(|worker| worker.is_finished()) { return Ok(false); }
        let name = CString::new(self.interface.as_str()).map_err(|_| invalid("invalid PPP interface name"))?;
        Ok(unsafe { libc::if_nametoindex(name.as_ptr()) } != 0)
    }

    pub async fn setup(&mut self) -> io::Result<()> {
        if self.shutdown.is_some() && self.worker.as_ref().is_some_and(|worker| !worker.is_finished()) {
            return Ok(());
        }
        if let Some(worker) = self.worker.as_mut() {
            let result = worker.await;
            self.worker.take();
            if let Err(error) = result { *self.failure.lock().unwrap() = Some(format!("L2TPv2 supervisor failed: {error}")); }
        }
        if let Some(error) = self.failure.lock().unwrap().as_ref() { return Err(io::Error::other(error.clone())); }
        let name = CString::new(self.interface.as_str()).map_err(|_| invalid("invalid PPP interface name"))?;
        if unsafe { libc::if_nametoindex(name.as_ptr()) } != 0 {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, "PPP interface already exists"));
        }
        // systemd removes its private runtime tree after cgroup shutdown. Unmanaged
        // installations retain /run and require operator cleanup after a crash.
        let runtime = runtime_directory(std::env::var_os("RUNTIME_DIRECTORY"))?;
        let dir = configuration(&runtime, &self.interface, &self.info, self.userspace)?;
        let source = CString::new(dir.0.join("ppp").as_os_str().as_encoded_bytes()).map_err(|_| invalid("invalid configuration path"))?;
        let mut command = Command::new("xl2tpd");
        command.arg("-D").arg("-c").arg(dir.0.join("xl2tpd.conf"))
            .arg("-s").arg(dir.0.join("l2tp-secrets"))
            .arg("-p").arg(dir.0.join("xl2tpd.pid"))
            .arg("-C").arg(dir.0.join("control"));
        let parent = unsafe { libc::getpid() };
        unsafe {
            command.as_std_mut().pre_exec(move || {
                confine_to_parent(parent)?;
                if libc::setsid() == -1 || libc::unshare(libc::CLONE_NEWNS) == -1 {
                    return Err(io::Error::last_os_error());
                }
                if libc::mount(std::ptr::null(), c"/".as_ptr(), std::ptr::null(), libc::MS_REC | libc::MS_PRIVATE, std::ptr::null()) == -1
                    || libc::mount(source.as_ptr(), c"/etc/ppp".as_ptr(), std::ptr::null(), libc::MS_BIND | libc::MS_REC, std::ptr::null()) == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn()?;
        let pid = child.id().ok_or_else(|| io::Error::other("xl2tpd has no process id"))? as i32;
        let group = OwnedProcessGroup { child, pid, unreaped: true };
        let (shutdown, stopped) = oneshot::channel();
        *self.failure.lock().unwrap() = None;
        let failure = self.failure.clone();
        self.worker = Some(tokio::spawn(async move {
            supervise(group, stopped, failure).await;
            drop(dir);
        }));
        self.shutdown = Some(shutdown);
        Ok(())
    }

    pub async fn destroy(&mut self) -> io::Result<()> {
        if let Some(shutdown) = self.shutdown.take() { let _ = shutdown.send(()); }
        if let Some(worker) = self.worker.as_mut() {
            let result = worker.await;
            self.worker.take();
            if let Err(error) = result { *self.failure.lock().unwrap() = Some(format!("L2TPv2 supervisor failed: {error}")); }
        }
        self.failure.lock().unwrap().as_ref().map_or(Ok(()), |error| Err(io::Error::other(error.clone())))
    }
}

impl Drop for L2tpV2Tunnel {
    fn drop(&mut self) { if let Some(shutdown) = self.shutdown.take() { let _ = shutdown.send(()); } }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn runtime_directory_rejects_unsafe_paths_and_metadata() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        assert_eq!(runtime_directory(None).unwrap(), Path::new("/run"));
        for path in ["", "/tmp", "/run/cat4igp-client/", "/run/cat4igp-client:/tmp"] {
            assert!(runtime_directory(Some(path.into())).is_err());
        }
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        validate_runtime_directory(directory.path()).unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o750)).unwrap();
        assert!(validate_runtime_directory(directory.path()).is_err());
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let link = directory.path().join("link");
        symlink(directory.path(), &link).unwrap();
        assert!(validate_runtime_directory(&link).is_err());
        let file = directory.path().join("file");
        fs::write(&file, "").unwrap();
        assert!(validate_runtime_directory(&file).is_err());
        assert!(validate_runtime_directory(&directory.path().join("missing")).is_err());
        if unsafe { libc::geteuid() } == 0 {
            let path = CString::new(directory.path().as_os_str().as_encoded_bytes()).unwrap();
            assert_eq!(unsafe { libc::chown(path.as_ptr(), 65534, !0 as libc::gid_t) }, 0);
            assert!(validate_runtime_directory(directory.path()).is_err());
            assert_eq!(unsafe { libc::chown(path.as_ptr(), 0, !0 as libc::gid_t) }, 0);
        }
    }


    fn session_child(program: &str, args: &[&str]) -> tokio::process::Child {
        let mut command = Command::new(program);
        command.args(args);
        unsafe {
            command.as_std_mut().pre_exec(|| {
                if libc::setsid() == -1 { return Err(io::Error::last_os_error()); }
                Ok(())
            });
        }
        command.spawn().unwrap()
    }

    #[tokio::test]
    async fn waits_for_descendants_before_reaping_the_group_leader() {
        use std::process::Stdio;
        use tokio::io::AsyncReadExt;
        let mut command = Command::new("sh");
        command.args(["-c", "sleep 60 </dev/null >/dev/null 2>&1 & echo $!"]).stdout(Stdio::piped());
        unsafe {
            command.as_std_mut().pre_exec(|| {
                if libc::setsid() == -1 { return Err(io::Error::last_os_error()); }
                Ok(())
            });
        }
        let mut child = command.spawn().unwrap();
        let pid = child.id().unwrap() as i32;
        let mut output = String::new();
        child.stdout.take().unwrap().read_to_string(&mut output).await.unwrap();
        let descendant: i32 = output.trim().parse().unwrap();
        let mut group = OwnedProcessGroup { child, pid, unreaped: true };
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while process_status(&PathBuf::from(format!("/proc/{pid}/stat"))).unwrap().unwrap().1 {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }).await.unwrap();
        assert!(group_has_running_members(pid).unwrap());
        assert!(tokio::time::timeout(std::time::Duration::from_millis(50), group.wait()).await.is_err(), "leader exit completed cleanup while its descendant was alive");
        assert!(group.unreaped, "waiting reaped the leader before its descendant exited");
        assert_eq!(unsafe { libc::kill(-pid, libc::SIGKILL) }, 0);
        group.wait().await.unwrap();
        assert!(!group.unreaped);
        assert!(!process_status(&PathBuf::from(format!("/proc/{descendant}/stat"))).unwrap().is_some_and(|(_, running)| running));
    }

    #[tokio::test]
    async fn unexpected_leader_exit_terminates_remaining_group_members() {
        use std::process::Stdio;
        use tokio::io::AsyncReadExt;
        let mut command = Command::new("sh");
        command.args(["-c", "sleep 60 </dev/null >/dev/null 2>&1 & echo $!"]).stdout(Stdio::piped());
        unsafe {
            command.as_std_mut().pre_exec(|| {
                if libc::setsid() == -1 { return Err(io::Error::last_os_error()); }
                Ok(())
            });
        }
        let mut child = command.spawn().unwrap();
        let pid = child.id().unwrap() as i32;
        let mut output = String::new();
        child.stdout.take().unwrap().read_to_string(&mut output).await.unwrap();
        let descendant: i32 = output.trim().parse().unwrap();
        let mut group = OwnedProcessGroup { child, pid, unreaped: true };
        group.leader_exited().await.unwrap();
        assert!(group_has_running_members(pid).unwrap());
        let (_shutdown, stopped) = oneshot::channel();
        let failure = Arc::new(Mutex::new(None));
        tokio::time::timeout(std::time::Duration::from_secs(6), supervise(group, stopped, failure.clone())).await.unwrap();
        assert!(failure.lock().unwrap().as_ref().unwrap().contains("exited unexpectedly"));
        assert!(!process_status(&PathBuf::from(format!("/proc/{descendant}/stat"))).unwrap().is_some_and(|(_, running)| running));
        assert!(process_status(&PathBuf::from(format!("/proc/{pid}/stat"))).unwrap().is_none(), "owned leader was not reaped");
    }

    #[test]
    fn parses_process_status_with_parentheses_and_whitespace_in_comm() {
        let file = tempfile::NamedTempFile::new().unwrap();
        fs::write(file.path(), "123 (a ) (name\n with spaces) Z 1 456 456 0 -1\n").unwrap();
        assert_eq!(process_status(file.path()).unwrap(), Some((456, false)));
        fs::write(file.path(), "123 (a ) (name\n with spaces) S 1 456 456 0 -1\n").unwrap();
        assert_eq!(process_status(file.path()).unwrap(), Some((456, true)));
        fs::write(file.path(), "invalid").unwrap();
        assert!(process_status(file.path()).is_err());
    }

    #[tokio::test]
    async fn destroy_and_setup_preserve_supervisor_failure() {
        let mut tunnel = L2tpV2Tunnel::new("ppp-test".into(), info(), false).unwrap();
        let failure = tunnel.failure.clone();
        tunnel.worker = Some(tokio::spawn(async move {
            *failure.lock().unwrap() = Some("cleanup failed".into());
        }));
        for _ in 0..2 { assert!(tunnel.destroy().await.unwrap_err().to_string().contains("cleanup failed")); }
        assert!(tunnel.setup().await.unwrap_err().to_string().contains("cleanup failed"));
    }

    #[tokio::test]
    async fn exited_leader_does_not_signal_a_reused_group() {
        let unrelated = session_child("sleep", &["60"]);
        let unrelated_pid = unrelated.id().unwrap() as i32;
        let mut unrelated = OwnedProcessGroup { child: unrelated, pid: unrelated_pid, unreaped: true };
        let child = session_child("true", &[]);
        let group = OwnedProcessGroup { child, pid: unrelated_pid, unreaped: true };
        let (_shutdown, stopped) = oneshot::channel();
        let failure = Arc::new(Mutex::new(None));
        // Simulate the old numeric PGID now naming an unrelated live process group.
        tokio::time::timeout(std::time::Duration::from_secs(5), supervise(group, stopped, failure.clone())).await.unwrap();
        assert!(failure.lock().unwrap().as_ref().unwrap().contains("ownership mismatch"));
        assert!(unrelated.child.try_wait().unwrap().is_none(), "unrelated process group was signaled");
        unsafe { libc::kill(-unrelated_pid, libc::SIGKILL); }
        unrelated.child.wait().await.unwrap();
        unrelated.unreaped = false;
    }

    #[tokio::test]
    async fn shutdown_and_worker_cancellation_terminate_the_owned_group() {
        for cancel in [false, true] {
            let child = session_child("sleep", &["60"]);
            let pid = child.id().unwrap() as i32;
            let group = OwnedProcessGroup { child, pid, unreaped: true };
            let (shutdown, stopped) = oneshot::channel();
            let failure = Arc::new(Mutex::new(None));
            let worker = tokio::spawn(supervise(group, stopped, failure.clone()));
            if cancel { worker.abort(); } else { shutdown.send(()).unwrap(); }
            let result = tokio::time::timeout(std::time::Duration::from_secs(5), worker).await.unwrap();
            if cancel { assert!(result.unwrap_err().is_cancelled()); } else { result.unwrap(); }
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                while unsafe { libc::kill(pid, 0) } == 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
                assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
            }).await.unwrap();
            assert!(failure.lock().unwrap().is_none());
        }
    }

    #[tokio::test]
    async fn cancelled_destroy_keeps_supervisor_until_cleanup_finishes() {
        let mut tunnel = L2tpV2Tunnel::new("ppp-test".into(), info(), false).unwrap();
        let (shutdown, stopped) = oneshot::channel();
        let (acknowledge, acknowledged) = oneshot::channel();
        let (release, released) = oneshot::channel();
        tunnel.shutdown = Some(shutdown);
        tunnel.worker = Some(tokio::spawn(async move {
            let _ = stopped.await;
            acknowledge.send(()).unwrap();
            let _ = released.await;
        }));
        {
            let destroy = tunnel.destroy();
            tokio::pin!(destroy);
            tokio::select! {
                result = &mut destroy => panic!("destroy returned before cleanup: {result:?}"),
                result = acknowledged => result.unwrap(),
            }
        }
        assert!(tunnel.worker.as_ref().is_some_and(|worker| !worker.is_finished()));
        {
            let setup = tunnel.setup();
            tokio::pin!(setup);
            tokio::select! {
                biased;
                result = &mut setup => panic!("setup returned before cleanup: {result:?}"),
                _ = std::future::ready(()) => {},
            }
        }
        assert!(tunnel.worker.as_ref().is_some_and(|worker| !worker.is_finished()));
        release.send(()).unwrap();
        tunnel.destroy().await.unwrap();
        assert!(tunnel.worker.is_none());
    }

    #[test]
    fn runtime_teardown_terminates_an_unpolled_supervisor() {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let pid = {
            let _entered = runtime.enter();
            let child = session_child("sleep", &["60"]);
            let pid = child.id().unwrap() as i32;
            let group = OwnedProcessGroup { child, pid, unreaped: true };
            let (_shutdown, stopped) = oneshot::channel();
            runtime.spawn(supervise(group, stopped, Arc::new(Mutex::new(None))));
            pid
        };
        drop(runtime);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let mut status = 0;
            let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            if result == pid {
                assert!(libc::WIFSIGNALED(status));
                assert_eq!(libc::WTERMSIG(status), libc::SIGKILL);
                break;
            }
            // Another Tokio runtime may already have drained the orphan queue.
            if result == -1 {
                assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ECHILD));
                break;
            }
            assert!(std::time::Instant::now() < deadline, "xl2tpd child survived runtime teardown");
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    #[test]
    fn parent_death_signal_is_installed_and_parent_race_fails_closed() {
        use std::os::unix::process::CommandExt;
        let parent = unsafe { libc::getpid() };
        let mut command = std::process::Command::new("true");
        unsafe {
            command.pre_exec(move || {
                confine_to_parent(parent)?;
                let mut signal = 0;
                if libc::prctl(libc::PR_GET_PDEATHSIG, &mut signal) == -1 {
                    return Err(io::Error::last_os_error());
                }
                if signal != libc::SIGKILL { return Err(io::Error::other("parent-death signal not installed")); }
                Ok(())
            });
        }
        assert!(command.status().unwrap().success());

        let mut command = std::process::Command::new("true");
        unsafe { command.pre_exec(|| confine_to_parent(0)); }
        assert!(command.spawn().is_err());
    }

    fn info() -> L2tpV2TunnelInfo {
        L2tpV2TunnelInfo { tunnel_id: 1, peer_node_id: 2, local_endpoint: "192.0.2.1".into(), remote_endpoint: "192.0.2.2".into(), local_port: 1701, remote_port: 1702, local_address: "10.0.0.1".into(), remote_address: "10.0.0.2".into(), secret: "test-secret".into(), mtu: 1400, initiator: true, wireguard_tunnel_id: None }
    }

    #[test]
    fn validates_untrusted_configuration() {
        assert!(validate("ppp-test", &info()).is_ok());
        let mut value = info();
        value.secret = "secret\ninjected".into();
        assert!(validate("ppp-test", &value).is_err());
        value = info(); value.remote_endpoint = "::1".into();
        assert!(validate("ppp-test", &value).is_err());
        value = info(); value.remote_address = value.local_address.clone();
        assert!(validate("ppp-test", &value).is_err());
        value = info(); value.remote_port = 0;
        assert!(validate("ppp-test", &value).is_err());
        value = info(); value.mtu = 9000;
        assert!(validate("ppp-test", &value).is_err());
        value.wireguard_tunnel_id = Some(1);
        assert!(validate("ppp-test", &value).is_ok());
        value.mtu = 65001;
        assert!(validate("ppp-test", &value).is_err());
        assert!(validate("../ppp", &info()).is_err());
        value.mtu = 4000;
        assert!(L2tpV2Tunnel::new("ppp-test".into(), value.clone(), true).is_ok());
        value.mtu = 4001;
        assert!(L2tpV2Tunnel::new("ppp-test".into(), value.clone(), true).is_err());
        assert!(L2tpV2Tunnel::new("ppp-test".into(), value, false).is_ok());
    }

    #[test]
    fn generates_private_configuration_for_both_roles() {
        use std::os::unix::fs::PermissionsExt;
        let parent = tempfile::tempdir().unwrap();
        for (initiator, userspace) in [(true, false), (true, true), (false, false), (false, true)] {
            let mut value = info(); value.initiator = initiator;
            let dir = configuration(parent.path(), "ppp-test", &value, userspace).unwrap();
            assert_eq!(fs::metadata(&dir.0).unwrap().permissions().mode() & 0o777, 0o700);
            assert_eq!(fs::metadata(dir.0.join("ppp/chap-secrets")).unwrap().permissions().mode() & 0o777, 0o600);
            let config = fs::read_to_string(dir.0.join("xl2tpd.conf")).unwrap();
            assert!(config.contains(if initiator { "lns = 192.0.2.2:1702" } else { "lac = 192.0.2.2" }));
            assert!(config.contains(if userspace { "force userspace = yes\n" } else { "force userspace = no\n" }));
            let options = fs::read_to_string(dir.0.join("options")).unwrap();
            assert!(options.contains("require-chap\n"));
            assert!(!options.contains("noauth\n"));
            let path = dir.0.clone(); drop(dir);
            assert!(!path.exists());
        }
    }

    #[tokio::test]
    #[ignore = "requires root, xl2tpd, pppd and Linux mount namespaces"]
    async fn ppp_session_transfers_packets_and_cleans_up() {
        let initiator = std::env::var("CAT4IGP_PPP_TEST_ROLE").expect("set CAT4IGP_PPP_TEST_ROLE to caller or listener") == "caller";
        let mut value = info();
        value.local_endpoint = if initiator { "198.18.0.1" } else { "198.18.0.2" }.into();
        value.remote_endpoint = if initiator { "198.18.0.2" } else { "198.18.0.1" }.into();
        value.local_address = if initiator { "10.241.0.1" } else { "10.241.0.2" }.into();
        value.remote_address = if initiator { "10.241.0.2" } else { "10.241.0.1" }.into();
        value.local_port = 31701; value.remote_port = 31701; value.initiator = initiator;
        if std::env::var_os("CAT4IGP_PPP_TEST_JUMBO").is_some() { value.mtu = 9000; value.wireguard_tunnel_id = Some(1); }
        let mut policy = if std::env::var_os("CAT4IGP_PPP_TEST_POLICY").is_some() {
            let local = value.local_endpoint.parse().unwrap();
            let remote = value.remote_endpoint.parse().unwrap();
            let policy = crate::daemon::l2tp_v2_policy::Policy::setup("wgtest", local, remote, 123).await.map_err(|(e, _)| e).unwrap();
            let status = std::process::Command::new("ip").args(["address", "add", &format!("{local}/32"), "dev", "wgtest"]).status().unwrap();
            assert!(status.success());
            Some(policy)
        } else { None };
        let mut tunnel = L2tpV2Tunnel::new("catppptest".into(), value, std::env::var_os("CAT4IGP_PPP_TEST_USERSPACE").is_some()).unwrap();
        tunnel.setup().await.unwrap();
        let connected = tokio::time::timeout(std::time::Duration::from_secs(30), async {
            loop {
                let expected_mtu = if std::env::var_os("CAT4IGP_PPP_TEST_JUMBO").is_some() { "9000" } else { "1400" };
                let address = if initiator { "10.241.0.1" } else { "10.241.0.2" };
                let configured = std::process::Command::new("ip").args(["-4", "-o", "address", "show", "dev", "catppptest"]).output().is_ok_and(|output| output.status.success() && String::from_utf8_lossy(&output.stdout).split_whitespace().any(|word| word == address || word.starts_with(&format!("{address}/"))));
                if tunnel.is_connected().unwrap() && configured && std::fs::read_to_string("/sys/class/net/catppptest/mtu").is_ok_and(|mtu| mtu.trim() == expected_mtu) { break; }
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }
        }).await;
        if connected.is_ok() && std::env::var_os("CAT4IGP_PPP_TEST_JUMBO").is_some() {
            let mtu = std::fs::read_to_string("/sys/class/net/catppptest/mtu").unwrap();
            assert_eq!(mtu.trim(), "9000");
        }
        let ping = if initiator && connected.is_ok() {
            Some(tokio::process::Command::new("ping").args(["-c", "3", "-w", "12", "-W", "2", "-s", if std::env::var_os("CAT4IGP_PPP_TEST_JUMBO").is_some() { "8000" } else { "56" }, "-M", "do", "-I", "catppptest", "10.241.0.2"]).status().await.unwrap())
        } else {
            if connected.is_ok() { tokio::time::sleep(std::time::Duration::from_secs(40)).await; }
            None
        };
        tunnel.destroy().await.unwrap();
        if let Some(policy) = &mut policy {
            let local = if initiator { "198.18.0.1/32" } else { "198.18.0.2/32" };
            assert!(std::process::Command::new("ip").args(["address", "del", local, "dev", "wgtest"]).status().unwrap().success());
            policy.destroy().await.unwrap();
        }
        assert!(connected.is_ok(), "PPP negotiation timed out");
        if let Some(status) = ping { assert!(status.success(), "PPP packets did not pass"); }
        let name = CString::new("catppptest").unwrap();
        assert_eq!(unsafe { libc::if_nametoindex(name.as_ptr()) }, 0, "PPP interface survived tunnel destruction");
        assert!(!tunnel.is_connected().unwrap());
    }
}
