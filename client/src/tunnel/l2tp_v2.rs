//! Linux L2TPv2/PPP backend. L2TPv2 and CHAP do not encrypt traffic.
use cat4igp_shared::control::L2tpV2TunnelInfo;
use std::{ffi::CString, fs::{self, OpenOptions}, io::{self, Write}, net::Ipv4Addr, os::unix::{fs::{DirBuilderExt, OpenOptionsExt}, process::CommandExt}, path::{Path, PathBuf}, sync::{Arc, Mutex}};
use tokio::{process::Command, sync::oneshot, task::JoinHandle};
use rand08::{rngs::OsRng, RngCore};

fn invalid(message: &'static str) -> io::Error { io::Error::new(io::ErrorKind::InvalidInput, message) }

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

/// One independently supervised xl2tpd instance. setup requires root privileges,
/// xl2tpd, pppd, /etc/ppp and Linux mount namespaces. PPP stays in the host
/// network namespace. The caller must explicitly opt in to unencrypted L2TPv2.
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
        if self.worker.as_ref().is_some_and(|worker| !worker.is_finished()) {
            return Ok(());
        }
        if let Some(worker) = self.worker.take() { let _ = worker.await; }
        let name = CString::new(self.interface.as_str()).map_err(|_| invalid("invalid PPP interface name"))?;
        if unsafe { libc::if_nametoindex(name.as_ptr()) } != 0 {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, "PPP interface already exists"));
        }
        let dir = configuration(Path::new("/run"), &self.interface, &self.info, self.userspace)?;
        let source = CString::new(dir.0.join("ppp").as_os_str().as_encoded_bytes()).map_err(|_| invalid("invalid configuration path"))?;
        let mut command = Command::new("xl2tpd");
        command.arg("-D").arg("-c").arg(dir.0.join("xl2tpd.conf"))
            .arg("-s").arg(dir.0.join("l2tp-secrets"))
            .arg("-p").arg(dir.0.join("xl2tpd.pid"))
            .arg("-C").arg(dir.0.join("control"))
            .kill_on_drop(true);
        unsafe {
            command.as_std_mut().pre_exec(move || {
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
        let mut child = command.spawn()?;
        let pid = child.id().ok_or_else(|| io::Error::other("xl2tpd has no process id"))? as i32;
        let (shutdown, stopped) = oneshot::channel();
        *self.failure.lock().unwrap() = None;
        let failure = self.failure.clone();
        self.worker = Some(tokio::spawn(async move {
            tokio::select! {
                result = child.wait() => {
                    *failure.lock().unwrap() = Some(match result {
                        Ok(status) => format!("xl2tpd exited unexpectedly: {status}"),
                        Err(error) => format!("waiting for xl2tpd: {error}"),
                    });
                }
                _ = stopped => {}
            }
            // pppd inherits the session/process group; terminate it even if xl2tpd died first.
            unsafe { libc::kill(-pid, libc::SIGKILL); }
            let _ = child.wait().await;
            drop(dir);
        }));
        self.shutdown = Some(shutdown);
        Ok(())
    }

    pub async fn destroy(&mut self) -> io::Result<()> {
        if let Some(shutdown) = self.shutdown.take() { let _ = shutdown.send(()); }
        if let Some(worker) = self.worker.take() {
            worker.await.map_err(|e| io::Error::other(format!("L2TPv2 supervisor failed: {e}")))?;
        }
        *self.failure.lock().unwrap() = None;
        Ok(())
    }
}

impl Drop for L2tpV2Tunnel {
    fn drop(&mut self) { if let Some(shutdown) = self.shutdown.take() { let _ = shutdown.send(()); } }
}

#[cfg(test)]
mod tests {
    use super::*;

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
                if tunnel.is_connected().unwrap() && std::fs::read_to_string("/sys/class/net/catppptest/mtu").is_ok_and(|mtu| mtu.trim() == expected_mtu) { break; }
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
        assert!(!tunnel.is_connected().unwrap());
    }
}
