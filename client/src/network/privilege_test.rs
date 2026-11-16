use std::{io, process::Command};

#[repr(C)]
struct CapHeader { version: u32, pid: i32 }
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapData { effective: u32, permitted: u32, inheritable: u32 }

#[tokio::test(flavor = "current_thread")]
async fn backends_fail_closed_without_capabilities() {
    const CHILD: &str = "CAT4IGP_PRIVILEGE_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        use std::os::unix::process::CommandExt;
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.args(["--exact", "network::privilege_test::backends_fail_closed_without_capabilities", "--nocapture"])
            .env(CHILD, "1");
        // Drop in the child, never in the test runner; no_new_privs prevents
        // exec (including UID 0's legacy rules) from restoring capabilities.
        unsafe {
            command.pre_exec(|| {
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1 {
                    return Err(io::Error::last_os_error());
                }
                let header = CapHeader { version: 0x2008_0522, pid: 0 };
                let data = [CapData::default(); 2];
                if libc::syscall(libc::SYS_capset, &header, data.as_ptr()) == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let output = command.output().unwrap();
        assert!(output.status.success(), "{}\n{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
        return;
    }

    let mut header = CapHeader { version: 0x2008_0522, pid: 0 };
    let mut data = [CapData::default(); 2];
    assert_eq!(unsafe { libc::syscall(libc::SYS_capget, &mut header, data.as_mut_ptr()) }, 0);
    assert!(data.iter().all(|caps| caps.effective == 0 && caps.permitted == 0 && caps.inheritable == 0));

    let error = match super::faketcp::FakeTcp::start(
        51820, "127.0.0.1:51821".parse().unwrap(), "127.0.0.1:51822".parse().unwrap(), [7; 32],
    ).await {
        Ok(_) => panic!("FakeTCP started without CAP_NET_RAW"),
        Err(error) => error,
    };
    assert_eq!(error.raw_os_error(), Some(libc::EPERM), "raw-socket denial was not propagated: {error}");

    use crate::tunnel::{shared::Tunnel, wireguard::WireGuardTunnel};
    let name = format!("deny{:x}", std::process::id());
    let interface = std::ffi::CString::new(name.as_str()).unwrap();
    assert_eq!(unsafe { libc::if_nametoindex(interface.as_ptr()) }, 0);
    let mut tunnel = WireGuardTunnel::new(
        name, wireguard_control::Key::generate_private().to_base64(),
        wireguard_control::Key::generate_private().get_public().to_base64(), None, None,
    );
    assert!(tunnel.setup().await.is_err(), "WireGuard setup succeeded without CAP_NET_ADMIN");
    assert_eq!(unsafe { libc::if_nametoindex(interface.as_ptr()) }, 0, "failed setup left an interface");
    tunnel.destroy().await.unwrap();

    let name = format!("l3deny{:x}", std::process::id());
    let interface = std::ffi::CString::new(name.as_str()).unwrap();
    assert_eq!(unsafe { libc::if_nametoindex(interface.as_ptr()) }, 0);
    let reservation = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let local = reservation.local_addr().unwrap();
    let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    drop(reservation);
    let mut tunnel = crate::tunnel::l2tp::L2tpTunnel::new(
        name, 1, local, peer.local_addr().unwrap(),
        std::num::NonZeroU32::new(1).unwrap(), std::num::NonZeroU32::new(2).unwrap(),
        [1; 8], [2; 8], 1400, None,
    );
    for _ in 0..2 {
        let error = tunnel.setup().await.expect_err("L2TPv3 started without CAP_NET_ADMIN");
        let error = error.downcast_ref::<io::Error>().expect("L2TPv3 lost the OS denial");
        // Minimal hosts may not expose /dev/net/tun at all.
        assert!(matches!(error.raw_os_error(), Some(libc::EPERM | libc::EACCES | libc::ENOENT | libc::ENODEV)), "unexpected L2TPv3 setup error: {error}");
        assert!(!tunnel.is_ift_created());
        assert!(!tunnel.is_connected().unwrap());
        assert_eq!(unsafe { libc::if_nametoindex(interface.as_ptr()) }, 0);
        // Check before destroy: failed setup must release its already-bound UDP socket.
        let rebound = std::net::UdpSocket::bind(local).expect("failed L2TPv3 setup leaked its UDP socket");
        tunnel.destroy().await.unwrap();
        tunnel.destroy().await.unwrap();
        drop(rebound);
    }

    // Supply an executable path, not an installed xl2tpd dependency. With zero
    // capabilities the mount-namespace pre_exec must fail before it can execute.
    let helpers = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(std::env::current_exe().unwrap(), helpers.path().join("xl2tpd")).unwrap();
    // This isolated child runs exactly one test; leave the parent runner's PATH alone.
    unsafe { std::env::set_var("PATH", helpers.path()); }
    for userspace in [false, true] {
        let name = format!("l2deny{:x}", std::process::id());
        let interface = std::ffi::CString::new(name.as_str()).unwrap();
        assert_eq!(unsafe { libc::if_nametoindex(interface.as_ptr()) }, 0);
        let info = cat4igp_shared::control::L2tpV2TunnelInfo {
            tunnel_id: 1, peer_node_id: 2, wireguard_tunnel_id: None,
            local_endpoint: "127.0.0.1".into(), remote_endpoint: "127.0.0.2".into(),
            local_port: 1701, remote_port: 1701,
            local_address: "192.0.2.1".into(), remote_address: "192.0.2.2".into(),
            secret: "capability-test".into(), mtu: 1400, initiator: true,
        };
        let mut tunnel = crate::tunnel::l2tp_v2::L2tpV2Tunnel::new(name.clone(), info, userspace).unwrap();
        for _ in 0..2 {
            let error = tunnel.setup().await.expect_err("L2TPv2 started without CAP_SYS_ADMIN");
            // Non-root fails creating /run configuration; root with zero caps
            // reaches unshare and gets EPERM. Neither may reach the executable.
            assert!(matches!(error.raw_os_error(), Some(libc::EPERM | libc::EACCES)), "unexpected L2TPv2 setup error: {error}");
            assert!(!tunnel.is_connected().unwrap());
            assert_eq!(unsafe { libc::if_nametoindex(interface.as_ptr()) }, 0);
            for entry in std::fs::read_dir("/run").unwrap() {
                let entry = entry.unwrap();
                if entry.file_name().as_encoded_bytes().starts_with(b"cat4igp-l2tpv2-") {
                    if let Ok(options) = std::fs::read_to_string(entry.path().join("options")) {
                        assert!(!options.lines().any(|line| line == format!("ifname {name}")), "failed L2TPv2 setup leaked configuration");
                    }
                }
            }
            let mut status = 0;
            assert_eq!(unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) }, -1, "failed L2TPv2 setup leaked a child");
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ECHILD));
            tunnel.destroy().await.unwrap();
            tunnel.destroy().await.unwrap();
            assert!(!tunnel.is_connected().unwrap());
        }
    }
}

// These profiles cover individual backends, not the privileges of the whole daemon.
fn selective_child(filter: &str, marker: &str, capabilities: u64) -> bool {
    if std::env::var_os(marker).is_some() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let mut header = CapHeader { version: 0x2008_0522, pid: 0 };
        let mut data = [CapData::default(); 2];
        assert_eq!(unsafe { libc::syscall(libc::SYS_capget, &mut header, data.as_mut_ptr()) }, 0);
        for (index, caps) in data.iter().enumerate() {
            let expected = (capabilities >> (index * 32)) as u32;
            assert_eq!(caps.effective, expected);
            assert_eq!(caps.permitted, expected);
            assert_eq!(caps.inheritable, 0);
        }
        for cap in 0..64 {
            let result = unsafe { libc::prctl(libc::PR_CAPBSET_READ, cap, 0, 0, 0) };
            if result >= 0 { assert_eq!(result, i32::from(capabilities & (1u64 << cap) != 0)); }
        }
        assert_eq!(unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) }, 1);
        return true;
    }
    assert_eq!(unsafe { libc::geteuid() }, 0, "requires a disposable root VM");
    use std::os::unix::process::CommandExt;
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.args(["--exact", filter, "--ignored", "--nocapture"]).env(marker, "1");
    unsafe {
        command.pre_exec(move || {
            // Isolate first, while CAP_SYS_ADMIN is still available. Neither
            // profile can enter another namespace after the capability cutover.
            if libc::unshare(libc::CLONE_NEWNET) == -1 { return Err(io::Error::last_os_error()); }
            for cap in 0..64 {
                if capabilities & (1u64 << cap) == 0
                    && libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) == -1
                    && io::Error::last_os_error().raw_os_error() != Some(libc::EINVAL) {
                    return Err(io::Error::last_os_error());
                }
            }
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1 { return Err(io::Error::last_os_error()); }
            let header = CapHeader { version: 0x2008_0522, pid: 0 };
            let data = [
                CapData { effective: capabilities as u32, permitted: capabilities as u32, inheritable: 0 },
                CapData { effective: (capabilities >> 32) as u32, permitted: (capabilities >> 32) as u32, inheritable: 0 },
            ];
            if libc::syscall(libc::SYS_capset, &header, data.as_ptr()) == -1 { return Err(io::Error::last_os_error()); }
            Ok(())
        });
    }
    let output = command.output().unwrap();
    assert!(output.status.success(), "{}\n{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    false
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "disposable root VM with CAP_SYS_ADMIN, CAP_SETPCAP and CAP_DAC_OVERRIDE"]
async fn l2tpv2_denied_without_sys_admin() {
    if !selective_child("network::privilege_test::l2tpv2_denied_without_sys_admin", "CAT4IGP_L2TPV2_SELECTIVE_CHILD", 1 << 1) { return; }
    // Retain CAP_DAC_OVERRIDE: prove /run creation succeeds, so a filesystem
    // denial cannot masquerade as the mount-namespace capability boundary.
    let probe = tempfile::Builder::new().prefix("cat4igp-cap-probe-").tempdir_in("/run").unwrap();
    drop(probe);
    let helpers = tempfile::tempdir().unwrap();
    let executable = std::env::current_exe().unwrap();
    std::os::unix::fs::symlink(&executable, helpers.path().join("xl2tpd")).unwrap();
    assert!(std::fs::metadata(helpers.path().join("xl2tpd")).unwrap().is_file());
    unsafe { std::env::set_var("PATH", helpers.path()); }
    let name = format!("s2deny{:x}", std::process::id());
    let interface = std::ffi::CString::new(name.as_str()).unwrap();
    let info = cat4igp_shared::control::L2tpV2TunnelInfo {
        tunnel_id: 1, peer_node_id: 2, wireguard_tunnel_id: None,
        local_endpoint: "127.0.0.1".into(), remote_endpoint: "127.0.0.2".into(),
        local_port: 1701, remote_port: 1701,
        local_address: "192.0.2.1".into(), remote_address: "192.0.2.2".into(),
        secret: "selective-capability-test".into(), mtu: 1400, initiator: true,
    };
    for userspace in [false, true] {
        let mut tunnel = crate::tunnel::l2tp_v2::L2tpV2Tunnel::new(name.clone(), info.clone(), userspace).unwrap();
        for _ in 0..2 {
            let error = tunnel.setup().await.expect_err("mount namespace created without CAP_SYS_ADMIN");
            assert_eq!(error.raw_os_error(), Some(libc::EPERM));
            assert!(!tunnel.is_connected().unwrap());
            assert_eq!(unsafe { libc::if_nametoindex(interface.as_ptr()) }, 0);
            for entry in std::fs::read_dir("/run").unwrap() {
                let entry = entry.unwrap();
                if entry.file_name().as_encoded_bytes().starts_with(b"cat4igp-l2tpv2-") {
                    if let Ok(options) = std::fs::read_to_string(entry.path().join("options")) {
                        assert!(!options.lines().any(|line| line == format!("ifname {name}")), "configuration leaked after pre_exec failure");
                    }
                }
            }
            let mut status = 0;
            assert_eq!(unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) }, -1);
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ECHILD));
            tunnel.destroy().await.unwrap();
            tunnel.destroy().await.unwrap();
        }
    }
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "disposable root VM with CAP_SYS_ADMIN, CAP_SETPCAP, CAP_NET_ADMIN and /dev/net/tun"]
async fn l2tpv3_setup_with_net_admin_only() {
    if !selective_child("network::privilege_test::l2tpv3_setup_with_net_admin_only", "CAT4IGP_L2TPV3_SELECTIVE_CHILD", 1 << 12) { return; }
    use crate::tunnel::shared::Tunnel;
    crate::interface::link_up_with_mtu("lo".into(), 65536).await.unwrap();
    let name = format!("s3allow{:x}", std::process::id());
    let interface = std::ffi::CString::new(name.as_str()).unwrap();
    assert_eq!(unsafe { libc::if_nametoindex(interface.as_ptr()) }, 0);
    let reservation = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let local = reservation.local_addr().unwrap();
    let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    drop(reservation);
    let mut tunnel = crate::tunnel::l2tp::L2tpTunnel::new(
        name, 1, local, peer.local_addr().unwrap(),
        std::num::NonZeroU32::new(1).unwrap(), std::num::NonZeroU32::new(2).unwrap(),
        [1; 8], [2; 8], 1400, None,
    );
    for _ in 0..2 {
        tunnel.setup().await.unwrap();
        assert!(tunnel.is_ift_created());
        assert!(tunnel.is_connected().unwrap());
        assert_ne!(unsafe { libc::if_nametoindex(interface.as_ptr()) }, 0);
        assert_eq!(tunnel.get_mtu().await.unwrap(), 1400);
        assert_eq!(std::net::UdpSocket::bind(local).unwrap_err().kind(), io::ErrorKind::AddrInUse);
        tunnel.destroy().await.unwrap();
        tunnel.destroy().await.unwrap();
        assert!(!tunnel.is_ift_created());
        assert!(!tunnel.is_connected().unwrap());
        assert_eq!(unsafe { libc::if_nametoindex(interface.as_ptr()) }, 0);
        drop(std::net::UdpSocket::bind(local).expect("destroy leaked L2TPv3 UDP socket"));
    }
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "disposable root VM with CAP_SYS_ADMIN, CAP_SETPCAP, CAP_NET_ADMIN and kernel WireGuard"]
async fn wireguard_setup_with_net_admin_only() {
    if !selective_child("network::privilege_test::wireguard_setup_with_net_admin_only", "CAT4IGP_WIREGUARD_SELECTIVE_CHILD", 1 << 12) { return; }
    use crate::tunnel::{shared::Tunnel, wireguard::WireGuardTunnel};
    use wireguard_control::{Backend, Device, InterfaceName, Key};
    let name = format!("wgallow{:x}", std::process::id());
    let interface = std::ffi::CString::new(name.as_str()).unwrap();
    let ifname: InterfaceName = name.parse().unwrap();
    assert_eq!(unsafe { libc::if_nametoindex(interface.as_ptr()) }, 0);
    let private = Key::generate_private();
    let peer = Key::generate_private().get_public();
    let reservation = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    let port = reservation.local_addr().unwrap().port();
    drop(reservation);
    let mut tunnel = WireGuardTunnel::new(name, private.to_base64(), peer.to_base64(), None, Some(port));
    for _ in 0..2 {
        tunnel.setup().await.unwrap();
        assert!(tunnel.is_ift_created());
        assert_ne!(unsafe { libc::if_nametoindex(interface.as_ptr()) }, 0);
        let device = Device::get(&ifname, Backend::Kernel).unwrap();
        assert_eq!(device.public_key, Some(private.get_public()));
        assert_eq!(device.listen_port, Some(port));
        assert_eq!(device.peers.len(), 1);
        assert_eq!(device.peers[0].config.public_key, peer);
        tunnel.destroy().await.unwrap();
        tunnel.destroy().await.unwrap();
        assert!(!tunnel.is_ift_created());
        assert_eq!(unsafe { libc::if_nametoindex(interface.as_ptr()) }, 0);
        drop(std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, port)).expect("destroy leaked WireGuard UDP socket"));
    }
}
