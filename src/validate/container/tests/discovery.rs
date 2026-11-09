use crate::resource::container::ContainerResource;
use crate::validate::container::discovery::{resolve_candidate_sockets_with_ctx, DiscoveryContext};
use crate::validate::container::validate;
use tempfile::tempdir;

#[test]
fn test_045_1_cross_user_socket_enumeration_prohibited() {
    // TEST-045-1: A synthetic /run/user/2001 contains an engine socket while effective UID is 1000.
    // The resolver returns no candidate under UID 2001.
    let dir = tempdir().unwrap();
    let run_user = dir.path().join("run_user");
    let uid_2001_dir = run_user.join("2001");
    std::fs::create_dir_all(&uid_2001_dir).unwrap();
    std::fs::write(uid_2001_dir.join("docker.sock"), b"").unwrap();

    let ctx = DiscoveryContext {
        effective_uid: 1000,
        xdg_runtime_dir: None,
        run_user_base: run_user,
        system_sockets: vec![],
    };

    let resource = ContainerResource {
        title: None,
        name: Some("test".to_string()),
        status: None,
        image: None,
        ports: vec![],
        socket: None,
        user: None,
        meta: None,
        timeout: None,
        skip: false,
    };

    let res = resolve_candidate_sockets_with_ctx(&resource, None, &ctx);
    assert_eq!(res, Err("E_CONTAINER_SOCKET_UNAVAILABLE"));
}

#[test]
fn test_045_2_run_as_designated_identity_selects_strictly_target_uid() {
    // TEST-045-2: run_as resolves to UID 2001 and both 1000 and 2001 have sockets.
    // Only UID 2001 Docker/Podman paths are eligible.
    let dir = tempdir().unwrap();
    let run_user = dir.path().join("run_user");
    let uid_1000_dir = run_user.join("1000");
    let uid_2001_dir = run_user.join("2001");
    std::fs::create_dir_all(&uid_1000_dir).unwrap();
    std::fs::create_dir_all(&uid_2001_dir).unwrap();

    let sock_1000 = uid_1000_dir.join("docker.sock");
    let sock_2001 = uid_2001_dir.join("docker.sock");
    std::fs::write(&sock_1000, b"").unwrap();
    std::fs::write(&sock_2001, b"").unwrap();

    let ctx = DiscoveryContext {
        effective_uid: 1000,
        xdg_runtime_dir: None,
        run_user_base: run_user,
        system_sockets: vec![],
    };

    let resource = ContainerResource {
        title: None,
        name: Some("test".to_string()),
        status: None,
        image: None,
        ports: vec![],
        socket: None,
        user: None,
        meta: None,
        timeout: None,
        skip: false,
    };

    let res = resolve_candidate_sockets_with_ctx(&resource, Some("2001"), &ctx).unwrap();
    assert_eq!(res, vec![sock_2001]);
}

#[test]
fn test_045_3_designated_run_as_socket_absent_does_not_fall_back_to_system() {
    // TEST-045-3: Designated run_as socket is absent but system socket exists.
    // Outcome must be E_CONTAINER_SOCKET_UNAVAILABLE; system socket receives no fallback.
    let dir = tempdir().unwrap();
    let sys_sock = dir.path().join("system_docker.sock");
    std::fs::write(&sys_sock, b"").unwrap();

    let ctx = DiscoveryContext {
        effective_uid: 1000,
        xdg_runtime_dir: None,
        run_user_base: dir.path().join("run_user"),
        system_sockets: vec![sys_sock],
    };

    let resource = ContainerResource {
        title: None,
        name: Some("test".to_string()),
        status: None,
        image: None,
        ports: vec![],
        socket: None,
        user: None,
        meta: None,
        timeout: None,
        skip: false,
    };

    let res = resolve_candidate_sockets_with_ctx(&resource, Some("2001"), &ctx);
    assert_eq!(res, Err("E_CONTAINER_SOCKET_UNAVAILABLE"));
}

#[test]
fn test_045_4_explicit_socket_absent_does_not_fall_back_to_session() {
    // TEST-045-4: An explicit socket is absent while a current-session socket exists.
    // Outcome must be E_CONTAINER_SOCKET_UNAVAILABLE; session socket receives no fallback.
    let dir = tempdir().unwrap();
    let session_dir = dir.path().join("run_user").join("1000");
    std::fs::create_dir_all(&session_dir).unwrap();
    let session_sock = session_dir.join("docker.sock");
    std::fs::write(&session_sock, b"").unwrap();

    let ctx = DiscoveryContext {
        effective_uid: 1000,
        xdg_runtime_dir: Some(session_dir),
        run_user_base: dir.path().join("run_user"),
        system_sockets: vec![],
    };

    let resource = ContainerResource {
        title: None,
        name: Some("test".to_string()),
        status: None,
        image: None,
        ports: vec![],
        socket: Some(
            dir.path()
                .join("non_existent.sock")
                .to_string_lossy()
                .to_string(),
        ),
        user: None,
        meta: None,
        timeout: None,
        skip: false,
    };

    let res = resolve_candidate_sockets_with_ctx(&resource, None, &ctx);
    assert_eq!(res, Err("E_CONTAINER_SOCKET_UNAVAILABLE"));
}

#[test]
fn test_045_5_resource_user_mismatch_fails_before_connection() {
    // TEST-045-5: resource.user differs from run_as or effective_uid.
    // Outcome must be E_CONTAINER_USER_SCOPE_MISMATCH.
    let resource = ContainerResource {
        title: None,
        name: Some("test".to_string()),
        status: None,
        image: None,
        ports: vec![],
        socket: None,
        user: Some("9999".to_string()),
        meta: None,
        timeout: None,
        skip: false,
    };

    let res = validate("test_app", &resource, Some("1000"));
    assert!(!res.passed);
    assert_eq!(
        res.error.as_deref(),
        Some("E_CONTAINER_USER_SCOPE_MISMATCH")
    );
}

#[test]
fn test_045_6_foreign_xdg_runtime_dir_is_ignored() {
    // TEST-045-6: $XDG_RUNTIME_DIR points outside the effective user's /run/user/<uid>.
    // It is not used.
    let dir = tempdir().unwrap();
    let run_user = dir.path().join("run_user");
    let foreign_dir = dir.path().join("foreign_runtime");
    std::fs::create_dir_all(&foreign_dir).unwrap();
    std::fs::write(foreign_dir.join("docker.sock"), b"").unwrap();

    let ctx = DiscoveryContext {
        effective_uid: 1000,
        xdg_runtime_dir: Some(foreign_dir),
        run_user_base: run_user,
        system_sockets: vec![],
    };

    let resource = ContainerResource {
        title: None,
        name: Some("test".to_string()),
        status: None,
        image: None,
        ports: vec![],
        socket: None,
        user: None,
        meta: None,
        timeout: None,
        skip: false,
    };

    let res = resolve_candidate_sockets_with_ctx(&resource, None, &ctx);
    assert_eq!(res, Err("E_CONTAINER_SOCKET_UNAVAILABLE"));
}

#[test]
fn test_045_8_root_effective_uid_selects_system_sockets_without_run_as() {
    // TEST-045-8: Root process without run_as has available standard system socket.
    let dir = tempdir().unwrap();
    let sys_sock = dir.path().join("system_docker.sock");
    std::fs::write(&sys_sock, b"").unwrap();

    let ctx = DiscoveryContext {
        effective_uid: 0,
        xdg_runtime_dir: None,
        run_user_base: dir.path().join("run_user"),
        system_sockets: vec![sys_sock.clone()],
    };

    let resource = ContainerResource {
        title: None,
        name: Some("test".to_string()),
        status: None,
        image: None,
        ports: vec![],
        socket: None,
        user: None,
        meta: None,
        timeout: None,
        skip: false,
    };

    let res = resolve_candidate_sockets_with_ctx(&resource, None, &ctx).unwrap();
    assert_eq!(res, vec![sys_sock]);
}
