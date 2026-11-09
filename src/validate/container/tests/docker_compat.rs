use crate::resource::container::ContainerResource;
use crate::validate::container::docker_compat::is_valid_container_name;
use crate::validate::container::validate;
use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::time::Duration;
use tempfile::tempdir;

#[test]
fn test_container_validation_mock_socket_success() {
    let dir = tempdir().unwrap();
    let sock_path = dir.path().join("mock_docker.sock");
    let listener = UnixListener::bind(&sock_path).unwrap();

    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut req = [0u8; 512];
        let _ = stream.read(&mut req);
        let body = r#"{"State":{"Status":"running"},"Config":{"Image":"ghcr.io/kmns/test:1.0","ExposedPorts":{"80/tcp":{}}},"NetworkSettings":{"Ports":{"80/tcp":[]}}}"#;
        let resp = format!(
            "HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(resp.as_bytes());
    });

    let resource = ContainerResource {
        title: None,
        name: Some("test_app".to_string()),
        status: Some("running".to_string()),
        image: Some("test:1.0".to_string()),
        ports: vec!["80/tcp".to_string()],
        socket: Some(sock_path.to_string_lossy().to_string()),
        user: None,
        meta: None,
        timeout: Some(2),
        skip: false,
    };

    let res = validate("test_app", &resource, None);
    let _ = handle.join();

    assert!(res.passed, "Failures: {:?}", res.failures);
    assert_eq!(res.resource_type, "container");
}

#[test]
fn test_container_validation_not_found() {
    let dir = tempdir().unwrap();
    let sock_path = dir.path().join("mock_docker_404.sock");
    let listener = UnixListener::bind(&sock_path).unwrap();

    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut req = [0u8; 512];
        let _ = stream.read(&mut req);
        let resp = "HTTP/1.0 404 Not Found\r\n\r\n{\"message\":\"No such container: missing\"}";
        let _ = stream.write_all(resp.as_bytes());
    });

    let resource = ContainerResource {
        title: None,
        name: Some("missing_app".to_string()),
        status: Some("running".to_string()),
        image: None,
        ports: vec![],
        socket: Some(sock_path.to_string_lossy().to_string()),
        user: None,
        meta: None,
        timeout: Some(2),
        skip: false,
    };

    let res = validate("missing_app", &resource, None);
    let _ = handle.join();

    assert!(!res.passed);
    assert!(!res.failures.is_empty());
    assert!(res.failures[0].contains("not found"));
}

#[test]
fn test_container_validation_response_limit_exceeded() {
    let dir = tempdir().unwrap();
    let sock_path = dir.path().join("mock_docker_oversized.sock");
    let listener = UnixListener::bind(&sock_path).unwrap();

    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut req = [0u8; 512];
        let _ = stream.read(&mut req);
        let header = "HTTP/1.0 200 OK\r\n\r\n";
        let _ = stream.write_all(header.as_bytes());
        // Stream chunks exceeding 4 MiB
        let chunk = [b'A'; 65536];
        for _ in 0..70 {
            if stream.write_all(&chunk).is_err() {
                break;
            }
        }
    });

    let resource = ContainerResource {
        title: None,
        name: Some("oversized_app".to_string()),
        status: Some("running".to_string()),
        image: None,
        ports: vec![],
        socket: Some(sock_path.to_string_lossy().to_string()),
        user: None,
        meta: None,
        timeout: Some(5),
        skip: false,
    };

    let res = validate("oversized_app", &resource, None);
    let _ = handle.join();

    assert!(!res.passed);
    assert_eq!(res.error.as_deref(), Some("E_CONTAINER_RESPONSE_LIMIT"));
}

#[test]
fn test_container_validation_response_timeout() {
    let dir = tempdir().unwrap();
    let sock_path = dir.path().join("mock_docker_slow.sock");
    let listener = UnixListener::bind(&sock_path).unwrap();

    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut req = [0u8; 512];
        let _ = stream.read(&mut req);
        let header = "HTTP/1.0 200 OK\r\n\r\n";
        let _ = stream.write_all(header.as_bytes());
        // Slowly trickle small chunks with small sleep
        for _ in 0..50 {
            std::thread::sleep(Duration::from_millis(50));
            if stream.write_all(b"{\"partial\":").is_err() {
                break;
            }
        }
    });

    let resource = ContainerResource {
        title: None,
        name: Some("slow_app".to_string()),
        status: Some("running".to_string()),
        image: None,
        ports: vec![],
        socket: Some(sock_path.to_string_lossy().to_string()),
        user: None,
        meta: None,
        timeout: Some(1), // 1s total timeout
        skip: false,
    };

    let res = validate("slow_app", &resource, None);
    let _ = handle.join();

    assert!(!res.passed);
    assert_eq!(res.error.as_deref(), Some("E_CONTAINER_RESPONSE_TIMEOUT"));
}

#[test]
fn test_is_valid_container_name() {
    assert!(is_valid_container_name("kmns-web-prod"));
    assert!(is_valid_container_name("/sample-app"));
    assert!(is_valid_container_name("my_app.1"));

    // Reject injection / traversal / empty / CRLF
    assert!(!is_valid_container_name(""));
    assert!(!is_valid_container_name("/"));
    assert!(!is_valid_container_name("app/../secret"));
    assert!(!is_valid_container_name("app\r\nHost: evil.com"));
    assert!(!is_valid_container_name("app?param=val"));
}
