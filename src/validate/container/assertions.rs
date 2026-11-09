use crate::resource::container::ContainerResource;
use serde_json::Value;

pub(crate) fn evaluate_assertions(
    resource: &ContainerResource,
    json_data: &Value,
    failures: &mut Vec<String>,
) {
    // 1. Verify Status (e.g. running)
    if let Some(expected_status) = &resource.status {
        let actual_status = json_data["State"]["Status"].as_str().unwrap_or("unknown");
        if !actual_status.eq_ignore_ascii_case(expected_status) {
            failures.push(format!(
                "status: expected {:?}, got {:?}",
                expected_status, actual_status
            ));
        }
    }

    // 2. Verify Image
    if let Some(expected_image) = &resource.image {
        let actual_image = json_data["Config"]["Image"].as_str().unwrap_or("");
        if !actual_image.contains(expected_image) {
            failures.push(format!(
                "image: expected {:?}, got {:?}",
                expected_image, actual_image
            ));
        }
    }

    // 3. Verify Exposed / Bound Ports
    if !resource.ports.is_empty() {
        let empty_map = serde_json::Map::new();
        let net_ports = json_data["NetworkSettings"]["Ports"]
            .as_object()
            .unwrap_or(&empty_map);
        let exp_ports = json_data["Config"]["ExposedPorts"]
            .as_object()
            .unwrap_or(&empty_map);

        for req_port in &resource.ports {
            let found = net_ports.contains_key(req_port) || exp_ports.contains_key(req_port);
            if !found {
                failures.push(format!(
                    "ports: container does not expose or bind required port {:?}",
                    req_port
                ));
            }
        }
    }
}
