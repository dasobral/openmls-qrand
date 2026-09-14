//! Loopback QRNG Open API test server (HTTP only for Task 2).
//!
//! Binds `127.0.0.1` with an OS-assigned port. TLS/mTLS are deferred to Task 9.

use std::collections::VecDeque;
use std::io::Read;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use tiny_http::{Header, Response, Server};

#[derive(Clone, Debug)]
pub struct RecordedRequest {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

struct CapabilitiesStub {
    status: u16,
    body: Vec<u8>,
}

struct EntropyOverride {
    status: u16,
    body: Vec<u8>,
}

struct Shared {
    requests: Mutex<Vec<RecordedRequest>>,
    capabilities: Mutex<Option<CapabilitiesStub>>,
    entropy_queue: Mutex<VecDeque<EntropyOverride>>,
    entropy_default_status: Mutex<u16>,
}

/// Deterministic per-block payload: byte `i` is `i % 256`.
pub fn default_entropy_block(block_size: usize) -> Vec<u8> {
    (0..block_size).map(|i| (i % 256) as u8).collect()
}

pub struct TestServer {
    port: u16,
    server: Arc<Server>,
    shared: Arc<Shared>,
    running: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl TestServer {
    /// Bind `127.0.0.1:0` and serve on a background thread.
    pub fn start() -> Self {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("bind 127.0.0.1:0");
        let port = listener.local_addr().expect("local addr after bind").port();

        let server = Arc::new(
            Server::from_listener(listener, None).expect("tiny_http server from listener"),
        );
        let shared = Arc::new(Shared {
            requests: Mutex::new(Vec::new()),
            capabilities: Mutex::new(None),
            entropy_queue: Mutex::new(VecDeque::new()),
            entropy_default_status: Mutex::new(200),
        });
        let running = Arc::new(AtomicBool::new(true));

        let server_thread = Arc::clone(&server);
        let shared_thread = Arc::clone(&shared);
        let running_thread = Arc::clone(&running);
        let join = thread::Builder::new()
            .name("qrng-test-server".into())
            .spawn(move || serve(server_thread, shared_thread, running_thread))
            .expect("spawn test server thread");

        Self {
            port,
            server,
            shared,
            running,
            join: Some(join),
        }
    }

    #[allow(dead_code)]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Origin with no path, e.g. `http://127.0.0.1:54321`.
    pub fn origin(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    pub fn set_capabilities_json(&self, body: serde_json::Value) {
        self.set_capabilities_raw(body.to_string().into_bytes());
    }

    pub fn set_capabilities_raw(&self, body: impl Into<Vec<u8>>) {
        let mut slot = self.shared.capabilities.lock().expect("capabilities lock");
        match slot.as_mut() {
            Some(stub) => stub.body = body.into(),
            None => {
                *slot = Some(CapabilitiesStub {
                    status: 200,
                    body: body.into(),
                });
            }
        }
    }

    pub fn set_capabilities_status(&self, status: u16) {
        let mut slot = self.shared.capabilities.lock().expect("capabilities lock");
        match slot.as_mut() {
            Some(stub) => stub.status = status,
            None => {
                *slot = Some(CapabilitiesStub {
                    status,
                    body: Vec::new(),
                });
            }
        }
    }

    pub fn recorded_requests(&self) -> Vec<RecordedRequest> {
        self.shared.requests.lock().expect("requests lock").clone()
    }

    /// Status used when the entropy override queue is empty (default 200).
    /// Status 200 with an empty queue generates a pattern block from `block_size`.
    #[allow(dead_code)]
    pub fn set_entropy_status(&self, status: u16) {
        *self
            .shared
            .entropy_default_status
            .lock()
            .expect("entropy status lock") = status;
    }

    pub fn enqueue_entropy_raw(&self, status: u16, body: impl Into<Vec<u8>>) {
        self.shared
            .entropy_queue
            .lock()
            .expect("entropy queue lock")
            .push_back(EntropyOverride {
                status,
                body: body.into(),
            });
    }

    pub fn enqueue_entropy_json(&self, status: u16, body: serde_json::Value) {
        self.enqueue_entropy_raw(status, body.to_string().into_bytes());
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        self.server.unblock();
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn serve(server: Arc<Server>, shared: Arc<Shared>, running: Arc<AtomicBool>) {
    while running.load(Ordering::SeqCst) {
        let mut request = match server.recv() {
            Ok(request) => request,
            Err(_) => break,
        };

        let method = request.method().to_string();
        let raw_url = request.url().to_string();
        let path = raw_url
            .split('?')
            .next()
            .unwrap_or(raw_url.as_str())
            .to_string();
        let headers = request
            .headers()
            .iter()
            .map(|header| {
                (
                    header.field.as_str().as_str().to_string(),
                    header.value.as_str().to_string(),
                )
            })
            .collect();
        let mut body = Vec::new();
        let _ = Read::read_to_end(request.as_reader(), &mut body);

        shared
            .requests
            .lock()
            .expect("requests lock")
            .push(RecordedRequest {
                method: method.clone(),
                path: path.clone(),
                headers,
                body: body.clone(),
            });

        let is_capabilities = method.eq_ignore_ascii_case("GET") && path_is_capabilities(&path);
        let is_entropy = method.eq_ignore_ascii_case("POST") && path_is_entropy(&path);
        let response = if is_capabilities {
            capabilities_response(&shared)
        } else if is_entropy {
            entropy_response(&shared, &body)
        } else {
            Response::from_data(b"not found".to_vec()).with_status_code(404)
        };
        let _ = request.respond(response);
    }
}

fn json_response(status: u16, body: Vec<u8>) -> Response<std::io::Cursor<Vec<u8>>> {
    let mut response = Response::from_data(body).with_status_code(status);
    if let Ok(header) = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]) {
        response = response.with_header(header);
    }
    response
}

fn capabilities_response(shared: &Shared) -> Response<std::io::Cursor<Vec<u8>>> {
    let capabilities = shared.capabilities.lock().expect("capabilities lock");
    match capabilities.as_ref() {
        Some(stub) => json_response(stub.status, stub.body.clone()),
        None => Response::from_data(b"not found".to_vec()).with_status_code(404),
    }
}

fn entropy_response(shared: &Shared, request_body: &[u8]) -> Response<std::io::Cursor<Vec<u8>>> {
    if let Some(override_response) = shared
        .entropy_queue
        .lock()
        .expect("entropy queue lock")
        .pop_front()
    {
        return json_response(override_response.status, override_response.body);
    }

    let status = *shared
        .entropy_default_status
        .lock()
        .expect("entropy status lock");
    if status != 200 {
        return json_response(status, Vec::new());
    }

    let block_size = parse_block_size(request_body).unwrap_or(0);
    let encoded = BASE64.encode(default_entropy_block(block_size));
    let body = serde_json::json!({ "entropy": [encoded] })
        .to_string()
        .into_bytes();
    json_response(200, body)
}

fn parse_block_size(body: &[u8]) -> Option<usize> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    value.get("block_size")?.as_u64().map(|n| n as usize)
}

fn path_is_capabilities(path: &str) -> bool {
    path == "/v1/capabilities" || path.ends_with("/v1/capabilities")
}

fn path_is_entropy(path: &str) -> bool {
    path == "/v1/entropy" || path.ends_with("/v1/entropy")
}
