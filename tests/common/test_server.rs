//! Loopback QRNG Open API test server (HTTP only for Task 2).
//!
//! Binds `127.0.0.1` with an OS-assigned port. TLS/mTLS are deferred to Task 9.

use std::io::Read;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use tiny_http::{Header, Response, Server};

#[derive(Clone, Debug)]
pub struct RecordedRequest {
    pub method: String,
    pub path: String,
    // Retained for authentication, entropy, and transport tests.
    #[allow(dead_code)]
    pub headers: Vec<(String, String)>,
    #[allow(dead_code)]
    pub body: Vec<u8>,
}

struct CapabilitiesStub {
    status: u16,
    body: Vec<u8>,
}

struct Shared {
    requests: Mutex<Vec<RecordedRequest>>,
    capabilities: Mutex<Option<CapabilitiesStub>>,
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
                body,
            });

        let capabilities = shared.capabilities.lock().expect("capabilities lock");
        let is_capabilities = method.eq_ignore_ascii_case("GET") && path_is_capabilities(&path);
        let response = if is_capabilities {
            match capabilities.as_ref() {
                Some(stub) => {
                    let mut response =
                        Response::from_data(stub.body.clone()).with_status_code(stub.status);
                    if let Ok(header) =
                        Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
                    {
                        response = response.with_header(header);
                    }
                    response
                }
                None => Response::from_string("not found").with_status_code(404),
            }
        } else {
            Response::from_string("not found").with_status_code(404)
        };
        drop(capabilities);
        let _ = request.respond(response);
    }
}

fn path_is_capabilities(path: &str) -> bool {
    path == "/v1/capabilities" || path.ends_with("/v1/capabilities")
}
