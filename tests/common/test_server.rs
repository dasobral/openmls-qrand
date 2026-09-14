//! Loopback QRNG Open API test server.
//!
//! Binds `127.0.0.1` with an OS-assigned port. HTTP uses tiny_http. TLS/mTLS
//! uses rustls plus a minimal HTTP/1.1 responder after the handshake.

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};
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

struct HealthStub {
    status: u16,
    body: Vec<u8>,
}

struct Shared {
    requests: Mutex<Vec<RecordedRequest>>,
    capabilities: Mutex<Option<CapabilitiesStub>>,
    entropy_queue: Mutex<VecDeque<EntropyOverride>>,
    entropy_default_status: Mutex<u16>,
    health: Mutex<Option<HealthStub>>,
}

/// Deterministic per-block payload: byte `i` is `i % 256`.
pub fn default_entropy_block(block_size: usize) -> Vec<u8> {
    (0..block_size).map(|i| (i % 256) as u8).collect()
}

/// Ephemeral CA used to issue loopback server and client certificates.
pub struct TestCa {
    pub cert_pem: String,
    cert_der: Vec<u8>,
    issuer: Issuer<'static, KeyPair>,
}

/// Leaf certificate plus PKCS#8 key, as PEM (for the client) and DER (for rustls).
pub struct IssuedIdentity {
    pub cert_pem: String,
    pub key_pem: String,
    cert_der: Vec<u8>,
    key_pkcs8: Vec<u8>,
    ca_der: Vec<u8>,
}

/// Subject Alternative Name for a test server certificate.
pub enum ServerSan {
    /// IP SAN for `127.0.0.1` (matches `https://127.0.0.1:<port>`).
    LoopbackIp,
    /// DNS SAN `localhost` only (mismatches `https://127.0.0.1:<port>`).
    LocalhostDns,
}

impl TestCa {
    pub fn generate(common_name: &str) -> Self {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("empty SAN list");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];

        let key_pair = KeyPair::generate().expect("CA key");
        let cert = params.self_signed(&key_pair).expect("self-signed CA");
        Self {
            cert_pem: cert.pem(),
            cert_der: cert.der().to_vec(),
            issuer: Issuer::new(params, key_pair),
        }
    }

    pub fn issue_server(&self, san: ServerSan) -> IssuedIdentity {
        let san_name = match san {
            ServerSan::LoopbackIp => "127.0.0.1".to_owned(),
            ServerSan::LocalhostDns => "localhost".to_owned(),
        };
        let mut params = CertificateParams::new(vec![san_name.clone()]).expect("server SAN");
        params
            .distinguished_name
            .push(DnType::CommonName, "qrng-test-server");
        params.use_authority_key_identifier_extension = true;
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);
        // CertificateParams::new already set the SAN; keep an explicit IP SAN for loopback.
        if matches!(san, ServerSan::LoopbackIp) {
            params.subject_alt_names =
                vec![rcgen::SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST))];
        }
        self.sign_leaf(params)
    }

    pub fn issue_client(&self, common_name: &str) -> IssuedIdentity {
        let mut params = CertificateParams::new(vec![common_name.to_owned()]).expect("client SAN");
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.use_authority_key_identifier_extension = true;
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ClientAuth);
        self.sign_leaf(params)
    }

    fn sign_leaf(&self, params: CertificateParams) -> IssuedIdentity {
        let key_pair = KeyPair::generate().expect("leaf key");
        let cert = params
            .signed_by(&key_pair, &self.issuer)
            .expect("sign leaf");
        IssuedIdentity {
            cert_pem: cert.pem(),
            key_pem: key_pair.serialize_pem(),
            cert_der: cert.der().to_vec(),
            key_pkcs8: key_pair.serialize_der(),
            ca_der: self.cert_der.clone(),
        }
    }
}

enum ListenerKind {
    Http(Arc<Server>),
    Tls,
}

pub struct TestServer {
    port: u16,
    scheme: &'static str,
    listener: ListenerKind,
    shared: Arc<Shared>,
    running: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl TestServer {
    /// Bind `127.0.0.1:0` and serve plain HTTP on a background thread.
    pub fn start() -> Self {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("bind 127.0.0.1:0");
        let port = listener.local_addr().expect("local addr after bind").port();

        let server = Arc::new(
            Server::from_listener(listener, None).expect("tiny_http server from listener"),
        );
        let shared = new_shared();
        let running = Arc::new(AtomicBool::new(true));

        let server_thread = Arc::clone(&server);
        let shared_thread = Arc::clone(&shared);
        let running_thread = Arc::clone(&running);
        let join = thread::Builder::new()
            .name("qrng-test-server".into())
            .spawn(move || serve_http(server_thread, shared_thread, running_thread))
            .expect("spawn test server thread");

        Self {
            port,
            scheme: "http",
            listener: ListenerKind::Http(server),
            shared,
            running,
            join: Some(join),
        }
    }

    /// HTTPS with a rustls server certificate. No client-certificate requirement.
    pub fn start_tls(server_id: &IssuedIdentity) -> Self {
        Self::start_rustls("https", rustls_server_config(server_id, None))
    }

    /// HTTPS that requires a client certificate issued by `client_ca`.
    pub fn start_mtls(server_id: &IssuedIdentity, client_ca: &TestCa) -> Self {
        Self::start_rustls(
            "https",
            rustls_server_config(server_id, Some(client_ca.cert_der.as_slice())),
        )
    }

    fn start_rustls(scheme: &'static str, tls_config: ServerConfig) -> Self {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("bind 127.0.0.1:0");
        listener
            .set_nonblocking(true)
            .expect("nonblocking TLS listener");
        let port = listener.local_addr().expect("local addr after bind").port();

        let shared = new_shared();
        let running = Arc::new(AtomicBool::new(true));
        let tls_config = Arc::new(tls_config);

        let shared_thread = Arc::clone(&shared);
        let running_thread = Arc::clone(&running);
        let join = thread::Builder::new()
            .name("qrng-test-server-tls".into())
            .spawn(move || serve_tls(listener, tls_config, shared_thread, running_thread))
            .expect("spawn TLS test server thread");

        Self {
            port,
            scheme,
            listener: ListenerKind::Tls,
            shared,
            running,
            join: Some(join),
        }
    }

    #[allow(dead_code)]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Origin with no path, e.g. `http://127.0.0.1:54321` or `https://127.0.0.1:54321`.
    pub fn origin(&self) -> String {
        format!("{}://127.0.0.1:{}", self.scheme, self.port)
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

    pub fn set_health_json(&self, body: serde_json::Value) {
        self.set_health_raw(body.to_string().into_bytes());
    }

    pub fn set_health_raw(&self, body: impl Into<Vec<u8>>) {
        let mut slot = self.shared.health.lock().expect("health lock");
        match slot.as_mut() {
            Some(stub) => stub.body = body.into(),
            None => {
                *slot = Some(HealthStub {
                    status: 200,
                    body: body.into(),
                });
            }
        }
    }

    pub fn set_health_status(&self, status: u16) {
        let mut slot = self.shared.health.lock().expect("health lock");
        match slot.as_mut() {
            Some(stub) => stub.status = status,
            None => {
                *slot = Some(HealthStub {
                    status,
                    body: Vec::new(),
                });
            }
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        match &self.listener {
            ListenerKind::Http(server) => server.unblock(),
            ListenerKind::Tls => {}
        }
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn new_shared() -> Arc<Shared> {
    Arc::new(Shared {
        requests: Mutex::new(Vec::new()),
        capabilities: Mutex::new(None),
        entropy_queue: Mutex::new(VecDeque::new()),
        entropy_default_status: Mutex::new(200),
        health: Mutex::new(None),
    })
}

fn rustls_server_config(server_id: &IssuedIdentity, client_ca_der: Option<&[u8]>) -> ServerConfig {
    let cert_chain = vec![
        CertificateDer::from(server_id.cert_der.clone()),
        CertificateDer::from(server_id.ca_der.clone()),
    ];
    let key = PrivatePkcs8KeyDer::from(server_id.key_pkcs8.clone()).into();

    let mut config = if let Some(ca_der) = client_ca_der {
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(ca_der.to_vec()))
            .expect("client CA as rustls root");
        let verifier = WebPkiClientVerifier::builder(roots.into())
            .build()
            .expect("mTLS client cert verifier");
        ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(cert_chain, key)
            .expect("mTLS server cert")
    } else {
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .expect("TLS server cert")
    };
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config
}

fn serve_http(server: Arc<Server>, shared: Arc<Shared>, running: Arc<AtomicBool>) {
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

        let (status, response_body) = dispatch(&shared, &method, &path, &body);
        let _ = request.respond(json_or_plain_response(status, response_body));
    }
}

fn serve_tls(
    listener: TcpListener,
    tls_config: Arc<ServerConfig>,
    shared: Arc<Shared>,
    running: Arc<AtomicBool>,
) {
    while running.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((tcp, _)) => {
                let tls_config = Arc::clone(&tls_config);
                let shared = Arc::clone(&shared);
                let _ = thread::Builder::new()
                    .name("qrng-test-server-tls-conn".into())
                    .spawn(move || handle_tls_conn(tcp, tls_config, shared));
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(_) => break,
        }
    }
}

fn handle_tls_conn(tcp: TcpStream, tls_config: Arc<ServerConfig>, shared: Arc<Shared>) {
    let _ = tcp.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = tcp.set_write_timeout(Some(Duration::from_secs(5)));
    let _ = tcp.set_nodelay(true);

    let Ok(conn) = ServerConnection::new(tls_config) else {
        return;
    };
    let mut stream = StreamOwned::new(conn, tcp);
    let Some((method, path, headers, body)) = read_http11(&mut stream) else {
        return;
    };

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

    let (status, response_body) = dispatch(&shared, &method, &path, &body);
    let _ = write_http11(&mut stream, status, &response_body);
}

type Http11Parts = (String, String, Vec<(String, String)>, Vec<u8>);

fn read_http11<R: Read>(stream: &mut R) -> Option<Http11Parts> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 2048];
    loop {
        let n = stream.read(&mut tmp).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(header_end) = find_header_end(&buf) {
            let header_text = std::str::from_utf8(&buf[..header_end]).ok()?;
            let mut lines = header_text.split("\r\n");
            let request_line = lines.next()?;
            let mut parts = request_line.split(' ');
            let method = parts.next()?.to_string();
            let raw_path = parts.next()?;
            let path = raw_path.split('?').next().unwrap_or(raw_path).to_string();
            let mut headers = Vec::new();
            let mut content_length = 0usize;
            for line in lines {
                if line.is_empty() {
                    continue;
                }
                let (name, value) = line.split_once(':')?;
                let name = name.trim();
                let value = value.trim();
                if name.eq_ignore_ascii_case("content-length") {
                    content_length = value.parse().unwrap_or(0);
                }
                headers.push((name.to_string(), value.to_string()));
            }
            let mut body = buf[header_end..].to_vec();
            while body.len() < content_length {
                let n = stream.read(&mut tmp).ok()?;
                if n == 0 {
                    break;
                }
                body.extend_from_slice(&tmp[..n]);
            }
            body.truncate(content_length);
            return Some((method, path, headers, body));
        }
        if buf.len() > 64 * 1024 {
            return None;
        }
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn write_http11<W: Write>(stream: &mut W, status: u16, body: &[u8]) -> io::Result<()> {
    let reason = if (200..300).contains(&status) {
        "OK"
    } else {
        "Error"
    };
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

fn json_or_plain_response(status: u16, body: Vec<u8>) -> Response<std::io::Cursor<Vec<u8>>> {
    let mut response = Response::from_data(body).with_status_code(status);
    if let Ok(header) = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]) {
        response = response.with_header(header);
    }
    response
}

fn dispatch(shared: &Shared, method: &str, path: &str, body: &[u8]) -> (u16, Vec<u8>) {
    let is_capabilities = method.eq_ignore_ascii_case("GET") && path_is_capabilities(path);
    let is_entropy = method.eq_ignore_ascii_case("POST") && path_is_entropy(path);
    let is_health = method.eq_ignore_ascii_case("GET") && path_is_healthtest(path);
    if is_capabilities {
        capabilities_body(shared)
    } else if is_entropy {
        entropy_body(shared, body)
    } else if is_health {
        health_body(shared)
    } else {
        (404, b"not found".to_vec())
    }
}

fn capabilities_body(shared: &Shared) -> (u16, Vec<u8>) {
    let capabilities = shared.capabilities.lock().expect("capabilities lock");
    match capabilities.as_ref() {
        Some(stub) => (stub.status, stub.body.clone()),
        None => (404, b"not found".to_vec()),
    }
}

fn entropy_body(shared: &Shared, request_body: &[u8]) -> (u16, Vec<u8>) {
    if let Some(override_response) = shared
        .entropy_queue
        .lock()
        .expect("entropy queue lock")
        .pop_front()
    {
        return (override_response.status, override_response.body);
    }

    let status = *shared
        .entropy_default_status
        .lock()
        .expect("entropy status lock");
    if status != 200 {
        return (status, Vec::new());
    }

    let block_size = parse_block_size(request_body).unwrap_or(0);
    let encoded = BASE64.encode(default_entropy_block(block_size));
    let body = serde_json::json!({ "entropy": [encoded] })
        .to_string()
        .into_bytes();
    (200, body)
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

fn path_is_healthtest(path: &str) -> bool {
    path == "/v1/healthtest" || path.ends_with("/v1/healthtest")
}

fn health_body(shared: &Shared) -> (u16, Vec<u8>) {
    let health = shared.health.lock().expect("health lock");
    match health.as_ref() {
        Some(stub) => (stub.status, stub.body.clone()),
        None => (404, b"not found".to_vec()),
    }
}
