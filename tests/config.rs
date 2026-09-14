use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static FIXTURE_SEQ: AtomicU64 = AtomicU64::new(0);

use openmls_qrng_provider::{ApiAuth, QrngConfig, QrngError, TransportMode};

const CA_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIDDzCCAfegAwIBAgIUdTcLrrEmOmQJcYCREjdqCjc+qWAwDQYJKoZIhvcNAQEL\n\
BQAwFzEVMBMGA1UEAwwMVGVzdCBRUk5HIENBMB4XDTI2MDkxNDEwMzI0OVoXDTM2\n\
MDkxMTEwMzI0OVowFzEVMBMGA1UEAwwMVGVzdCBRUk5HIENBMIIBIjANBgkqhkiG\n\
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvJFRinb7dUbpSM4LSktTz0ya4LlAyVw/Xi2r\n\
J30RNDPQx4MoXtrnB4mUDRhARM7viTuDSdvhjpkDpIpuJzdrxM6+Km6E+nWuGlEo\n\
FOQ4gKYSG6I8bSKTm6S7FlqBML+uOcrUeQkF/7E9idlsdwqK+Z5DeWDZ6fJE6BMj\n\
fCuP4rdWbq+K3T66qNCsuPMxE/cC8wB83Km8WBofPGoYWGYTxLsQh4xXm+K5304T\n\
E7fULfwOMfKiLw8bXtLi5sNH7KVCVcIe6/AR8qIU2HovibZf1z1SbfUVO8Sprbwz\n\
/kzLQFry9NAiVe6E8sRQwZ6xyO0rpRL83fqYo4yleqod15ZR6wIDAQABo1MwUTAd\n\
BgNVHQ4EFgQU1L+DMo4eIC1Av2q/daAU+OR0W6gwHwYDVR0jBBgwFoAU1L+DMo4e\n\
IC1Av2q/daAU+OR0W6gwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOC\n\
AQEANTwUsFkMzVpo/L1RpLcMPGIDUGyOX2gHoaeLRUTdIaGpSU0cyFC1O6/ezmBx\n\
vGXhKvXVQKSlynFRsPo53Nyl+6yzcFPz4CQXQyqQ5ODGJQXdVXC+h+VvUU5lvgAq\n\
ChBOEbzsxkSQIFjjcmee1Y+6CkBlu0/hMe5/egyQta9fplq/ZRtccG/268GX27NY\n\
6VuZzBxtluHaxjI8YkExMjA3/tAAQq2TQinpeMjWvBUvGvBxssHD4ObXH+O16Fpw\n\
/YqwgsnpjoKK0jHthG0KTFUfcVpVY29AmyRTRJW50q2HsmnnIYSa1FrLoUwheLYl\n\
Ipi0lXDLMovBWd/PlsfwSbqe+Q==\n\
-----END CERTIFICATE-----\n";

const CLIENT_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIICuTCCAaECFA42AmmdPdnGG6FQMrv3rAQFCnfLMA0GCSqGSIb3DQEBCwUAMBcx\n\
FTATBgNVBAMMDFRlc3QgUVJORyBDQTAeFw0yNjA5MTQxMDMyNDlaFw0zNjA5MTEx\n\
MDMyNDlaMBsxGTAXBgNVBAMMEFRlc3QgUVJORyBDbGllbnQwggEiMA0GCSqGSIb3\n\
DQEBAQUAA4IBDwAwggEKAoIBAQDH0a7vYdwxGRhF9juacKrvuTY3JkIqlfjdS3bg\n\
PwJWJsaHejCBpc0mMppVPVZL61+SHVO5ySt7Jw3Ar6woti0hZw1Owh9UkzpSNT6v\n\
3BHK4u7a4IS6l93MnJC1ZdxFKSHAVq7aJcV3tk48ZERW8vMOW34Gs/1bO8aQE4H4\n\
lK7WT/NI2WdxgwINULTtE0ahqEC0Y4ORS4ktMvnjtqU3es9xG6YO9LYQqv+wqC17\n\
0drwNwoB+S6TgnpT1FkXjPspUIUPm9prjt5BxFtPuYg+jlrdPJ4KJlBYl6nNUXeK\n\
1+xm6Y2SqAEPM6B0MUQyCYwHW+u5ouy9MlEz0nrrOK/vQCrvAgMBAAEwDQYJKoZI\n\
hvcNAQELBQADggEBAJu0PBcomvW5cUD9nrZHO+u0t9yHOKMnnbLBxxWoFkf4Nt3t\n\
lpVe1Qkh/gMM0DJJUkkBF4rHbRyUKN5o82lN0/aE0QnvAFSHq5SAdXv/1bIFZC+I\n\
PUPBwoTWB0HXUFjvG8vrllBzKybTFUrcIje9NBKNPIPaam8Y8WGV7NGQ/D9UD2Xf\n\
7aoq6LuptgIfrYaLvEBciTrGxjA4NyrGEenc2rOmKVBV23LlViqREGDQ995mUzXn\n\
1SL9ZLIwm4hdoWirXtodDJ3HgreHsrCDHN8jI0ptVzrNln4mi6W33SxVsCtDhvsU\n\
kcDaR9kWBX68gtoB5nf3a1mh2BvbIebH2s9XxUc=\n\
-----END CERTIFICATE-----\n";

const CLIENT_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDH0a7vYdwxGRhF\n\
9juacKrvuTY3JkIqlfjdS3bgPwJWJsaHejCBpc0mMppVPVZL61+SHVO5ySt7Jw3A\n\
r6woti0hZw1Owh9UkzpSNT6v3BHK4u7a4IS6l93MnJC1ZdxFKSHAVq7aJcV3tk48\n\
ZERW8vMOW34Gs/1bO8aQE4H4lK7WT/NI2WdxgwINULTtE0ahqEC0Y4ORS4ktMvnj\n\
tqU3es9xG6YO9LYQqv+wqC170drwNwoB+S6TgnpT1FkXjPspUIUPm9prjt5BxFtP\n\
uYg+jlrdPJ4KJlBYl6nNUXeK1+xm6Y2SqAEPM6B0MUQyCYwHW+u5ouy9MlEz0nrr\n\
OK/vQCrvAgMBAAECggEAAU51KtqEcou79WUlQZ6/915KJPUqlJWzcVr3dYLj9IU/\n\
Yg5h988KNtg42xrSECADWXS4oevXTXBVbi+X3BJI3EGMvDmXs9lclcIEXWj+csmm\n\
DydNptysVhSl+5GlbYxVzKikbwe1MVGvVETBj6H6BduCSO/vVaPf6fw+qs3qELul\n\
IcDIrNl1tVxfwdF1WABiayUXLibb/EPhDROBLIlTxfQPjx89qh8NWCzJuGtHvL1S\n\
wsrtVcmk+1Odi9GP2bbNxyO7jPpPBntPLg64xc4gUJX6YgSP9jQHP4+AXyhXjbFi\n\
Prs9lfaN8zMBdYrFsLygkDvv/xhO1aWgbjoyJFSS3QKBgQDnDwS+7GoIISeVnW0b\n\
AMQf57ajXyAXQFod4rbp59P1FdmtiI+eR18pOzbmWvvH+Dq+kPl4hey5W3GTcKpS\n\
1USYQ5joz4Vow4SCjwMIpdFuiqrqnnJ+yOMgwlZfygksgB1+n7MeY2VVswci97fn\n\
rQn1yfPx+TSP7/XfFML1TRnGKwKBgQDdY2cSfA4wGOs3sOblJ8ZN419QXlsoXdfG\n\
OWxQpRV94qznY5CIyJHCAqgBZ1U74YutpltXO00BNil+mMf4hKUr3CLK8wwlQ4BF\n\
3SZR4H2GCOjx2tuPYudYmQVKJCcLKEDkwt8wNzj8VtkVQCeuzW9ar8H1qwQR8gle\n\
sCYMw8awTQKBgFgk4ZGYDKcHRtuLj7iyZR8qvQC75DkagoZOG6tFlhUz/bN2mhsu\n\
bP4Eqd/cq5pQdtCF67VvmavoV36Ah2lMFHvlpaqCqAkcNSu9NNISt79sxOD2CwWU\n\
yxiPKnYmU7OXOCk68RDRqDG2Ny2+xHhsCZWrMhWIFOYoC2rLt8fuXru7AoGAOiE3\n\
lyrrrsVcPas9dT4UW68v/7JGzTqWxX2eay5tjjhOnhMOiFvhqcd4xaWUQ7zdKCNe\n\
KHFxrrfB/XOwThjGJdYPbKqUrdQjgjSnMyh2zRLZ12dX7zZQ+Hp1YRpNBijzoR1p\n\
7QcS9272YRYPVV6rtmwfyZm13+BlhW9LDl75dKECgYAYu0MM5BIuOxo2D/ujnrtP\n\
expEqXKOfK8rJDinXeUCVj5lChrdDHS8ZSONycTMllELjRriYeWCMVBcBp2DGjW9\n\
xe9jarmRkNgcVpQWpU9Kz1M5FnNncgT5+hnmhnIOUpsYut2v3uR8STZt8KIrUdtC\n\
V/IMBBBQl6DhX9JejE66Cw==\n\
-----END PRIVATE KEY-----\n";

fn fixture_dir() -> PathBuf {
    // Unique per call so parallel tests do not overwrite shared PEM fixtures.
    let dir = std::env::temp_dir().join(format!(
        "openmls-qrng-provider-config-tests-{}-{}",
        std::process::id(),
        FIXTURE_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&dir).expect("create fixture directory");
    dir
}

fn write_fixture(name: &str, contents: &str) -> PathBuf {
    let path = fixture_dir().join(name);
    fs::write(&path, contents).expect("write PEM fixture");
    path
}

fn missing_path(name: &str) -> PathBuf {
    let path = fixture_dir().join(name);
    let _ = fs::remove_file(&path);
    assert!(!path.exists());
    path
}

fn mtls_paths() -> (PathBuf, PathBuf, PathBuf) {
    (
        write_fixture("ca.crt", CA_CERT_PEM),
        write_fixture("client.crt", CLIENT_CERT_PEM),
        write_fixture("client.key", CLIENT_KEY_PEM),
    )
}

fn config(base_url: &str, transport: TransportMode) -> QrngConfig {
    QrngConfig {
        base_url: base_url.parse().expect("valid URL"),
        transport,
        auth: ApiAuth::None,
        entropy_type: None,
        request_timeout: Duration::from_secs(5),
        health_poll_interval: Some(Duration::from_secs(5)),
    }
}

#[test]
fn plain_http_accepts_http_url() {
    let cfg = config("http://127.0.0.1:8002", TransportMode::PlainHttp);
    assert!(cfg.validate().is_ok());
}

#[test]
fn tls_accepts_https_url_without_custom_ca() {
    let cfg = config(
        "https://entropy.example.net/qrng",
        TransportMode::Tls { ca_cert_pem: None },
    );
    assert!(cfg.validate().is_ok());
}

#[test]
fn mutual_tls_accepts_https_url_with_readable_pem_files() {
    let (ca, cert, key) = mtls_paths();
    let cfg = config(
        "https://entropy.example.net",
        TransportMode::MutualTls {
            ca_cert_pem: ca,
            client_cert_pem: cert,
            client_key_pem: key,
        },
    );
    assert!(cfg.validate().is_ok());
}

#[test]
fn accepts_disabled_health_poll_interval() {
    let mut cfg = config("http://127.0.0.1:8002", TransportMode::PlainHttp);
    cfg.health_poll_interval = None;
    assert!(cfg.validate().is_ok());
}

#[test]
fn plain_http_rejects_https_url() {
    let err = config("https://entropy.example.net", TransportMode::PlainHttp)
        .validate()
        .expect_err("https must be rejected with PlainHttp");
    assert!(matches!(err, QrngError::InvalidConfig(_)));
}

#[test]
fn tls_rejects_http_url() {
    let err = config(
        "http://127.0.0.1:8002",
        TransportMode::Tls { ca_cert_pem: None },
    )
    .validate()
    .expect_err("http must be rejected with Tls");
    assert!(matches!(err, QrngError::InvalidConfig(_)));
}

#[test]
fn mutual_tls_rejects_http_url() {
    let (ca, cert, key) = mtls_paths();
    let err = config(
        "http://127.0.0.1:8002",
        TransportMode::MutualTls {
            ca_cert_pem: ca,
            client_cert_pem: cert,
            client_key_pem: key,
        },
    )
    .validate()
    .expect_err("http must be rejected with MutualTls");
    assert!(matches!(err, QrngError::InvalidConfig(_)));
}

#[test]
fn rejects_zero_request_timeout() {
    let mut cfg = config("http://127.0.0.1:8002", TransportMode::PlainHttp);
    cfg.request_timeout = Duration::ZERO;
    let err = cfg
        .validate()
        .expect_err("zero request_timeout must be rejected");
    assert!(matches!(err, QrngError::InvalidConfig(_)));
}

#[test]
fn rejects_zero_health_poll_interval() {
    let mut cfg = config("http://127.0.0.1:8002", TransportMode::PlainHttp);
    cfg.health_poll_interval = Some(Duration::ZERO);
    let err = cfg
        .validate()
        .expect_err("zero health_poll_interval must be rejected");
    assert!(matches!(err, QrngError::InvalidConfig(_)));
}

#[test]
fn rejects_url_with_query_string() {
    let err = config(
        "https://entropy.example.net/?foo=bar",
        TransportMode::Tls { ca_cert_pem: None },
    )
    .validate()
    .expect_err("query string must be rejected");
    assert!(matches!(err, QrngError::InvalidConfig(_)));
}

#[test]
fn rejects_url_with_fragment() {
    let err = config(
        "https://entropy.example.net/#section",
        TransportMode::Tls { ca_cert_pem: None },
    )
    .validate()
    .expect_err("fragment must be rejected");
    assert!(matches!(err, QrngError::InvalidConfig(_)));
}

#[test]
fn tls_rejects_missing_ca_cert_file() {
    let missing = missing_path("missing-ca.pem");
    let err = config(
        "https://entropy.example.net",
        TransportMode::Tls {
            ca_cert_pem: Some(missing),
        },
    )
    .validate()
    .expect_err("missing CA file must be rejected");
    assert!(
        matches!(err, QrngError::TlsMaterial(_) | QrngError::InvalidConfig(_)),
        "expected TlsMaterial (preferred) or InvalidConfig, got {err:?}"
    );
}

#[test]
fn tls_rejects_non_pem_ca_cert_file() {
    let not_pem = write_fixture("not-a-cert.txt", "this is not pem material\n");
    let err = config(
        "https://entropy.example.net",
        TransportMode::Tls {
            ca_cert_pem: Some(not_pem),
        },
    )
    .validate()
    .expect_err("non-PEM CA file must be rejected");
    assert!(
        matches!(err, QrngError::TlsMaterial(_) | QrngError::InvalidConfig(_)),
        "expected TlsMaterial (preferred) or InvalidConfig, got {err:?}"
    );
}

#[test]
fn mutual_tls_rejects_missing_client_key_file() {
    let (ca, cert, _) = mtls_paths();
    let missing_key = missing_path("missing-client.key");
    let err = config(
        "https://entropy.example.net",
        TransportMode::MutualTls {
            ca_cert_pem: ca,
            client_cert_pem: cert,
            client_key_pem: missing_key,
        },
    )
    .validate()
    .expect_err("missing client key must be rejected");
    assert!(
        matches!(err, QrngError::TlsMaterial(_) | QrngError::InvalidConfig(_)),
        "expected TlsMaterial (preferred) or InvalidConfig, got {err:?}"
    );
}
