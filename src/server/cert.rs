use std::str::FromStr;
use std::sync::{Arc};
use tokio::sync::Mutex;
use http::uri::Authority;
use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::{X509, X509NameBuilder, X509Req, X509ReqBuilder};
use openssl::x509::extension::{AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectAlternativeName, SubjectKeyIdentifier};
use rustls::{Certificate, PrivateKey, ServerConfig};
use uluru::LRUCache;

const MAX_CACHED_CERTIFICATES:usize = 1_000;

#[derive(Clone)]
pub struct SignedWithCaCert {
    authority: Authority,
    pub server_configuration: ServerConfig,
}

impl SignedWithCaCert {
    fn new(
        authority: Authority,
        private_key: PKey<Private>,
        ca_certificate: X509,
        ca_private_key: PKey<Private>
    ) -> Self {
        let x509 = Self::build_ca_signed_cert(&ca_certificate, &ca_private_key, &authority, &private_key);

        let certs = vec![
            Certificate(x509.to_der().unwrap()),
            Certificate(ca_certificate.to_der().unwrap()),
        ];

        let server_configuration = ServerConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs, PrivateKey(private_key.private_key_to_der().unwrap()))
            .unwrap();

        Self {
            authority,
            server_configuration,
        }
    }

    fn build_ca_signed_cert(
        ca_cert: &X509,
        ca_key_pair: &PKey<Private>,
        authority: &Authority,
        private_key: &PKey<Private>,
    ) -> X509 {
        let req = Self::build_certificate_request(private_key, authority);

        let mut cert_builder = X509::builder().unwrap();
        cert_builder.set_version(2).unwrap();

        let serial_number: Asn1Integer = {
          let mut serial = BigNum::new().unwrap();
            serial.rand(159, MsbOption::MAYBE_ZERO, false).unwrap();
            serial.to_asn1_integer().unwrap()
        };

        cert_builder.set_serial_number(&serial_number).unwrap();
        cert_builder.set_subject_name(req.subject_name()).unwrap();
        cert_builder
            .set_issuer_name(ca_cert.subject_name())
            .unwrap();
        cert_builder.set_pubkey(private_key).unwrap();

        let not_before = Asn1Time::days_from_now(0).unwrap();
        let not_after = Asn1Time::days_from_now(365).unwrap();
        cert_builder.set_not_before(&not_before).unwrap();
        cert_builder.set_not_after(&not_after).unwrap();

        cert_builder.append_extension(BasicConstraints::new().build().unwrap()).unwrap();

        cert_builder
            .append_extension(
                KeyUsage::new()
                    .critical()
                    .non_repudiation()
                    .digital_signature()
                    .key_encipherment()
                    .build()
                    .unwrap(),
            )
            .unwrap();

        let subject_alternative_name = match std::net::IpAddr::from_str(authority.host()) {
            Ok(_ip_adder) => {
                let mut san = SubjectAlternativeName::new();
                san.ip(authority.host());
                san
            },
            Err(_err) => {
                let mut san = SubjectAlternativeName::new();
                san.dns(authority.host());
                san
            }
        }.build(&cert_builder.x509v3_context(Some(ca_cert), None)).unwrap();

        cert_builder
            .append_extension(subject_alternative_name)
            .unwrap();

        let subject_key_identifier = SubjectKeyIdentifier::new()
            .build(&cert_builder.x509v3_context(Some(ca_cert), None))
            .unwrap();
        cert_builder.append_extension(subject_key_identifier).unwrap();

        let auth_key_identifier = AuthorityKeyIdentifier::new()
            .keyid(false)
            .issuer(false)
            .build(&cert_builder.x509v3_context(Some(ca_cert), None))
            .unwrap();
        cert_builder.append_extension(auth_key_identifier).unwrap();

        cert_builder
            .sign(ca_key_pair, MessageDigest::sha256())
            .unwrap();

        cert_builder.build()
    }

    fn build_certificate_request(key_pair: &PKey<Private>, authority: &Authority) -> X509Req {
        let mut request_builder = X509ReqBuilder::new().unwrap();
        request_builder.set_pubkey(key_pair).unwrap();

        let mut x509_name = X509NameBuilder::new().unwrap();

        let authority_host = authority.host();
        let common_name = if authority_host.len() > 64 {
            "privaxy_cn_too_long.local"
        } else {
            authority_host
        };

        x509_name.append_entry_by_text("CN", common_name).unwrap();
        let x509_name = x509_name.build();
        request_builder.set_subject_name(&x509_name).unwrap();

        request_builder
            .sign(key_pair, MessageDigest::sha256())
            .unwrap();

        request_builder.build()
    }
}


#[derive(Clone)]
pub struct CertCache {
    // LRU (Least Recently Used) => 운영체제의 페이지 교체 알고리즘 중 하나,
    // 페이지를 교체할 때 가장 오랫동안 사용되지 않은 페이지를 교체 대상으로 삼는 알고리즘.
    // LRU Cache => Cache 에 공간이 부족할 때 가장 오랫동안 사용하지 않은 데이터를 제거하고 새로운 데이터를 배치함.
    // LRUCache 는 get, get_mut, put, pop 메서드 제공하며, 이 연산들은 전부 O(1)에 처리 가능. (Double Linked List 사용)
    // MAX_CACHED_CERTIFICATES 수 만큼 Cache 공간 생성 및, LRU 알고리즘에 따라 Cache 관리.
    cache: Arc<Mutex<LRUCache<SignedWithCaCert, MAX_CACHED_CERTIFICATES>>>,
    // We use a single RSA key for all certificates.
    private_key: PKey<Private>,
    ca_certificate: X509,
    ca_private_key: PKey<Private>,
}


impl CertCache {
    pub fn new(ca_certificate: X509, ca_private_key: PKey<Private>) -> Self {
        Self {
            cache: Arc::new(Mutex::new(LRUCache::default())),
            private_key: {
                let rsa = Rsa::generate(2048).unwrap();
                PKey::from_rsa(rsa).unwrap()
            },
            ca_certificate,
            ca_private_key,
        }
    }

    async fn insert(&self, certificate: SignedWithCaCert) {
        let mut cache = self.cache.lock().await;
        cache.insert(certificate);
    }

    // mitm 에서 어떻게 사용하는지 확인 후 설명 (?)
    async fn get(&self, authority: Authority) -> SignedWithCaCert {
        let mut cache = self.cache.lock().await;

        match cache.find(|cert| cert.authority == authority) {
            Some(certificate) => certificate.clone(),
            None => {
                drop(cache);
                let private_key = self.private_key.clone();
                let ca_certificate = self.ca_certificate.clone();
                let ca_private_key = self.ca_private_key.clone();

                let certificate = tokio::task::spawn_blocking(move || {
                    SignedWithCaCert::new(authority, private_key, ca_certificate, ca_private_key)
                })
                    .await
                    .unwrap();

                self.insert(certificate.clone()).await;
                certificate
            }
        }
    }

}
