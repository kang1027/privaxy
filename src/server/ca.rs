use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::{X509, X509NameBuilder};
use openssl::x509::extension::{BasicConstraints, KeyUsage, SubjectKeyIdentifier};

pub fn make_ca_certificate() -> (X509, PKey<Private>){
    // RSA 2048 암호화 알고리즘 사용
    let rsa = Rsa::generate(2048).unwrap();
    // rsa 기반으로 key pair 생성
    let key_pair = PKey::from_rsa(rsa).unwrap();

    // x509 name 빌드
    let mut x509_name = X509NameBuilder::new().unwrap();
    // Country
    x509_name.append_entry_by_text("C", "KR").unwrap();
    // State
    x509_name.append_entry_by_text("ST", "SE").unwrap();
    // Organization
    x509_name.append_entry_by_text("O", "Privaxy").unwrap();
    // Common Name
    x509_name.append_entry_by_text("CN", "Privaxy").unwrap();
    let x509_name = x509_name.build();

    let mut cert_builder = X509::builder().unwrap();
    // X.509 v3의 확장 사용하기 위함.
    cert_builder.set_version(2).unwrap();

    // X.509 인증서의 일련 번호 생성
    let serial_number = {
        let mut serial = BigNum::new().unwrap();
        // 159 bits 로 난수 생성, 양수로 설정하되 MSB(최상위 비트)가 0일 수 있음.
        serial.rand(159, MsbOption::MAYBE_ZERO, false).unwrap();
        // 인증서에 적용하기 위해 난수를 ASN.1 형식의 정수로 변환.
        serial.to_asn1_integer().unwrap()
    };

    // serial number 설정
    cert_builder.set_serial_number(&serial_number).unwrap();
    // 주체 설정
    cert_builder.set_subject_name(&x509_name).unwrap();
    // 발급자 설정 (CA 설정으로 발급자와 주체가 동일)
    cert_builder.set_issuer_name(&x509_name).unwrap();
    // 인증서의 공개 키 설정
    // 개인 키는 개별 관리, 클라 <-> 서버 간 암호화 통신 위해 public key 지정.
    cert_builder.set_pubkey(&key_pair).unwrap();

    // 인증서 유효 시작 날짜
    let not_before = Asn1Time::days_from_now(0).unwrap();
    cert_builder.set_not_before(&not_before).unwrap();

    // 인증서 유효 종료 날짜, 3650일, 약 10년으로 지정
    let not_after = Asn1Time::days_from_now(3650).unwrap();
    cert_builder.set_not_after(&not_after).unwrap();

    // BasicConstraints extension 추가 (인증서가 CA로 사용될 수 있는지를 제어)
    cert_builder.append_extension(
        BasicConstraints::new()
            // 임계값 (critical) 으로 지정해 BasicConstraints 확장을
            // 이해하지 못하는 시스템에서는 인증서를 거부해야 함을 나타냄.
            .critical()
            // Certificate Authority 로 사용할 수 있음을 나타냄.
            // CA 로 사용 가능한 인증서는 다른 인증서를 서명할 수 있음.
            .ca()
            .build()
            .unwrap()
    ).unwrap();

    // KeyUsage extension 추가 (특정한 키 사용 규칙을 정의)
    cert_builder.append_extension(
        KeyUsage::new()
            .critical()
            // 키 인증 및 인증서 서명에 사용할 수 있음을 나타냄.
            .key_cert_sign()
            // CRL(Certificate Revocation List) 서명에 사용할 수 있음을 나타냄.
            // CRL => '인증서 폐지 목록' 으로 폐지된 인증서들의 목록임.
            .crl_sign()
            .build()
            .unwrap()
    ).unwrap();

    // SKI(Subject Key Identifier) 는 인증서 내에서 사용되는 특정 키의 식별자로, 쉽게 키를 식별하기 위해 사용함.
    // 다른 인증서에서 SKI 값을 비교해 서명한 CA의 공개 키를 식별하거나 특정 사용자의 인증서를 검증하는 데 사용
    // cert_builder 의 X.509 v3 context 를 사용해 Subject Key Identifier 빌드.
    let subject_key_identifier = SubjectKeyIdentifier::new()
        .build(&cert_builder.x509v3_context(None, None))
        .unwrap();

    // 공개 키 식별에 사용하기 위해 extension 추가.
    cert_builder.append_extension(subject_key_identifier).unwrap();

    // 인증서의 개인 키로 SHA-256 해시 함수를 사용해 서명.
    cert_builder.sign(&key_pair, MessageDigest::sha256()).unwrap();

    let cert = cert_builder.build();

    // X.509 인증서와 private key 를 반환.
    (cert, key_pair)
}