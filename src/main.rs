use num_bigint_dig::BigUint;
use num_bigint_dig::ModInverse;
use num_bigint_dig::RandBigInt;
use num_integer::Integer;
use num_traits::{One, Zero};
use rsa::RsaPublicKey;
use rsa::{
    RsaPrivateKey,
    traits::{PrivateKeyParts, PublicKeyParts},
};

fn main() {
    env_logger::init();
    log::info!("Hello, world!");

    let bits = 2048;
    let mut rng = rand::rngs::OsRng::default();

    let priv_key = RsaPrivateKey::new(&mut rng, bits).unwrap();
    let pub_key = priv_key.to_public_key();
    let n = pub_key.n();
    let e = pub_key.e();
    let d = priv_key.d();

    let n = BigUint::from_bytes_le(n.to_bytes_le().as_slice());
    let e = BigUint::from_bytes_le(e.to_bytes_le().as_slice());
    let d = BigUint::from_bytes_le(d.to_bytes_le().as_slice());

    log::info!("n: {}", n);
    log::info!("e: {}", e);
    log::info!("d: {}", d);

    let m = rng.gen_biguint(1024);

    log::info!("m: {}", m);
    let r = loop {
        let r = rng.gen_biguint_below(&n);

        if r != BigUint::zero() && r.gcd(&n) == BigUint::one() {
            break r;
        }
    };
    log::info!("r: {}", r);

    let r_e = r.modpow(&e, &n);
    let m_blinded = (&m * &r_e) % &n;

    let s_blinded = m_blinded.modpow(&d, &n);

    let r_inv = r.mod_inverse(&n).unwrap().to_biguint().unwrap();

    let s = (&s_blinded * &r_inv) % &n;

    let m_check = s.modpow(&e, &n);

    assert_eq!(m, m_check);

    log::info!("r_e: {}", r_e);
    log::info!("m_blinded: {}", m_blinded);
    log::info!("s_blinded: {}", s_blinded);
    log::info!("r_inv: {}", r_inv);
    log::info!("s: {}", s);
    log::info!("m_check: {}", m_check);

    let alice = Client::new("alice");
    let server = Server::new();

    let server_public_key = server.public_key();
    let blinded_message =
        alice.create_blinded_message("I vote for freedom".as_bytes(), &server_public_key);
    let blinded_signature = server.blind_sign(&blinded_message.blinded_message());
    let signature =
        alice.unblind_signature(&blinded_message, &blinded_signature, &server_public_key);

    assert!(server.verify(&blinded_message.message(), &signature));
}

struct Server {
    private_key: RsaPrivateKey,
}

impl Server {
    pub fn new() -> Self {
        Self {
            private_key: RsaPrivateKey::new(&mut rand::rngs::OsRng::default(), 1024).unwrap(),
        }
    }

    fn public_key(&self) -> RsaPublicKey {
        self.private_key.to_public_key()
    }
}

fn verify_identity(identity: &str) -> bool {
    // authentication logic
    return true;
}

impl Server {
    fn blind_sign(&self, payload: &[u8]) -> Vec<u8> {
        let m_blinded = rsa::BigUint::from_bytes_le(payload);
        let d = self.private_key.d();
        let n = self.private_key.n();

        let s_blinded = m_blinded.modpow(&d, &n);

        s_blinded.to_bytes_le()
    }

    fn verify(&self, payload: &[u8], signature: &[u8]) -> bool {
        let s = rsa::BigUint::from_bytes_le(signature);
        let n = self.private_key.n();

        let m_check = s.modpow(&self.private_key.e(), &n);

        m_check == rsa::BigUint::from_bytes_le(payload)
    }
}

struct Client {
    identity: String,
}

impl Client {
    fn new(identity: impl Into<String>) -> Self {
        Self {
            identity: identity.into(),
        }
    }

    fn create_blinded_message(&self, payload: &[u8], public_key: &RsaPublicKey) -> BlindedMessage {
        let mut rng = rand::rngs::OsRng::default();
        let n = public_key.n();
        let e = public_key.e();
        let r = loop {
            let r = rng.gen_biguint_below(&n);

            if r != BigUint::zero() && r.gcd(&n) == BigUint::one() {
                break r;
            }
        };

        let m = rsa::BigUint::from_bytes_le(payload);
        let r_e = r.modpow(&e, &n);
        let m_blinded = (&m * &r_e) % n;

        BlindedMessage { r, m_blinded, m }
    }

    fn unblind_signature(
        &self,
        blinded_message: &BlindedMessage,
        blinded_signature: &[u8],
        public_key: &RsaPublicKey,
    ) -> Vec<u8> {
        let s_blinded = BigUint::from_bytes_le(blinded_signature);
        let n = public_key.n();
        let r = &blinded_message.r;
        let r_inv = r.mod_inverse(n).unwrap().to_biguint().unwrap();
        let s = (&s_blinded * &r_inv) % n;

        s.to_bytes_le()
    }
}

struct BlindedMessage {
    m: BigUint,
    r: BigUint,
    m_blinded: BigUint,
}

impl BlindedMessage {
    fn blinded_message(&self) -> Vec<u8> {
        self.m_blinded.to_bytes_le()
    }
    fn message(&self) -> Vec<u8> {
        self.m.to_bytes_le()
    }
}

struct Submission {
    payload: Vec<u8>,
    signature: Vec<u8>,
}
