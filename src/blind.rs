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

pub struct Server {
    private_key: RsaPrivateKey,
}

impl Server {
    pub fn new() -> Self {
        Self {
            private_key: RsaPrivateKey::new(&mut rand::rngs::OsRng::default(), 1024).unwrap(),
        }
    }

    pub fn public_key(&self) -> RsaPublicKey {
        self.private_key.to_public_key()
    }
}

impl Server {
    pub fn blind_sign(&self, payload: &[u8]) -> Result<Vec<u8>, String> {
        let m_blinded = rsa::BigUint::from_bytes_le(payload);
        let d = self.private_key.d();
        let n = self.private_key.n();

        let s_blinded = m_blinded.modpow(&d, &n);

        Ok(s_blinded.to_bytes_le())
    }

    pub fn verify(&self, payload: &[u8], signature: &[u8]) -> bool {
        let s = rsa::BigUint::from_bytes_le(signature);
        let n = self.private_key.n();

        let m_check = s.modpow(&self.private_key.e(), &n);

        m_check == rsa::BigUint::from_bytes_le(payload)
    }
}

pub struct Client {
    identity: String,
}

impl Client {
    pub fn identity(&self) -> &str {
        &self.identity
    }

    pub fn new(identity: impl Into<String>) -> Self {
        Self {
            identity: identity.into(),
        }
    }

    pub fn create_blinded_message(
        &self,
        payload: &[u8],
        public_key: &RsaPublicKey,
    ) -> BlindedMessage {
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

    pub fn unblind_signature(
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

#[derive(Debug)]
pub struct BlindedMessage {
    m: BigUint,
    r: BigUint,
    m_blinded: BigUint,
}

impl BlindedMessage {
    pub fn blinded_message(&self) -> Vec<u8> {
        self.m_blinded.to_bytes_le()
    }
    pub fn message(&self) -> Vec<u8> {
        self.m.to_bytes_le()
    }
}

#[test]
fn test_blind_sign() {
    let _ = env_logger::try_init();

    let alice = Client::new("alice");
    let server = Server::new();

    let server_public_key = server.public_key();
    let blinded_message =
        alice.create_blinded_message("I vote for freedom".as_bytes(), &server_public_key);

    log::info!(
        "Message: {:X?}, Blinded Message: {:X?}",
        blinded_message.message(),
        blinded_message.blinded_message()
    );
    let blinded_signature = server
        .blind_sign(&blinded_message.blinded_message())
        .unwrap();
    log::info!("Blinded Signature: {:X?}", blinded_signature);
    let signature =
        alice.unblind_signature(&blinded_message, &blinded_signature, &server_public_key);
    log::info!("Signature: {:X?}", signature);

    assert!(server.verify(&blinded_message.message(), &signature));
    assert!(!server.verify(&blinded_message.message(), &blinded_signature));
    assert!(server.verify(&blinded_message.blinded_message(), &blinded_signature));
}
