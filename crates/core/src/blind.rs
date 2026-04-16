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

pub struct BlindSigner {
    private_key: RsaPrivateKey,
}

impl BlindSigner {
    pub fn generate() -> Self {
        Self::new(RsaPrivateKey::new(&mut rand::rngs::OsRng::default(), 1024).unwrap())
    }

    pub fn new(private_key: RsaPrivateKey) -> Self {
        Self { private_key }
    }

    pub fn public_key(&self) -> RsaPublicKey {
        self.private_key.to_public_key()
    }
}

impl BlindSigner {
    pub fn blind_sign(&self, payload: &[u8]) -> Result<Vec<u8>, String> {
        let m_blinded = rsa::BigUint::from_bytes_le(payload);
        let d = self.private_key.d();
        let n = self.private_key.n();

        let s_blinded = m_blinded.modpow(&d, &n);

        Ok(s_blinded.to_bytes_le())
    }

    pub fn verify(&self, payload: &[u8], signature: &[u8]) -> bool {
        if payload.is_empty() || signature.is_empty() {
            return false;
        }
        let s = rsa::BigUint::from_bytes_le(signature);
        let n = self.private_key.n();

        let m_check = s.modpow(&self.private_key.e(), &n);

        m_check == rsa::BigUint::from_bytes_le(payload) % n
    }
}

pub fn create_blinded_message(payload: &[u8], public_key: &RsaPublicKey) -> BlindedMessage {
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
    use rand::RngCore;
    use sha2::{Digest, Sha256};

    let server = BlindSigner::generate();
    let server_public_key = server.public_key();

    let batch_size = std::env::var("BATCH_SIZE")
        .map(|x| x.parse().unwrap_or(1))
        .unwrap_or(1);

    for i in 0..batch_size {
        println!("Batch ID: {}", i);
        let mut submission = vec![0u8; 1024];
        let mut nonce = vec![0u8; 16];

        rand::rngs::OsRng::default()
            .try_fill_bytes(&mut submission)
            .unwrap();
        rand::rngs::OsRng::default()
            .try_fill_bytes(&mut nonce)
            .unwrap();

        let mut hasher = Sha256::new();
        hasher.update(&submission);
        hasher.update(&nonce);
        let hash = hasher.finalize();

        let blinded_message = create_blinded_message(&hash, &server_public_key);

        let blinded_signature = server
            .blind_sign(&blinded_message.blinded_message())
            .unwrap();
        let signature = unblind_signature(&blinded_message, &blinded_signature, &server_public_key);

        assert!(server.verify(&hash, &signature));
        assert!(!server.verify(&hash, &blinded_signature));
    }
}
