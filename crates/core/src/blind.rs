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
    let _ = env_logger::try_init();

    let server = BlindSigner::generate();

    let server_public_key = server.public_key();

    let batch_size = std::env::var("BATCH_SIZE")
        .map(|x| x.parse().unwrap_or(1))
        .unwrap();
    for i in 0..batch_size {
        log::info!("Batch ID: {}", i);
        let mut payload = vec![0u8; 2048];

        rand::rngs::OsRng::default()
            .try_fill_bytes(&mut payload)
            .unwrap();

        let blinded_message = create_blinded_message(&payload, &server_public_key);

        log::info!("Message: {:X?}Blinded Message", blinded_message.message(),);
        log::info!("Blinded Message: {:X?}", blinded_message.blinded_message());
        let blinded_signature = server
            .blind_sign(&blinded_message.blinded_message())
            .unwrap();
        log::info!("Blinded Signature: {:X?}", blinded_signature);
        let signature = unblind_signature(&blinded_message, &blinded_signature, &server_public_key);
        log::info!("Signature: {:X?}", signature);

        assert!(server.verify(&blinded_message.message(), &signature));
        assert!(!server.verify(&blinded_message.message(), &blinded_signature));
        assert!(server.verify(&blinded_message.blinded_message(), &blinded_signature));
    }
}
