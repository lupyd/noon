use recrypt::{
    api::{
        DefaultRng, EncryptedValue, Plaintext, PrivateKey, PublicKey, SigningKeypair, TransformKey,
    },
    prelude::*,
};

const ENCODED_SIZE_BYTES: usize = 384;

pub struct ProxyReEncryptor {
    recrypt: Recrypt<Sha256, Ed25519, RandomBytes<DefaultRng>>,
    signing_keypair: SigningKeypair,
}

impl ProxyReEncryptor {
    pub fn new() -> Self {
        let recrypt = Recrypt::new();
        let signing_keypair = recrypt.generate_ed25519_key_pair();
        Self {
            recrypt,
            signing_keypair,
        }
    }

    pub fn transform(
        &self,
        transform_key: TransformKey,
        encrypted_value: EncryptedValue,
    ) -> EncryptedValue {
        let result = self
            .recrypt
            .transform(encrypted_value, transform_key, &self.signing_keypair)
            .unwrap();
        result
    }
}

pub struct Client {
    recrypt: Recrypt<Sha256, Ed25519, RandomBytes<DefaultRng>>,
    private_key: PrivateKey,
    public_key: PublicKey,
    signing_keypair: SigningKeypair,
}

impl Client {
    pub fn new() -> Self {
        let recrypt = Recrypt::new();

        let signing_keypair = recrypt.generate_ed25519_key_pair();
        let (private_key, public_key) = recrypt.generate_key_pair().unwrap();
        Self {
            recrypt,
            private_key,
            public_key,
            signing_keypair,
        }
    }

    fn encrypt(&self, pt: &Plaintext) -> EncryptedValue {
        let result = self
            .recrypt
            .encrypt(pt, &self.public_key, &self.signing_keypair)
            .unwrap();

        result
    }
    pub fn transform_key(&self, private_key: &PrivateKey) -> (PrivateKey, TransformKey) {
        let (target_priv_key, target_pub_key) = self.recrypt.generate_key_pair().unwrap();
        let initial_to_target_transform_key = self
            .recrypt
            .generate_transform_key(private_key, &target_pub_key, &self.signing_keypair)
            .unwrap();
        (target_priv_key, initial_to_target_transform_key)
    }

    fn decrypt(&self, private_key: &PrivateKey, encrypted_value: EncryptedValue) -> Plaintext {
        let result = self.recrypt.decrypt(encrypted_value, private_key).unwrap();

        result
    }

    pub fn encrypt_message(&self, message: &[u8]) -> Vec<u8> {
        for chunk in message.chunks(ENCODED_SIZE_BYTES) {
            if chunk.len() == ENCODED_SIZE_BYTES {
            } else {
                let mut new_chunk = vec![0u8; ENCODED_SIZE_BYTES];
                new_chunk[..chunk.len()].copy_from_slice(chunk);
            }

            let pt = Plaintext::new_from_slice(chunk).unwrap();

            let ev = self.encrypt(&pt);
        }

        todo!()
    }
}

#[test]
fn test_re_encryption() {
    let _ = env_logger::try_init();
    let client = Client::new();
    let server = ProxyReEncryptor::new();

    let pt = Recrypt::new().gen_plaintext();

    let encrypted = client.encrypt(&pt);
    log::info!("{:?}", encrypted);
    let (new_key, transform_key) = client.transform_key(&client.private_key);

    let re_encrypted = server.transform(transform_key, encrypted);
    log::info!("{:?}", re_encrypted);
    let decrypted = client.decrypt(&new_key, re_encrypted.clone());

    assert_eq!(pt, decrypted);

    let (new_key, transform_key) = client.transform_key(&new_key);

    let re_encrypted = server.transform(transform_key, re_encrypted);
    log::info!("{:?}", re_encrypted);
    let decrypted = client.decrypt(&new_key, re_encrypted);
    log::info!("{:?}", decrypted);

    assert_eq!(pt, decrypted);
}
