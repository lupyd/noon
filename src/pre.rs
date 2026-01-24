use std::io::Write;
use std::time::Instant;

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
    fn print_encrypted_value(ev: &EncryptedValue, w: &mut impl Write) {
        match ev {
            EncryptedValue::EncryptedOnceValue {
                ephemeral_public_key,
                encrypted_message,
                auth_hash,
                public_signing_key,
                signature,
            } => {
                writeln!(w, "EncryptedOnceValue:").unwrap();
                let (x, y) = ephemeral_public_key.bytes_x_y();
                writeln!(w, "  ephemeral_public_key: x={}, y={}", hex::encode(x), hex::encode(y)).unwrap();
                writeln!(w, "  encrypted_message: {}", hex::encode(encrypted_message.bytes())).unwrap();
                writeln!(w, "  auth_hash: {}", hex::encode(auth_hash.bytes())).unwrap();
                writeln!(w, "  public_signing_key: {}", hex::encode(public_signing_key.bytes())).unwrap();
                writeln!(w, "  signature: {}", hex::encode(signature.bytes())).unwrap();
            }
            EncryptedValue::TransformedValue {
                ephemeral_public_key,
                encrypted_message,
                auth_hash,
                transform_blocks,
                public_signing_key,
                signature,
            } => {
                writeln!(w, "TransformedValue:").unwrap();
                let (x, y) = ephemeral_public_key.bytes_x_y();
                writeln!(w, "  ephemeral_public_key: x={}, y={}", hex::encode(x), hex::encode(y)).unwrap();
                writeln!(w, "  encrypted_message: {}", hex::encode(encrypted_message.bytes())).unwrap();
                writeln!(w, "  auth_hash: {}", hex::encode(auth_hash.bytes())).unwrap();
                writeln!(w, "  public_signing_key: {}", hex::encode(public_signing_key.bytes())).unwrap();
                writeln!(w, "  signature: {}", hex::encode(signature.bytes())).unwrap();
                writeln!(w, "  transform_blocks:").unwrap();
                for (i, block) in transform_blocks.to_vec().iter().enumerate() {
                    writeln!(w, "    [{}]:", i).unwrap();
                    let (x, y) = block.public_key().bytes_x_y();
                    writeln!(w, "      public_key: x={}, y={}", hex::encode(x), hex::encode(y)).unwrap();
                    writeln!(w, "      encrypted_temp_key: {}", hex::encode(block.encrypted_temp_key().bytes())).unwrap();
                    let (x, y) = block.random_transform_public_key().bytes_x_y();
                    writeln!(w, "      random_transform_public_key: x={}, y={}", hex::encode(x), hex::encode(y)).unwrap();
                    writeln!(w, "      encrypted_random_transform_temp_key: {}", hex::encode(block.encrypted_random_transform_temp_key().bytes())).unwrap();
                }
            }
        }
    }

    let _ = env_logger::try_init();
    let start = Instant::now();
    let client = Client::new();
    log::info!("Client creation: {:?}", start.elapsed());
    let start = Instant::now();
    let server = ProxyReEncryptor::new();
    log::info!("Server creation: {:?}", start.elapsed());

    let pt = Recrypt::new().gen_plaintext();

    let start = Instant::now();
    let mut encrypted = client.encrypt(&pt);
    log::info!("Initial encryption: {:?}", start.elapsed());
    let mut buffer = Vec::new();
    print_encrypted_value(&encrypted, &mut buffer);
    log::info!("Initial: {}", String::from_utf8_lossy(&buffer));

    let mut current_key = client.private_key.clone();
    const N: usize = 6;

    for i in 0..N {
        let start = Instant::now();
        let (new_key, transform_key) = client.transform_key(&current_key);
        log::info!("Transform key generation {}: {:?}", i + 1, start.elapsed());

        let start = Instant::now();
        encrypted = server.transform(transform_key, encrypted);
        log::info!("Transform operation {}: {:?}", i + 1, start.elapsed());
        
        let mut buffer = Vec::new();
        print_encrypted_value(&encrypted, &mut buffer);
        log::info!("Transform {}: {}", i + 1, String::from_utf8_lossy(&buffer));
        
        let start = Instant::now();
        let decrypted = client.decrypt(&new_key, encrypted.clone());
        log::info!("Decryption {}: {:?}", i + 1, start.elapsed());
        assert_eq!(pt, decrypted);
        
        current_key = new_key;
    }
}
