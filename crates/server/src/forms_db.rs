use anyhow::Context;
use deadpool_postgres::Pool;
use noon_core::blind::BlindSigner;
use quick_protobuf::{MessageRead, MessageWrite};
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use std::time::{SystemTime, UNIX_EPOCH};
use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey};
use serde::{Deserialize, Serialize};

use crate::pb::forms::{Form, FormSubmission};
use crate::otp::generate_otp;

pub async fn get_or_create_blind_signer(pool: &Pool) -> anyhow::Result<BlindSigner> {
    let client = pool.get().await?;

    let row = client
        .query_opt(
            "SELECT rsa_key FROM keys ORDER BY created_at DESC LIMIT 1",
            &[],
        )
        .await?;

    if let Some(row) = row {
        let rsa_key_bytes: Vec<u8> = row.get(0);
        let private_key = rsa::RsaPrivateKey::from_pkcs8_der(&rsa_key_bytes)
            .context("Failed to parse pkcs8 der from db")?;
        return Ok(BlindSigner::new(private_key));
    }

    log::info!("No existing RSA key found. Generating a new BlindSigner key...");
    let private_key = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng::default(), 1024).unwrap();
    let pkcs8_doc = private_key.to_pkcs8_der().unwrap();
    let pkcs8_bytes = pkcs8_doc.as_bytes();

    client
        .execute("INSERT INTO keys (rsa_key) VALUES ($1)", &[&pkcs8_bytes])
        .await?;

    Ok(BlindSigner::new(private_key))
}

pub async fn create_form(pool: &Pool, mut form: Form<'_>, owner: String) -> anyhow::Result<u64> {
    let client = pool.get().await?;

    let mut out = Vec::new();
    let mut writer = quick_protobuf::Writer::new(&mut out);
    form.write_message(&mut writer)?;

    let mentioned_emails: Vec<&str> = form.mentioned_emails.iter().map(|s| s.as_ref()).collect();

    let stmt = "INSERT INTO forms (name, description, owner, fields, mentioned_emails) VALUES ($1, $2, $3, $4, $5) RETURNING id";
    let row = client
        .query_one(
            stmt,
            &[
                &form.name.to_string(),
                &form.description.to_string(),
                &owner,
                &out,
                &mentioned_emails,
            ],
        )
        .await?;

    let form_id: i64 = row.get(0);
    form.id = form_id as u64;

    for participant in &form.allowed_participants {
        let stmt = "INSERT INTO form_allowed_participants (form_id, participant) VALUES ($1, $2) ON CONFLICT DO NOTHING";
        client
            .execute(stmt, &[&form_id, &format!("user:{}", participant)])
            .await?;
    }

    for email in &form.mentioned_emails {
        let stmt = "INSERT INTO form_allowed_participants (form_id, participant) VALUES ($1, $2) ON CONFLICT DO NOTHING";
        client
            .execute(stmt, &[&form_id, &format!("email:{}", email)])
            .await?;
    }

    Ok(form_id as u64)
}

pub async fn get_form_bytes(pool: &Pool, form_id: u64) -> anyhow::Result<Vec<u8>> {
    let client = pool.get().await?;
    let row = client.query_one("SELECT name, description, owner, fields, extract(epoch from created_at)::bigint as created_at, mentioned_emails FROM forms WHERE id = $1", &[&(form_id as i64)]).await?;

    let name: String = row.get(0);
    let description: String = row.get(1);
    let owner: String = row.get(2);
    let bytes: Vec<u8> = row.get(3);
    let created_at: i64 = row.get(4);
    let mentioned_emails: Vec<String> = row.get(5);

    let mut reader = quick_protobuf::BytesReader::from_bytes(&bytes);
    let parsed_form = Form::from_reader(&mut reader, &bytes).unwrap_or_default();

    let mut form = parsed_form;
    form.id = form_id;
    form.name = name.into();
    form.description = description.into();
    form.owner = owner.into();
    form.created_at = created_at as u64;
    form.mentioned_emails = mentioned_emails.into_iter().map(|s| s.into()).collect();

    let rows = client
        .query(
            "SELECT participant FROM form_allowed_participants WHERE form_id = $1",
            &[&(form_id as i64)],
        )
        .await?;
    form.allowed_participants = rows
        .into_iter()
        .map(|r| {
            let p: String = r.get(0);
            p.into()
        })
        .collect();

    let mut final_out = Vec::new();
    let mut writer = quick_protobuf::Writer::new(&mut final_out);
    form.write_message(&mut writer)?;

    Ok(final_out)
}

pub async fn check_and_mark_participant_accepted(
    pool: &Pool,
    form_id: u64,
    participant: &str,
) -> anyhow::Result<bool> {
    let mut client = pool.get().await?;
    let tx = client.transaction().await?;

    let row = tx.query_opt("SELECT accepted FROM form_allowed_participants WHERE form_id = $1 AND participant = $2 FOR UPDATE", &[&(form_id as i64), &participant]).await?;
    if let Some(r) = row {
        let accepted: bool = r.get(0);
        if accepted {
            return Ok(false); // already accepted
        }

        tx.execute("UPDATE form_allowed_participants SET accepted = true WHERE form_id = $1 AND participant = $2", &[&(form_id as i64), &participant]).await?;
        tx.commit().await?;
        return Ok(true);
    }

    Ok(false)
}

pub async fn submit_form(pool: &Pool, submission: FormSubmission<'_>) -> anyhow::Result<()> {
    let client = pool.get().await?;

    let mut out = Vec::new();
    let mut writer = quick_protobuf::Writer::new(&mut out);
    submission.write_message(&mut writer)?;

    client
        .execute(
            "INSERT INTO form_submissions (form_id, data) VALUES ($1, $2)",
            &[
                &(submission.form_id as i64),
                &out,
            ],
        )
        .await?;

    Ok(())
}

pub async fn create_otp(pool: &Pool, email: &str, form_id: Option<u64>) -> anyhow::Result<String> {
    let client = pool.get().await?;

    let code = generate_otp();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as f64;
    let expires_at = now + 300.0;
    let form_id_i64 = form_id.map(|id| id as i64);

    client
        .execute(
            "INSERT INTO otp_codes (email, code, form_id, expires_at) VALUES ($1, $2, $3, to_timestamp($4))",
            &[&email, &code, &form_id_i64, &expires_at],
        )
        .await?;

    Ok(code)
}

pub async fn verify_otp(pool: &Pool, email: &str, code: &str, form_id: Option<u64>) -> anyhow::Result<bool> {
    let client = pool.get().await?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as f64;

    let form_id_i64 = form_id.map(|id| id as i64);

    let row = if let Some(fid) = form_id_i64 {
        client
            .query_opt(
                "SELECT id FROM otp_codes WHERE email = $1 AND code = $2 AND form_id = $3 AND used = false AND expires_at > to_timestamp($4)",
                &[&email, &code, &fid, &now],
            )
            .await?
    } else {
        client
            .query_opt(
                "SELECT id FROM otp_codes WHERE email = $1 AND code = $2 AND form_id IS NULL AND used = false AND expires_at > to_timestamp($3)",
                &[&email, &code, &now],
            )
            .await?
    };

    if let Some(row) = row {
        let id: i64 = row.get(0);
        client
            .execute("UPDATE otp_codes SET used = true WHERE id = $1", &[&id])
            .await?;
        return Ok(true);
    }

    Ok(false)
}


pub async fn is_participant_allowed(
    pool: &Pool,
    form_id: u64,
    participant: &str,
) -> anyhow::Result<bool> {
    let client = pool.get().await?;

    let row = client
        .query_opt(
            "SELECT 1 FROM form_allowed_participants WHERE form_id = $1 AND participant = $2",
            &[&(form_id as i64), &participant],
        )
        .await?;

    Ok(row.is_some())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EmailClaims {
    pub sub: String, // email
    pub exp: usize,
    pub iat: usize,
    pub form_id: Option<u64>,
}

pub async fn get_jwt_secret(pool: &Pool) -> anyhow::Result<Vec<u8>> {
    let client = pool.get().await?;
    let row = client
        .query_opt(
            "SELECT key_data, created_at FROM secrets ORDER BY created_at DESC LIMIT 1",
            &[],
        )
        .await?;

    if let Some(row) = row {
        let key_data: Vec<u8> = row.get(0);
        let created_at: SystemTime = row.get(1);
        let now = SystemTime::now();
        
        // Rotate every 24 hours for security (can be adjusted)
        if now.duration_since(created_at).unwrap_or_default().as_secs() > 3600 * 24 {
            return rotate_jwt_secret(pool).await;
        }
        
        Ok(key_data)
    } else {
        rotate_jwt_secret(pool).await
    }
}

pub async fn rotate_jwt_secret(pool: &Pool) -> anyhow::Result<Vec<u8>> {
    let client = pool.get().await?;
    let mut key = vec![0u8; 32];
    rand::Rng::fill(&mut rand::thread_rng(), &mut key[..]);
    client
        .execute("INSERT INTO secrets (key_data) VALUES ($1)", &[&key])
        .await?;
    Ok(key)
}

pub async fn generate_email_jwt(pool: &Pool, email: &str, form_id: Option<u64>) -> anyhow::Result<String> {
    let secret = get_jwt_secret(pool).await?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize;
    
    let claims = EmailClaims {
        sub: email.to_string(),
        exp: now + 3600 * 24 * 7, // 7 days
        iat: now,
        form_id,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(&secret),
    )?;

    Ok(token)
}

pub async fn verify_email_jwt(pool: &Pool, token: &str) -> anyhow::Result<(String, Option<u64>)> {
    let client = pool.get().await?;
    let rows = client
        .query("SELECT key_data FROM secrets ORDER BY created_at DESC", &[])
        .await?;

    for row in rows {
        let secret: Vec<u8> = row.get(0);
        let validation = Validation::new(Algorithm::HS256);
        if let Ok(token_data) = decode::<EmailClaims>(
            token,
            &DecodingKey::from_secret(&secret),
            &validation,
        ) {
            return Ok((token_data.claims.sub, token_data.claims.form_id));
        }
    }

    Err(anyhow::anyhow!("Invalid token"))
}
