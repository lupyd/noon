use anyhow::Context;
use deadpool_postgres::Pool;
use deadpool_postgres::tokio_postgres::types::Type;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use noon_core::blind::BlindSigner;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::otp::generate_otp;
use crate::pb::forms::{Form, FormSubmission};

use crate::SharedData;

pub async fn get_or_create_blind_signer(sd: &SharedData) -> anyhow::Result<Arc<BlindSigner>> {
    {
        let cache = sd.cache.blind_signer.read().await;
        if let Some(signer) = &*cache {
            return Ok(signer.clone());
        }
    }

    let client = sd.db.get().await?;

    let rows = client
        .query_typed(
            "SELECT rsa_key FROM keys ORDER BY created_at DESC LIMIT 1",
            &[],
        )
        .await?;
    let row = rows.into_iter().next();
    if let Some(row) = row {
        let rsa_key_bytes: Vec<u8> = row.try_get(0)?;
        let private_key = rsa::RsaPrivateKey::from_pkcs8_der(&rsa_key_bytes)
            .context("Failed to parse pkcs8 der from db")?;
        let signer = Arc::new(BlindSigner::new(private_key));
        let mut cache = sd.cache.blind_signer.write().await;
        *cache = Some(signer.clone());
        return Ok(signer);
    }

    log::info!("No existing RSA key found. Generating a new BlindSigner key...");
    let private_key = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng::default(), 1024).unwrap();
    let pkcs8_doc = private_key.to_pkcs8_der().unwrap();
    let pkcs8_bytes = pkcs8_doc.as_bytes();

    client
        .query_typed(
            "INSERT INTO keys (rsa_key) VALUES ($1)",
            &[(&pkcs8_bytes, Type::BYTEA)],
        )
        .await?;

    let signer = Arc::new(BlindSigner::new(private_key));
    let mut cache = sd.cache.blind_signer.write().await;
    *cache = Some(signer.clone());

    Ok(signer)
}

pub async fn create_form(pool: &Pool, mut form: Form<'_>, owner: String) -> anyhow::Result<u64> {
    let client = pool.get().await?;

    let out = crate::utils::serialize_proto(&form)?;

    let allowed_participants: Vec<&str> = form
        .allowed_participants
        .iter()
        .map(|s| s.as_ref())
        .collect();

    let deadline = if form.deadline == 0 {
        None
    } else {
        Some(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(form.deadline))
    };

    let stmt = "INSERT INTO forms (name, description, owner, fields, mentioned_emails, deadline, participant_mode, participant_cap, submission_reply_message) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id";
    let name_str = form.name.to_string();
    let desc_str = form.description.to_string();
    let out_ref = out.as_ref();
    let p_mode = form.participant_mode as i16;
    let p_cap = form.participant_cap as i32;
    let reply_msg = form.submission_reply_message.to_string();
    let rows = client
        .query_typed(
            stmt,
            &[
                (&name_str, Type::VARCHAR),
                (&desc_str, Type::TEXT),
                (&owner, Type::VARCHAR),
                (&out_ref, Type::BYTEA),
                (&allowed_participants, Type::TEXT_ARRAY),
                (&deadline, Type::TIMESTAMPTZ),
                (&p_mode, Type::INT2),
                (&p_cap, Type::INT4),
                (&reply_msg, Type::VARCHAR),
            ],
        )
        .await?;
    let row = rows
        .into_iter()
        .next()
        .context("Failed to get id from insert")?;

    let form_id: i64 = row.try_get(0)?;
    form.id = form_id as u64;

    for participant in &form.allowed_participants {
        let stmt = "INSERT INTO form_allowed_participants (form_id, participant) VALUES ($1, $2) ON CONFLICT DO NOTHING";
        let part_str = participant.as_ref();
        let formatted_participant = if part_str.contains('@') {
            format!("email:{}", part_str)
        } else {
            format!("user:{}", part_str)
        };
        client
            .query_typed(
                stmt,
                &[
                    (&form_id, Type::INT8),
                    (&formatted_participant, Type::VARCHAR),
                ],
            )
            .await?;
    }

    Ok(form_id as u64)
}

pub async fn get_form_bytes(pool: &Pool, form_id: u64) -> anyhow::Result<Vec<u8>> {
    let client = pool.get().await?;
    let form_id_i64 = form_id as i64;
    let rows = client
        .query_typed(
            "SELECT name, description, owner, fields, extract(epoch from created_at)::bigint as created_at, \
             mentioned_emails, extract(epoch from deadline)::bigint as deadline, \
             participant_mode, participant_cap, submission_reply_message, submission_count \
             FROM forms WHERE id = $1",
            &[(&form_id_i64, Type::INT8)],
        )
        .await?;
    let row = rows.into_iter().next().context("Form not found")?;

    let name: String = row.try_get(0)?;
    let description: String = row.try_get(1)?;
    let owner: String = row.try_get(2)?;
    let bytes: Vec<u8> = row.try_get(3)?;
    let created_at: i64 = row.try_get(4)?;
    let mentioned_emails: Vec<String> = row.try_get(5)?;
    let deadline: Option<i64> = row.try_get(6)?;
    let p_mode: i16 = row.try_get(7)?;
    let p_cap: i32 = row.try_get(8)?;
    let reply_msg: String = row.try_get(9)?;
    let sub_count: i32 = row.try_get(10)?;

    let parsed_form = crate::utils::deserialize_proto::<Form>(&bytes).unwrap_or_default();

    let mut form = parsed_form;
    form.id = form_id;
    form.name = name.into();
    form.description = description.into();
    form.owner = owner.into();
    form.created_at = created_at as u64;
    form.allowed_participants = mentioned_emails.into_iter().map(|s| s.into()).collect();
    form.deadline = deadline.unwrap_or(0) as u64;
    form.participant_mode = crate::pb::forms::ParticipantMode::from(p_mode as i32);
    form.participant_cap = p_cap as u64;
    form.submission_reply_message = reply_msg.into();
    form.submission_count = sub_count as u64;

    let form_id_i64 = form_id as i64;
    let rows = client
        .query_typed(
            "SELECT participant FROM form_allowed_participants WHERE form_id = $1",
            &[(&form_id_i64, Type::INT8)],
        )
        .await?;
    let mut allowed_participants = Vec::new();
    for r in rows {
        let p: String = r.try_get(0)?;
        allowed_participants.push(p.into());
    }
    form.allowed_participants = allowed_participants;

    let final_out = crate::utils::serialize_proto(&form)?;

    Ok(final_out.to_vec())
}

pub async fn check_and_mark_participant_accepted(
    pool: &Pool,
    form_id: u64,
    participant: &str,
) -> anyhow::Result<bool> {
    let mut client = pool.get().await?;
    let tx = client.transaction().await?;

    let form_id_i64 = form_id as i64;
    let rows = tx
        .query_typed(
            "SELECT accepted FROM form_allowed_participants WHERE form_id = $1 AND participant = $2 FOR UPDATE",
            &[(&form_id_i64, Type::INT8), (&participant, Type::VARCHAR)],
        )
        .await?;
    let row = rows.into_iter().next();
    if let Some(r) = row {
        let accepted: bool = r.try_get(0)?;
        if accepted {
            return Ok(false); // already accepted
        }

        let form_id_i64 = form_id as i64;
        tx.query_typed(
            "UPDATE form_allowed_participants SET accepted = true WHERE form_id = $1 AND participant = $2",
            &[(&form_id_i64, Type::INT8), (&participant, Type::VARCHAR)],
        )
        .await?;
        tx.commit().await?;
        return Ok(true);
    }

    Ok(false)
}

pub async fn submit_form(pool: &Pool, submission: FormSubmission<'_>) -> anyhow::Result<()> {
    let client = pool.get().await?;

    let out = crate::utils::serialize_proto(&submission)?;

    let form_id_i64 = submission.form_id as i64;
    let out_ref = out.as_ref();
    client
        .query_typed(
            "INSERT INTO form_submissions (form_id, data) VALUES ($1, $2)",
            &[(&form_id_i64, Type::INT8), (&out_ref, Type::BYTEA)],
        )
        .await?;

    Ok(())
}

pub async fn get_form_submissions(
    pool: &Pool,
    form_id: u64,
    limit: i64,
    offset: i64,
) -> anyhow::Result<Vec<Vec<u8>>> {
    let client = pool.get().await?;
    let form_id_i64 = form_id as i64;
    let rows = client
        .query_typed(
            "SELECT data FROM form_submissions WHERE form_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
            &[(&form_id_i64, Type::INT8), (&limit, Type::INT8), (&offset, Type::INT8)],
        )
        .await?;

    let mut results = Vec::new();
    for r in rows {
        results.push(r.try_get(0)?);
    }
    Ok(results)
}

pub async fn get_forms_by_owner(
    pool: &Pool,
    owner: &str,
    limit: i64,
    offset: i64,
) -> anyhow::Result<Vec<Vec<u8>>> {
    let client = pool.get().await?;
    let owner_str = owner.to_string();
    let rows = client
        .query_typed(
            "SELECT id, name, description, extract(epoch from created_at)::bigint as created_at, \
             extract(epoch from deadline)::bigint as deadline, fields, \
             participant_mode, participant_cap, submission_reply_message, submission_count \
             FROM forms WHERE owner = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
            &[
                (&owner_str, Type::VARCHAR),
                (&limit, Type::INT8),
                (&offset, Type::INT8),
            ],
        )
        .await?;

    let mut results = Vec::new();
    for row in rows {
        let id: i64 = row.try_get(0)?;
        let name: String = row.try_get(1)?;
        let description: String = row.try_get(2)?;
        let created_at: i64 = row.try_get(3)?;
        let deadline: Option<i64> = row.try_get(4)?;
        let bytes: Vec<u8> = row.try_get(5)?;
        let p_mode: i16 = row.try_get(6)?;
        let p_cap: i32 = row.try_get(7)?;
        let reply_msg: String = row.try_get(8)?;
        let sub_count: i32 = row.try_get(9)?;

        let mut form = crate::utils::deserialize_proto::<Form>(&bytes).unwrap_or_default();
        form.id = id as u64;
        form.name = name.into();
        form.description = description.into();
        form.created_at = created_at as u64;
        form.deadline = deadline.unwrap_or(0) as u64;
        form.participant_mode = crate::pb::forms::ParticipantMode::from(p_mode as i32);
        form.participant_cap = p_cap as u64;
        form.submission_reply_message = reply_msg.into();
        form.submission_count = sub_count as u64;

        let final_bytes = crate::utils::serialize_proto(&form)?;
        results.push(final_bytes.to_vec());
    }

    Ok(results)
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
        .query_typed(
            "INSERT INTO otp_codes (email, code, form_id, expires_at) VALUES ($1, $2, $3, to_timestamp($4))",
            &[
                (&email, Type::VARCHAR),
                (&code, Type::VARCHAR),
                (&form_id_i64, Type::INT8),
                (&expires_at, Type::FLOAT8),
            ],
        )
        .await?;

    Ok(code)
}

pub async fn verify_otp(
    pool: &Pool,
    email: &str,
    code: &str,
    form_id: Option<u64>,
) -> anyhow::Result<bool> {
    let client = pool.get().await?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as f64;

    let form_id_i64 = form_id.map(|id| id as i64);

    let row = if let Some(fid) = form_id_i64 {
        let rows = client
            .query_typed(
                "SELECT id FROM otp_codes WHERE email = $1 AND code = $2 AND form_id = $3 AND used = false AND expires_at > to_timestamp($4)",
                &[
                    (&email, Type::VARCHAR),
                    (&code, Type::VARCHAR),
                    (&fid, Type::INT8),
                    (&now, Type::FLOAT8),
                ],
            )
            .await?;
        rows.into_iter().next()
    } else {
        let rows = client
            .query_typed(
                "SELECT id FROM otp_codes WHERE email = $1 AND code = $2 AND form_id IS NULL AND used = false AND expires_at > to_timestamp($3)",
                &[
                    (&email, Type::VARCHAR),
                    (&code, Type::VARCHAR),
                    (&now, Type::FLOAT8),
                ],
            )
            .await?;
        rows.into_iter().next()
    };

    if let Some(row) = row {
        let id: i64 = row.try_get(0)?;
        client
            .query_typed(
                "UPDATE otp_codes SET used = true WHERE id = $1",
                &[(&id, Type::INT8)],
            )
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

    let form_id_i64 = form_id as i64;
    let rows = client
        .query_typed(
            "SELECT 1 FROM form_allowed_participants WHERE form_id = $1 AND participant = $2",
            &[(&form_id_i64, Type::INT8), (&participant, Type::VARCHAR)],
        )
        .await?;
    let row = rows.into_iter().next();

    Ok(row.is_some())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EmailClaims {
    pub sub: String, // email
    pub exp: usize,
    pub iat: usize,
    pub iss: String,
    pub aud: String,
    pub form_id: Option<u64>,
}

pub async fn get_jwt_secret(sd: &SharedData) -> anyhow::Result<Vec<u8>> {
    {
        let cache = sd.cache.jwt_secret.read().await;
        if let Some((key, created_at)) = &*cache {
            let now = SystemTime::now();
            if now
                .duration_since(*created_at)
                .unwrap_or_default()
                .as_secs()
                < 3600 * 24
            {
                return Ok(key.clone());
            }
        }
    }

    let client = sd.db.get().await?;
    let rows = client
        .query_typed(
            "SELECT key_data, created_at FROM secrets ORDER BY created_at DESC LIMIT 1",
            &[],
        )
        .await?;
    let row = rows.into_iter().next();

    if let Some(row) = row {
        let key_data: Vec<u8> = row.try_get(0)?;
        let created_at: SystemTime = row.try_get(1)?;
        let now = SystemTime::now();

        // Rotate every 24 hours for security (can be adjusted)
        if now.duration_since(created_at).unwrap_or_default().as_secs() > 3600 * 24 {
            return rotate_jwt_secret(sd).await;
        }

        let mut cache = sd.cache.jwt_secret.write().await;
        *cache = Some((key_data.clone(), created_at));

        Ok(key_data)
    } else {
        rotate_jwt_secret(sd).await
    }
}

pub async fn rotate_jwt_secret(sd: &SharedData) -> anyhow::Result<Vec<u8>> {
    let client = sd.db.get().await?;
    let mut key = vec![0u8; 32];
    rand::Rng::fill(&mut rand::thread_rng(), &mut key[..]);
    client
        .query_typed(
            "INSERT INTO secrets (key_data) VALUES ($1)",
            &[(&key, Type::BYTEA)],
        )
        .await?;

    let now = SystemTime::now();
    let mut cache = sd.cache.jwt_secret.write().await;
    *cache = Some((key.clone(), now));

    // Clear recent secrets cache so it will be reloaded
    let mut recent_cache = sd.cache.jwt_recent_secrets.write().await;
    *recent_cache = None;

    Ok(key)
}

pub async fn generate_email_jwt(
    sd: &SharedData,
    email: &str,
    form_id: Option<u64>,
    iss: String,
    aud: String,
) -> anyhow::Result<String> {
    let secret = get_jwt_secret(sd).await?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize;

    let claims = EmailClaims {
        sub: email.to_string(),
        exp: now + 3600 * 24 * 7, // 7 days
        iat: now,
        iss,
        aud,
        form_id,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(&secret),
    )?;

    Ok(token)
}

pub async fn verify_email_jwt(
    sd: &SharedData,
    token: &str,
    iss: &str,
    aud: &str,
) -> anyhow::Result<(String, Option<u64>)> {
    let secrets = {
        let cache = sd.cache.jwt_recent_secrets.read().await;
        if let Some(s) = &*cache {
            s.clone()
        } else {
            drop(cache);
            let client = sd.db.get().await?;
            let rows = client
                .query_typed(
                    "SELECT key_data FROM secrets ORDER BY created_at DESC LIMIT 3",
                    &[],
                )
                .await?;
            let mut s = Vec::new();
            for r in rows {
                s.push(r.try_get(0)?);
            }
            let mut cache = sd.cache.jwt_recent_secrets.write().await;
            *cache = Some(s.clone());
            s
        }
    };

    for secret in secrets {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[iss]);
        validation.set_audience(&[aud]);

        if let Ok(token_data) =
            decode::<EmailClaims>(token, &DecodingKey::from_secret(&secret), &validation)
        {
            return Ok((token_data.claims.sub, token_data.claims.form_id));
        }
    }

    Err(anyhow::anyhow!("Invalid token"))
}

pub async fn get_form_submissions_count(pool: &Pool, form_id: u64) -> anyhow::Result<u64> {
    let client = pool.get().await?;
    let form_id_i64 = form_id as i64;
    let rows = client
        .query_typed(
            "SELECT COUNT(form_id) FROM form_submissions WHERE form_id = $1",
            &[(&form_id_i64, Type::INT8)],
        )
        .await?;
    let row = rows
        .into_iter()
        .next()
        .context("No row returned from COUNT")?;
    let count: i64 = row.try_get(0)?;
    Ok(count as u64)
}

use crate::subscription_db::SubscriptionStatus;

pub async fn get_user_subscription_tier(pool: &Pool, owner: &str) -> anyhow::Result<String> {
    let client = pool.get().await?;
    let rows = client
        .query_typed(
            "SELECT tier, subscription_status FROM user_subscriptions WHERE owner = $1",
            &[(&owner, Type::VARCHAR)],
        )
        .await?;
    
    if let Some(row) = rows.into_iter().next() {
        let tier: String = row.try_get(0)?;
        let status_val: i16 = row.try_get(1)?;
        let status = SubscriptionStatus::from_i16(status_val);
        
        if status == SubscriptionStatus::Active {
            return Ok(tier);
        }
    }
    
    Ok("free".to_string())
}

pub async fn get_owner_form_count(pool: &Pool, owner: &str) -> anyhow::Result<u64> {
    let client = pool.get().await?;
    let rows = client
        .query_typed(
            "SELECT COUNT(id) FROM forms WHERE owner = $1",
            &[(&owner, Type::VARCHAR)],
        )
        .await?;
    let row = rows
        .into_iter()
        .next()
        .context("No row returned from COUNT")?;
    let count: i64 = row.try_get(0)?;
    Ok(count as u64)
}

pub async fn get_owner_total_submissions(pool: &Pool, owner: &str) -> anyhow::Result<u64> {
    let client = pool.get().await?;
    let rows = client
        .query_typed(
            "SELECT COALESCE(SUM(submission_count), 0)::BIGINT FROM forms WHERE owner = $1",
            &[(&owner, Type::VARCHAR)],
        )
        .await?;
    let row = rows
        .into_iter()
        .next()
        .context("No row returned from SUM")?;
    let count: i64 = row.try_get(0)?;
    Ok(count as u64)
}

pub async fn add_and_mark_open_participant_accepted(
    pool: &Pool,
    form_id: u64,
    participant: &str,
    cap: u64,
) -> anyhow::Result<bool> {
    let mut client = pool.get().await?;
    let tx = client.transaction().await?;

    let form_id_i64 = form_id as i64;
    
    // First, check if participant already exists and is accepted
    let rows = tx
        .query_typed(
            "SELECT accepted FROM form_allowed_participants WHERE form_id = $1 AND participant = $2 FOR UPDATE",
            &[(&form_id_i64, Type::INT8), (&participant, Type::VARCHAR)],
        )
        .await?;
    
    if let Some(row) = rows.into_iter().next() {
        let accepted: bool = row.try_get(0)?;
        if accepted {
            return Ok(false); // Already participated
        }
        
        if cap > 0 {
            let count_rows = tx
                .query_typed(
                    "SELECT COUNT(participant) FROM form_allowed_participants WHERE form_id = $1 AND accepted = true",
                    &[(&form_id_i64, Type::INT8)],
                )
                .await?;
            let active_count: i64 = match count_rows.first() {
                Some(r) => r.try_get(0)?,
                None => 0,
            };
            if active_count >= cap as i64 {
                return Ok(false); // Cap reached
            }
        }

        tx.query_typed(
            "UPDATE form_allowed_participants SET accepted = true WHERE form_id = $1 AND participant = $2",
            &[(&form_id_i64, Type::INT8), (&participant, Type::VARCHAR)],
        )
        .await?;
        tx.commit().await?;
        return Ok(true);
    }

    // Participant does not exist in the table. We check the cap.
    if cap > 0 {
        let count_rows = tx
            .query_typed(
                "SELECT COUNT(participant) FROM form_allowed_participants WHERE form_id = $1 AND accepted = true",
                &[(&form_id_i64, Type::INT8)],
            )
            .await?;
        let active_count: i64 = match count_rows.first() {
            Some(r) => r.try_get(0)?,
            None => 0,
        };
        if active_count >= cap as i64 {
            return Ok(false); // Cap reached
        }
    }

    // Insert as accepted = true immediately
    tx.query_typed(
        "INSERT INTO form_allowed_participants (form_id, participant, accepted) VALUES ($1, $2, true)",
        &[(&form_id_i64, Type::INT8), (&participant, Type::VARCHAR)],
    )
    .await?;
    tx.commit().await?;
    Ok(true)
}

pub async fn check_and_log_reply_sent(
    pool: &Pool,
    form_id: u64,
    email: &str,
) -> anyhow::Result<bool> {
    let client = pool.get().await?;
    let form_id_i64 = form_id as i64;
    let email_str = email.to_string();

    // Try to insert
    let stmt = "INSERT INTO form_reply_log (form_id, email) VALUES ($1, $2) ON CONFLICT DO NOTHING RETURNING 1";
    let rows = client
        .query_typed(stmt, &[(&form_id_i64, Type::INT8), (&email_str, Type::VARCHAR)])
        .await?;
    
    Ok(!rows.is_empty())
}

pub async fn get_form_submitter_emails(pool: &Pool, form_id: u64) -> anyhow::Result<Vec<String>> {
    let client = pool.get().await?;
    let form_id_i64 = form_id as i64;
    let rows = client
        .query_typed(
            "SELECT participant FROM form_allowed_participants WHERE form_id = $1 AND accepted = TRUE",
            &[(&form_id_i64, Type::INT8)],
        )
        .await?;
    let mut emails = Vec::new();
    for r in rows {
        let p: String = r.try_get(0)?;
        if p.contains('@') {
            emails.push(p);
        }
    }
    Ok(emails)
}

pub async fn process_reply_queue(sd: &Arc<crate::SharedData>) -> anyhow::Result<()> {
    let client = sd.db.get().await?;

    // 1. Fetch all pending reply log entries using typed method
    let rows = client
        .query_typed(
            "SELECT form_id, email FROM form_reply_log WHERE sent_at IS NULL",
            &[],
        )
        .await?;

    if rows.is_empty() {
        return Ok(());
    }

    log::info!("Found {} pending reply emails to process.", rows.len());

    // 2. Loop through and process them
    for row in rows {
        let form_id_i64: i64 = row.try_get(0)?;
        let email: String = row.try_get(1)?;
        let form_id = form_id_i64 as u64;

        // Fetch form details
        let form_bytes = match get_form_bytes(&sd.db, form_id).await {
            Ok(b) => b,
            Err(e) => {
                log::error!("Failed to fetch form bytes for form_id={} in queue: {:?}", form_id, e);
                continue;
            }
        };

        let form = match crate::utils::deserialize_proto::<Form>(&form_bytes) {
            Ok(f) => f,
            Err(e) => {
                log::error!("Failed to deserialize form_id={} in queue: {:?}", form_id, e);
                continue;
            }
        };

        // If the form doesn't have a reply message configured, mark it as sent/skipped
        if form.submission_reply_message.is_empty() {
            let _ = client
                .execute_typed(
                    "UPDATE form_reply_log SET sent_at = NOW() WHERE form_id = $1 AND email = $2",
                    &[(&form_id_i64, Type::INT8), (&email, Type::VARCHAR)],
                )
                .await;
            continue;
        }

        // Send email using emailer
        if let Some(emailer) = &sd.emailer {
            match emailer
                .send_submission_reply(&email, &form.name, &form.submission_reply_message)
                .await
            {
                Ok(_) => {
                    log::info!("Successfully sent reply receipt to {} for form '{}'", email, form.name);
                    let _ = client
                        .execute_typed(
                            "UPDATE form_reply_log SET sent_at = NOW() WHERE form_id = $1 AND email = $2",
                            &[(&form_id_i64, Type::INT8), (&email, Type::VARCHAR)],
                        )
                        .await;
                }
                Err(e) => {
                    log::error!("Failed to send reply to {} for form_id={}: {:?}", email, form_id, e);
                }
            }
        } else if sd.config.skip_email_sending {
            // In development, print to console and mark as sent
            println!("--- EMAIL REPLY QUEUE BATCH ---");
            println!("To: {}", email);
            println!("Subject: Thanks for participating in {}", form.name);
            println!("Body: {}", form.submission_reply_message);
            println!("-------------------");
            let _ = client
                .execute_typed(
                    "UPDATE form_reply_log SET sent_at = NOW() WHERE form_id = $1 AND email = $2",
                    &[(&form_id_i64, Type::INT8), (&email, Type::VARCHAR)],
                )
                .await;
        }
    }

    Ok(())
}
