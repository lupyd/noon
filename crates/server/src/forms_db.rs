use anyhow::Context;
use base64::prelude::*;
use deadpool_postgres::Pool;
use deadpool_postgres::tokio_postgres::types::Json;
use noon_core::blind::BlindSigner;
use quick_protobuf::{MessageRead, MessageWrite};
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey};

use crate::pb::forms::{Form, FormSubmission};

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

    let db_form_json = serde_json::json!({ "protobuf_data": BASE64_STANDARD.encode(&out) });

    let stmt = "INSERT INTO forms (name, description, owner, fields, is_anonymous) VALUES ($1, $2, $3, $4, $5) RETURNING id";
    let row = client
        .query_one(
            stmt,
            &[
                &form.name.to_string(),
                &form.description.to_string(),
                &owner,
                &Json(&db_form_json),
                &form.is_anonymous,
            ],
        )
        .await?;

    let form_id: i64 = row.get(0);
    form.id = form_id as u64;

    for participant in &form.allowed_participants {
        let stmt = "INSERT INTO form_allowed_participants (form_id, participant) VALUES ($1, $2)";
        client
            .execute(stmt, &[&form_id, &participant.to_string()])
            .await?;
    }

    Ok(form_id as u64)
}

pub async fn get_form_bytes(pool: &Pool, form_id: u64) -> anyhow::Result<Vec<u8>> {
    let client = pool.get().await?;
    let row = client.query_one("SELECT name, description, owner, fields, extract(epoch from created_at)::bigint as created_at, is_anonymous FROM forms WHERE id = $1", &[&(form_id as i64)]).await?;

    let name: String = row.get(0);
    let description: String = row.get(1);
    let owner: String = row.get(2);
    let fields_json: Json<serde_json::Value> = row.get(3);
    let created_at: i64 = row.get(4);
    let is_anonymous: bool = row.get(5);

    let bytes = if let Some(data) = fields_json.0.get("protobuf_data") {
        if let Some(s) = data.as_str() {
            BASE64_STANDARD.decode(s)?
        } else {
            vec![]
        }
    } else {
        vec![]
    };

    let mut reader = quick_protobuf::BytesReader::from_bytes(&bytes);
    let parsed_form = Form::from_reader(&mut reader, &bytes).unwrap_or_default();

    let mut form = parsed_form;
    form.id = form_id;
    form.name = name.into();
    form.description = description.into();
    form.owner = owner.into();
    form.created_at = created_at as u64;
    form.is_anonymous = is_anonymous;

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

    let data_json = serde_json::json!({ "protobuf_data": BASE64_STANDARD.encode(&out) });

    client
        .execute(
            "INSERT INTO form_submissions (form_id, data, username) VALUES ($1, $2, $3)",
            &[
                &(submission.form_id as i64),
                &Json(&data_json),
                &submission.username.to_string(),
            ],
        )
        .await?;

    Ok(())
}
