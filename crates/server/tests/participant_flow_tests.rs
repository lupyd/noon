use noon_server::pb::forms::{
    OtpRequest, OtpVerify, Form, FormSubmission, BlindSubmission
};
use noon_server::start_http_server;
use quick_protobuf::{MessageWrite, Writer};
use reqwest::{Client, StatusCode};
use std::time::Duration;
use std::borrow::Cow;
use noon_core::blind::{create_blinded_message, unblind_signature};
use base64::Engine;

fn serialize_proto<T: MessageWrite>(msg: &T) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut writer = Writer::new(&mut bytes);
    msg.write_message(&mut writer)
        .expect("Failed to serialize protobuf");
    bytes
}

async fn setup_test_server(port: u16) -> String {
    unsafe {
        std::env::set_var("NO_TOKEN_VERIFICATION", "true");
        std::env::set_var(
            "DB_CONN_STR",
            "postgres://postgres:password123@localhost:39222/noondb?sslmode=disable",
        );
        std::env::set_var("EMULATOR_MODE", "true");
        std::env::set_var("SKIP_EMAIL_SENDING", "true");
    }

    tokio::spawn(async move {
        let _ = start_http_server(port).await;
    });

    tokio::time::sleep(Duration::from_millis(500)).await;
    format!("http://127.0.0.1:{}", port)
}

#[tokio::test]
async fn test_form_creation_participants_required() {
    let port = 40001;
    let base_url = setup_test_server(port).await;
    let client = Client::new();

    let mut form = Form::default();
    form.name = "No Participants Form".into();
    form.owner = "creator".into();
    form.allowed_participants = vec![]; // EMPTY

    let res = client
        .post(format!("{}/forms/create", base_url))
        .header("Authorization", "Bearer creator")
        .body(serialize_proto(&form))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body = res.text().await.unwrap();
    assert!(body.contains("allowed_participants and mentioned_emails cannot be empty"));
}

async fn submit_form_blind(
    client: &Client,
    base_url: &str,
    form_id: u64,
    submission: &FormSubmission<'_>,
    auth_prefix: &str,
    auth_token: &str,
) -> StatusCode {
    // 1. Get public key
    let pk_res = client
        .get(format!("{}/forms/{}/public_key", base_url, form_id))
        .send()
        .await
        .expect("Failed to get public key");
    assert_eq!(pk_res.status(), StatusCode::OK);
    let pk_body = pk_res.json::<serde_json::Value>().await.expect("Failed to parse public key");
    
    let n_bytes = base64::prelude::BASE64_STANDARD.decode(pk_body["n"].as_str().unwrap()).unwrap();
    let e_bytes = base64::prelude::BASE64_STANDARD.decode(pk_body["e"].as_str().unwrap()).unwrap();
    
    let n = rsa::BigUint::from_bytes_le(&n_bytes);
    let e = rsa::BigUint::from_bytes_le(&e_bytes);
    let public_key = rsa::RsaPublicKey::new(n, e).expect("Failed to create public key");

    // 2. Prepare payload
    let payload = vec![1, 2, 3, 4];
    let blinded = create_blinded_message(&payload, &public_key);

    // 3. Request blind signature
    let sign_res = client
        .post(format!("{}/forms/{}/blind_sign", base_url, form_id))
        .header("Authorization", format!("{} {}", auth_prefix, auth_token))
        .body(blinded.blinded_message())
        .send()
        .await
        .expect("Failed to request blind sign");

    if sign_res.status() != StatusCode::OK {
        return sign_res.status();
    }

    let blinded_sig = sign_res.bytes().await.unwrap();
    let signature = unblind_signature(&blinded, &blinded_sig, &public_key);

    // 4. Submit
    let submission_bytes = serialize_proto(submission);
    let mut blind_sub = BlindSubmission::default();
    blind_sub.payload = Cow::Owned(payload);
    blind_sub.signature = Cow::Owned(signature);
    blind_sub.submission = Cow::Owned(submission_bytes);

    let submit_res = client
        .post(format!("{}/forms/{}/submit", base_url, form_id))
        .body(serialize_proto(&blind_sub))
        .send()
        .await
        .expect("Failed to submit form");

    submit_res.status()
}

#[tokio::test]
async fn test_complete_flow_creator_to_submitter() {
    let port = 40002;
    let base_url = setup_test_server(port).await;
    let client = Client::new();

    let test_email = format!("test_{}@example.com", uuid::Uuid::new_v4());

    // 1. Creator creates form with specific participants (username and email)
    let mut form = Form::default();
    form.name = "Flow Test Form".into();
    form.owner = "creator".into();
    form.allowed_participants = vec!["allowed_user".into()];
    form.mentioned_emails = vec![test_email.clone().into()];

    let create_res = client
        .post(format!("{}/forms/create", base_url))
        .header("Authorization", "Bearer creator")
        .body(serialize_proto(&form))
        .send()
        .await
        .unwrap();

    assert_eq!(create_res.status(), StatusCode::OK);
    let create_body = create_res.text().await.unwrap();
    let form_id = serde_json::from_str::<serde_json::Value>(&create_body).unwrap()["id"]
        .as_u64()
        .unwrap();

    // 2. Non-allowed user tries to GET form
    let get_res = client
        .get(format!("{}/forms/{}", base_url, form_id))
        .header("Authorization", "Bearer intruder")
        .send()
        .await
        .unwrap();
    assert_eq!(get_res.status(), StatusCode::FORBIDDEN);

    // 3. Allowed user (username) GETs form - Success
    let get_res = client
        .get(format!("{}/forms/{}", base_url, form_id))
        .header("Authorization", "Bearer allowed_user")
        .send()
        .await
        .unwrap();
    assert_eq!(get_res.status(), StatusCode::OK);

    // 4. Allowed user (username) Submits form - Success
    let mut submission = FormSubmission::default();
    submission.form_id = form_id;
    let status = submit_form_blind(&client, &base_url, form_id, &submission, "Bearer", "allowed_user").await;
    assert_eq!(status, StatusCode::OK);

    // 5. Allowed user (email) tries to GET form WITHOUT verification - Failure
    let get_res = client
        .get(format!("{}/forms/{}", base_url, form_id))
        .header("Authorization", format!("EmailOnly {}", test_email))
        .send()
        .await
        .unwrap();
    assert_eq!(get_res.status(), StatusCode::UNAUTHORIZED);

    // 6. Verify Email (obtained global token)
    let mut verify_req = OtpRequest::default();
    verify_req.email = test_email.clone().into();
    verify_req.form_id = 0; // Global
    client
        .post(format!("{}/email/request_otp", base_url))
        .body(serialize_proto(&verify_req))
        .send()
        .await
        .unwrap();

    let mut verify_confirm = OtpVerify::default();
    verify_confirm.email = test_email.clone().into();
    verify_confirm.code = "123456".into(); // Predictable due to EMULATOR_MODE
    verify_confirm.form_id = 0; // Global
    let verify_res = client
        .post(format!("{}/email/verify_otp", base_url))
        .body(serialize_proto(&verify_confirm))
        .send()
        .await
        .unwrap();
    assert_eq!(verify_res.status(), StatusCode::OK);
    let _global_token = verify_res.text().await.unwrap();

    // 6.5 Request OTP for specific form (now mandatory)
    let mut otp_req = OtpRequest::default();
    otp_req.email = test_email.clone().into();
    otp_req.form_id = form_id;
    let otp_res = client
        .post(format!("{}/email/request_otp", base_url))
        .body(serialize_proto(&otp_req))
        .send()
        .await
        .unwrap();
    assert_eq!(otp_res.status(), StatusCode::OK);

    // 6.6 Verify OTP to get form-specific token
    let mut otp_verify = OtpVerify::default();
    otp_verify.email = test_email.clone().into();
    otp_verify.code = "123456".into(); // Predictable due to EMULATOR_MODE
    otp_verify.form_id = form_id;
    let verify_otp_res = client
        .post(format!("{}/email/verify_otp", base_url))
        .body(serialize_proto(&otp_verify))
        .send()
        .await
        .unwrap();
    assert_eq!(verify_otp_res.status(), StatusCode::OK);
    let form_token = verify_otp_res.text().await.unwrap();

    // 7. Allowed user (email) GETs form AFTER per-form OTP - Success
    let get_res = client
        .get(format!("{}/forms/{}", base_url, form_id))
        .header("Authorization", format!("EmailOnly {}", form_token))
        .send()
        .await
        .unwrap();
    assert_eq!(get_res.status(), StatusCode::OK);

    // 8. Allowed user (email) Submits form AFTER per-form OTP - Success
    let mut submission = FormSubmission::default();
    submission.form_id = form_id;
    let status = submit_form_blind(&client, &base_url, form_id, &submission, "EmailOnly", &form_token).await;
    assert_eq!(status, StatusCode::OK);
}
