use noon_server::pb::forms::{FieldType, FieldValue, Form, FormSubmission, mod_FieldValue, mod_Form};
use noon_server::start_http_server;
use quick_protobuf::{MessageWrite, Writer};
use reqwest::{Client, StatusCode};
use std::borrow::Cow;
use std::collections::HashMap;
use std::time::Duration;

fn serialize_proto<T: MessageWrite>(msg: &T) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut writer = Writer::new(&mut bytes);
    msg.write_message(&mut writer).expect("Failed to serialize protobuf");
    bytes
}

async fn setup_test_server(port: u16) -> String {
    unsafe {
        std::env::remove_var("NO_TOKEN_VERIFICATION");
        std::env::remove_var("DB_CONN_STR");
        std::env::remove_var("EMULATOR_MODE");
        std::env::set_var("NO_TOKEN_VERIFICATION", "true");
        std::env::set_var("DB_CONN_STR", "postgres://postgres:password123@localhost:39222/noondb?sslmode=disable");
        std::env::set_var("EMULATOR_MODE", "true");
    }

    tokio::spawn(async move {
        let _ = start_http_server(port).await;
    });

    tokio::time::sleep(Duration::from_millis(500)).await;
    format!("http://127.0.0.1:{}", port)
}

#[tokio::test]
async fn test_create_form() {
    let port = 39216;
    let base_url = setup_test_server(port).await;
    let client = Client::new();

    let mut form = Form::default();
    form.name = "Test Form".into();
    form.description = "A test form".into();
    form.owner = "testuser".into();
    form.is_anonymous = false;

    let res = client
        .post(format!("{}/forms/create", base_url))
        .header("Authorization", "Bearer testuser")
        .body(serialize_proto(&form))
        .send()
        .await
        .expect("Failed to create form");

    assert_eq!(res.status(), StatusCode::OK);
    let body = res.text().await.unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(parsed["id"].as_u64().is_some());
}

#[tokio::test]
async fn test_get_form() {
    let port = 39217;
    let base_url = setup_test_server(port).await;
    let client = Client::new();

    let mut form = Form::default();
    form.name = "Get Test Form".into();
    form.description = "Form to test retrieval".into();
    form.owner = "testuser".into();
    form.is_anonymous = false;

    let create_res = client
        .post(format!("{}/forms/create", base_url))
        .header("Authorization", "Bearer testuser")
        .body(serialize_proto(&form))
        .send()
        .await
        .expect("Failed to create form");

    let create_body = create_res.text().await.unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&create_body).unwrap();
    let form_id = parsed["id"].as_u64().unwrap();

    let get_res = client
        .get(format!("{}/forms/{}", base_url, form_id))
        .send()
        .await
        .expect("Failed to get form");

    assert_eq!(get_res.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_get_form_not_found() {
    let port = 39218;
    let base_url = setup_test_server(port).await;
    let client = Client::new();

    let res = client
        .get(format!("{}/forms/{}", base_url, 999999))
        .send()
        .await
        .expect("Failed to get form");

    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_submit_form() {
    let port = 39219;
    let base_url = setup_test_server(port).await;
    let client = Client::new();

    let mut form = Form::default();
    form.name = "Submit Test Form".into();
    form.description = "Form to test submission".into();
    form.owner = "owner".into();
    form.is_anonymous = false;

    let create_res = client
        .post(format!("{}/forms/create", base_url))
        .header("Authorization", "Bearer owner")
        .body(serialize_proto(&form))
        .send()
        .await
        .expect("Failed to create form");

    let create_body = create_res.text().await.unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&create_body).unwrap();
    let form_id = parsed["id"].as_u64().unwrap();

    let mut submission = FormSubmission::default();
    submission.form_id = form_id;
    let mut values = HashMap::new();
    let mut fv = FieldValue::default();
    fv.value = mod_FieldValue::OneOfvalue::string_value("Test Answer".into());
    values.insert(Cow::Borrowed("question_1"), fv);
    submission.values = values;

    let submit_res = client
        .post(format!("{}/forms/{}/submit", base_url, form_id))
        .header("Authorization", "Bearer submitter")
        .body(serialize_proto(&submission))
        .send()
        .await
        .expect("Failed to submit form");

    assert_eq!(submit_res.status(), StatusCode::OK);
    assert_eq!(submit_res.text().await.unwrap(), "OK");
}

#[tokio::test]
async fn test_submit_form_unauthorized() {
    let port = 39220;
    let base_url = setup_test_server(port).await;
    let client = Client::new();

    let mut form = Form::default();
    form.name = "Unauthorized Test Form".into();
    form.description = "Form to test unauthorized submission".into();
    form.owner = "owner".into();
    form.is_anonymous = false;

    let create_res = client
        .post(format!("{}/forms/create", base_url))
        .header("Authorization", "Bearer owner")
        .body(serialize_proto(&form))
        .send()
        .await
        .expect("Failed to create form");

    let create_body = create_res.text().await.unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&create_body).unwrap();
    let form_id = parsed["id"].as_u64().unwrap();

    let mut submission = FormSubmission::default();
    submission.form_id = form_id;

    let submit_res = client
        .post(format!("{}/forms/{}/submit", base_url, form_id))
        .body(serialize_proto(&submission))
        .send()
        .await
        .expect("Failed to submit form");

    assert_eq!(submit_res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_submit_to_anonymous_form_fails() {
    let port = 39221;
    let base_url = setup_test_server(port).await;
    let client = Client::new();

    let mut form = Form::default();
    form.name = "Anonymous Form".into();
    form.description = "This form requires blind signatures".into();
    form.owner = "owner".into();
    form.is_anonymous = true;

    let create_res = client
        .post(format!("{}/forms/create", base_url))
        .header("Authorization", "Bearer owner")
        .body(serialize_proto(&form))
        .send()
        .await
        .expect("Failed to create form");

    let create_body = create_res.text().await.unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&create_body).unwrap();
    let form_id = parsed["id"].as_u64().unwrap();

    let mut submission = FormSubmission::default();
    submission.form_id = form_id;

    let submit_res = client
        .post(format!("{}/forms/{}/submit", base_url, form_id))
        .header("Authorization", "Bearer submitter")
        .body(serialize_proto(&submission))
        .send()
        .await
        .expect("Failed to submit form");

    assert_eq!(submit_res.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_get_public_key() {
    let port = 39223;
    let base_url = setup_test_server(port).await;
    let client = Client::new();

    let mut form = Form::default();
    form.name = "Public Key Test Form".into();
    form.description = "Form to test public key retrieval".into();
    form.owner = "testuser".into();
    form.is_anonymous = true;

    let create_res = client
        .post(format!("{}/forms/create", base_url))
        .header("Authorization", "Bearer testuser")
        .body(serialize_proto(&form))
        .send()
        .await
        .expect("Failed to create form");

    let create_body = create_res.text().await.unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&create_body).unwrap();
    let form_id = parsed["id"].as_u64().unwrap();

    let pk_res = client
        .get(format!("{}/forms/{}/public_key", base_url, form_id))
        .send()
        .await
        .expect("Failed to get public key");

    assert_eq!(pk_res.status(), StatusCode::OK);
    let body = pk_res.text().await.unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(parsed.get("n").is_some());
    assert!(parsed.get("e").is_some());
}

#[tokio::test]
async fn test_create_and_submit_form_with_no_token_verification() {
    let port = 39224;
    let base_url = setup_test_server(port).await;
    let client = Client::new();

    let mut form = Form::default();
    form.name = "Integration Test Form".into();
    form.description = "Test form description".into();
    form.owner = "testuser".into();
    form.is_anonymous = false;

    let create_res = client
        .post(format!("{}/forms/create", base_url))
        .header("Authorization", "Bearer custom_user_token")
        .body(serialize_proto(&form))
        .send()
        .await
        .expect("Failed to create form");

    assert_eq!(create_res.status(), StatusCode::OK, "Form creation failed");

    let create_body = create_res.text().await.unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&create_body).unwrap();
    let form_id = parsed["id"].as_u64().expect("Form ID not returned as u64");

    let mut submission = FormSubmission::default();
    submission.form_id = form_id;

    let mut values = HashMap::new();
    let mut fv = FieldValue::default();
    fv.value = mod_FieldValue::OneOfvalue::string_value("Test Value".into());
    values.insert(Cow::Borrowed("test_field"), fv);
    submission.values = values;

    let submit_res = client
        .post(format!("{}/forms/{}/submit", base_url, form_id))
        .header("Authorization", "Bearer submitter_token")
        .body(serialize_proto(&submission))
        .send()
        .await
        .expect("Failed to submit form");

    assert_eq!(
        submit_res.status(),
        StatusCode::OK,
        "Form submission failed"
    );
    let submit_body = submit_res.text().await.unwrap();
    assert_eq!(submit_body, "OK");
}

#[tokio::test]
async fn test_create_form_with_fields() {
    let port = 39225;
    let base_url = setup_test_server(port).await;
    let client = Client::new();

    let mut form = Form::default();
    form.name = "Form With Fields".into();
    form.description = "Form containing field definitions".into();
    form.owner = "testuser".into();
    form.is_anonymous = false;

    let mut field = mod_Form::Field::default();
    field.name = "email".into();
    field.label = "Email Address".into();
    field.type_pb = FieldType::TEXT;
    field.required = true;
    field.placeholder = "Enter your email".into();
    form.fields.push(field);

    let mut field2 = mod_Form::Field::default();
    field2.name = "age".into();
    field2.label = "Age".into();
    field2.type_pb = FieldType::NUMBER;
    field2.required = false;
    form.fields.push(field2);

    let create_res = client
        .post(format!("{}/forms/create", base_url))
        .header("Authorization", "Bearer testuser")
        .body(serialize_proto(&form))
        .send()
        .await
        .expect("Failed to create form");

    assert_eq!(create_res.status(), StatusCode::OK);

    let create_body = create_res.text().await.unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&create_body).unwrap();
    let form_id = parsed["id"].as_u64().unwrap();

    let get_res = client
        .get(format!("{}/forms/{}", base_url, form_id))
        .send()
        .await
        .expect("Failed to get form");

    assert_eq!(get_res.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_create_form_with_otp_verification() {
    let port = 39226;
    let base_url = setup_test_server(port).await;
    let client = Client::new();

    let mut form = Form::default();
    form.name = "OTP Test Form".into();
    form.description = "Form with OTP verification".into();
    form.owner = "testuser".into();
    form.is_anonymous = false;
    form.requires_otp_verification = true;
    form.mentioned_emails.push("test@example.com".into());

    let res = client
        .post(format!("{}/forms/create", base_url))
        .header("Authorization", "Bearer testuser")
        .body(serialize_proto(&form))
        .send()
        .await
        .expect("Failed to create form");

    assert_eq!(res.status(), StatusCode::OK);
    let body = res.text().await.unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
    let form_id = parsed["id"].as_u64().unwrap();

    use noon_server::pb::forms::OtpRequest;
    let mut otp_req = OtpRequest::default();
    otp_req.email = "test@example.com".into();
    otp_req.form_id = form_id;

    let otp_res = client
        .post(format!("{}/forms/{}/request_otp", base_url, form_id))
        .body(serialize_proto(&otp_req))
        .send()
        .await
        .expect("Failed to request OTP");

    let otp_status = otp_res.status();
    if otp_status != StatusCode::OK {
        let body = otp_res.text().await.unwrap();
        eprintln!("OTP request failed: {} - {}", otp_status, body);
    }
    assert_eq!(otp_status, StatusCode::OK);

    use noon_server::pb::forms::OtpVerify;
    let mut otp_verify = OtpVerify::default();
    otp_verify.email = "test@example.com".into();
    otp_verify.code = "123456".into();
    otp_verify.form_id = form_id;

    let verify_res = client
        .post(format!("{}/forms/{}/verify_otp", base_url, form_id))
        .body(serialize_proto(&otp_verify))
        .send()
        .await
        .expect("Failed to verify OTP");

    assert_eq!(verify_res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_request_otp_for_non_otp_form_fails() {
    let port = 39227;
    let base_url = setup_test_server(port).await;
    let client = Client::new();

    let mut form = Form::default();
    form.name = "Regular Form".into();
    form.description = "Form without OTP".into();
    form.owner = "testuser".into();
    form.is_anonymous = false;
    form.requires_otp_verification = false;

    let create_res = client
        .post(format!("{}/forms/create", base_url))
        .header("Authorization", "Bearer testuser")
        .body(serialize_proto(&form))
        .send()
        .await
        .expect("Failed to create form");

    let create_body = create_res.text().await.unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&create_body).unwrap();
    let form_id = parsed["id"].as_u64().unwrap();

    use noon_server::pb::forms::OtpRequest;
    let mut otp_req = OtpRequest::default();
    otp_req.email = "test@example.com".into();
    otp_req.form_id = form_id;

    let otp_res = client
        .post(format!("{}/forms/{}/request_otp", base_url, form_id))
        .body(serialize_proto(&otp_req))
        .send()
        .await
        .expect("Failed to request OTP");

    assert_eq!(otp_res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_request_otp_for_unauthorized_email_fails() {
    let port = 39228;
    let base_url = setup_test_server(port).await;
    let client = Client::new();

    let mut form = Form::default();
    form.name = "OTP Form".into();
    form.description = "Form with OTP".into();
    form.owner = "testuser".into();
    form.is_anonymous = false;
    form.requires_otp_verification = true;
    form.mentioned_emails.push("authorized@example.com".into());

    let create_res = client
        .post(format!("{}/forms/create", base_url))
        .header("Authorization", "Bearer testuser")
        .body(serialize_proto(&form))
        .send()
        .await
        .expect("Failed to create form");

    let create_body = create_res.text().await.unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&create_body).unwrap();
    let form_id = parsed["id"].as_u64().unwrap();

    use noon_server::pb::forms::OtpRequest;
    let mut otp_req = OtpRequest::default();
    otp_req.email = "unauthorized@example.com".into();
    otp_req.form_id = form_id;

    let otp_res = client
        .post(format!("{}/forms/{}/request_otp", base_url, form_id))
        .body(serialize_proto(&otp_req))
        .send()
        .await
        .expect("Failed to request OTP");

    assert_eq!(otp_res.status(), StatusCode::FORBIDDEN);
}
