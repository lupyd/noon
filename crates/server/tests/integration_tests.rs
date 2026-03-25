use noon_server::pb::forms::{FieldValue, Form, FormSubmission, mod_FieldValue};
use noon_server::start_http_server;
use quick_protobuf::{MessageWrite, Writer};
use reqwest::{Client, StatusCode};
use std::borrow::Cow;
use std::collections::HashMap;
use std::time::Duration;

#[tokio::test]
async fn test_create_and_submit_form_with_no_token_verification() {
    // Set no token verification flag used in emulator mode
    unsafe {
        std::env::set_var("NO_TOKEN_VERIFICATION", "true");
    }

    // Start server on a specific port for testing
    let port = 39215; // use a separate port for tests
    tokio::spawn(async move {
        let _ = start_http_server(port).await;
    });

    // Give the server a moment to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = Client::new();
    let base_url = format!("http://127.0.0.1:{}", port);

    // 1. Create a form
    let mut form = Form::default();
    form.name = "Integration Test Form".into();
    form.description = "Test form description".into();
    form.owner = "testuser".into();
    form.is_anonymous = false;

    let mut form_bytes = Vec::new();
    let mut writer = Writer::new(&mut form_bytes);
    form.write_message(&mut writer)
        .expect("Failed to write form config");

    let create_res = client
        .post(format!("{}/forms/create", base_url))
        .header("Authorization", "Bearer custom_user_token")
        .body(form_bytes)
        .send()
        .await
        .expect("Failed to create form");

    assert_eq!(create_res.status(), StatusCode::OK, "Form creation failed");

    let create_body = create_res.text().await.unwrap();
    // Parse "{"id": <id>}"
    let parsed: serde_json::Value = serde_json::from_str(&create_body).unwrap();
    let form_id = parsed["id"].as_u64().expect("Form ID not returned as u64");

    // 2. Submit to the form
    let mut submission = FormSubmission::default();
    submission.form_id = form_id;

    let mut values = HashMap::new();
    let mut fv = FieldValue::default();
    fv.value = mod_FieldValue::OneOfvalue::string_value("Test Value".into());
    values.insert(Cow::Borrowed("test_field"), fv);
    submission.values = values;

    let mut sub_bytes = Vec::new();
    let mut writer = Writer::new(&mut sub_bytes);
    submission
        .write_message(&mut writer)
        .expect("Failed to write submission");

    let submit_res = client
        .post(format!("{}/forms/{}/submit", base_url, form_id))
        .header("Authorization", "Bearer submitter_token")
        .body(sub_bytes)
        .send()
        .await
        .expect("Failed to submit form");

    // Verify that submission succeeds. NO_TOKEN_VERIFICATION handles the "submitter_token"
    assert_eq!(
        submit_res.status(),
        StatusCode::OK,
        "Form submission failed"
    );
    let submit_body = submit_res.text().await.unwrap();
    assert_eq!(submit_body, "OK");
}
