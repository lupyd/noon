use base64::Engine;
use bytes::Bytes;
use http_body_util::Full;
use hyper::{Method, Request, Response, StatusCode, body::Incoming, header};
use quick_protobuf::MessageRead;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::forms_db;
use crate::pb::forms::{BlindSubmission, Form, FormSubmission, OtpRequest, OtpVerify};
use crate::shared_data::SharedData;
use crate::{
    bad_request_response, build_response, internal_error_response, limit_and_collect,
    not_found_response, ok_response, unauthorized_response,
};
use rsa::traits::PublicKeyParts;

pub async fn handle_request(
    req: Request<Incoming>,
    sd: Arc<SharedData>,
    path: &str,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let method = req.method().clone();

    if method == Method::POST && path == "/forms/create" {
        return create_form_route(req, sd).await;
    }

    if method == Method::GET && path == "/forms" {
        return list_my_forms_route(req, sd).await;
    }

    if method == Method::POST && path == "/email/request_otp" {
        return request_otp_route(req, sd).await;
    }

    if method == Method::POST && path == "/email/verify_otp" {
        return verify_otp_route(req, sd).await;
    }

    if let Some(rest) = path.strip_prefix("/forms/") {
        let parts: Vec<&str> = rest.split('/').collect();
        if parts.is_empty() {
            return Ok(not_found_response());
        }

        let form_id = match parts[0].parse::<u64>() {
            Ok(id) => id,
            Err(_) => return Ok(bad_request_response()),
        };

        if parts.len() == 1 && method == Method::GET {
            return get_form_route(req, sd, form_id).await;
        }

        if parts.len() == 2 {
            match (method, parts[1]) {
                (Method::GET, "public_key") => return get_public_key_route(req, sd, form_id).await,
                (Method::POST, "submit") => return submit_blind_route(req, sd, form_id).await,
                (Method::POST, "blind_sign") => return blind_sign_route(req, sd, form_id).await,
                (Method::GET, "results") => return get_results_route(req, sd, form_id).await,
                _ => return Ok(not_found_response()),
            }
        }
    }

    Ok(not_found_response())
}

async fn get_authorized_participant(
    headers: &header::HeaderMap,
    sd: &Arc<SharedData>,
    expected_form_id: Option<u64>,
) -> Option<String> {
    let auth_header = headers.get(header::AUTHORIZATION)?;
    let auth_str = auth_header.to_str().unwrap_or("");

    // In emulator/test mode, accept Bearer tokens directly as user identities
    if *crate::utils::EMULATOR_MODE {
        if let Some(username) = auth_str.strip_prefix("Bearer ") {
            return Some(format!("user:{}", username));
        }
    }

    if let Some(token) = auth_str.strip_prefix("EmailOnly ") {
        if let Ok((email, form_id)) =
            forms_db::verify_email_jwt(&sd.db, token, &sd.auth_iss, &sd.auth_aud).await
        {
            if let Some(expected) = expected_form_id {
                if let Some(token_form_id) = form_id {
                    if token_form_id != expected {
                        return None; // Token is for another form
                    }
                }
                // If token_form_id is None, it's a global token which is allowed
            } else {
                if form_id.is_some() {
                    return None; // Form-specific token used for global action
                }
            }
            return Some(format!("email:{}", email));
        }
    }

    None
}

async fn create_form_route(
    req: Request<Incoming>,
    sd: Arc<SharedData>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let headers = req.headers().clone();
    let body_bytes = match limit_and_collect(req.into_body(), 1024 * 1024 * 5).await {
        // 5MB max
        Ok(b) => b,
        Err(_) => return Ok(bad_request_response()),
    };

    let mut reader = quick_protobuf::BytesReader::from_bytes(&body_bytes);
    let form = match Form::from_reader(&mut reader, &body_bytes) {
        Ok(f) => f,
        Err(_) => return Ok(bad_request_response()),
    };

    let owner = match get_authorized_participant(&headers, &sd, None).await {
        Some(o) => o,
        None => return Ok(unauthorized_response()),
    };

    // Only user:* can create forms? Or email:* too?
    // Let's allow both for now.

    if form.allowed_participants.is_empty() {
        return Ok(build_response(
            StatusCode::BAD_REQUEST,
            "allowed_participants cannot be empty (anonymous forms require participants list)",
        ));
    }

    let total_participants = form.allowed_participants.len();
    let max = *crate::utils::MAX_PARTICIPANTS;
    if total_participants > max {
        return Ok(build_response(
            StatusCode::BAD_REQUEST,
            format!(
                "Maximum number of participants allowed is {}. You have {}. Please contact contact@lupyd.com to increase your limit.",
                max, total_participants
            ),
        ));
    }

    // Validate email format for mentioned_emails
    let email_regex = regex::Regex::new(
        r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
    ).unwrap();

    let invalid_emails: Vec<&str> = form
        .allowed_participants
        .iter()
        .map(|e| e.as_ref())
        .filter(|e| e.contains('@') && !email_regex.is_match(e))
        .collect();

    if !invalid_emails.is_empty() {
        return Ok(build_response(
            StatusCode::BAD_REQUEST,
            format!(
                "Invalid email{}: {}",
                if invalid_emails.len() > 1 { "s" } else { "" },
                invalid_emails.join(", ")
            ),
        ));
    }

    let mut ids = std::collections::HashSet::new();
    for field in &form.fields {
        if field.id.is_empty() {
            return Ok(build_response(
                StatusCode::BAD_REQUEST,
                format!("Field '{}' is missing an ID", field.name),
            ));
        }
        if !ids.insert(&field.id) {
            return Ok(build_response(
                StatusCode::BAD_REQUEST,
                format!("Duplicate field ID: {}", field.id),
            ));
        }
    }

    match forms_db::create_form(&sd.db, form.clone(), owner.clone()).await {
        Ok(id) => {
            // Send emails to participants
            let frontend_url =
                std::env::var("FRONTEND_URL").unwrap_or("http://localhost:8080".to_string());
            let owner_display = owner
                .strip_prefix("email:")
                .or_else(|| owner.strip_prefix("user:"))
                .unwrap_or(&owner);

            for participant in &form.allowed_participants {
                let p = participant.as_ref();
                if p.contains('@') {
                    if let Ok(token) = forms_db::generate_email_jwt(
                        &sd.db,
                        p,
                        Some(id),
                        sd.auth_iss.clone(),
                        sd.auth_aud.clone(),
                    )
                    .await
                    {
                        let form_link = format!("{}/forms/{}?token={}", frontend_url, id, token);
                        if let Some(emailer) = &sd.emailer {
                            if let Err(e) = emailer.send_form_invitation(
                                p,
                                &form.name,
                                owner_display,
                                &form_link,
                            ) {
                                log::error!("Failed to send invitation email to {}: {}", p, e);
                            }
                        } else if sd.skip_email_sending {
                            println!("--- EMAIL INVITATION ---");
                            println!("To: {}", p);
                            println!("Subject: Invitation to fill {}", form.name);
                            println!(
                                "Body: {} has invited you to fill out the form: {}\nDirect Link: {}",
                                owner_display, form.name, form_link
                            );
                            println!("------------------------");
                        }
                    }
                }
            }

            Ok(build_response(
                StatusCode::OK,
                format!("{{\"id\": {}}}", id),
            ))
        }
        Err(e) => {
            log::error!("create_form db error: {:?}", e);
            Ok(internal_error_response())
        }
    }
}

async fn get_form_route(
    req: Request<Incoming>,
    sd: Arc<SharedData>,
    form_id: u64,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let headers = req.headers();
    let participant = match get_authorized_participant(headers, &sd, Some(form_id)).await {
        Some(p) => p,
        None => return Ok(unauthorized_response()),
    };

    // Check if participant is allowed
    match forms_db::is_participant_allowed(&sd.db, form_id, &participant).await {
        Ok(true) => {}
        Ok(false) => {
            return Ok(build_response(
                StatusCode::FORBIDDEN,
                "You are not allowed to access this form",
            ));
        }
        Err(e) => {
            log::error!("is_participant_allowed error: {:?}", e);
            return Ok(internal_error_response());
        }
    }

    match forms_db::get_form_bytes(&sd.db, form_id).await {
        Ok(bytes) => {
            let mut reader = quick_protobuf::BytesReader::from_bytes(&bytes);
            let parsed_form = Form::from_reader(&mut reader, &bytes).unwrap_or_default();

            if parsed_form.deadline > 0 {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                if now > parsed_form.deadline {
                    return Ok(build_response(
                        StatusCode::FORBIDDEN,
                        "This form has expired",
                    ));
                }
            }
            Ok(ok_response(bytes))
        }
        Err(e) => {
            log::error!("get_form error: {:?}", e);
            Ok(not_found_response())
        }
    }
}

async fn get_public_key_route(
    _req: Request<Incoming>,
    sd: Arc<SharedData>,
    _form_id: u64,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    // A single blind signer key for the whole app
    match forms_db::get_or_create_blind_signer(&sd.db).await {
        Ok(signer) => {
            let n = signer.public_key().n().to_bytes_le();
            let e = signer.public_key().e().to_bytes_le();
            let resp = serde_json::json!({
                "n": base64::prelude::BASE64_STANDARD.encode(&n),
                "e": base64::prelude::BASE64_STANDARD.encode(&e)
            });
            Ok(ok_response(resp.to_string()))
        }
        Err(_) => Ok(internal_error_response()),
    }
}

// Removed submit_form_route as all forms are now anonymous

async fn blind_sign_route(
    req: Request<Incoming>,
    sd: Arc<SharedData>,
    form_id: u64,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let participant = match get_authorized_participant(req.headers(), &sd, Some(form_id)).await {
        Some(p) => p,
        None => return Ok(unauthorized_response()),
    };

    let form_bytes = match forms_db::get_form_bytes(&sd.db, form_id).await {
        Ok(b) => b,
        Err(_) => return Ok(not_found_response()),
    };
    let mut reader = quick_protobuf::BytesReader::from_bytes(&form_bytes);
    let parsed_form = Form::from_reader(&mut reader, &form_bytes).unwrap_or_default();

    if parsed_form.deadline > 0 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now > parsed_form.deadline {
            return Ok(build_response(
                StatusCode::FORBIDDEN,
                "This form has expired",
            ));
        }
    }

    let body_bytes = match limit_and_collect(req.into_body(), 1024 * 1024 * 5).await {
        // 5MB
        Ok(b) => b,
        Err(_) => return Ok(bad_request_response()),
    };

    // Mark user as participated
    match forms_db::check_and_mark_participant_accepted(&sd.db, form_id, &participant).await {
        Ok(true) => {}
        Ok(false) => {
            return Ok(build_response(
                StatusCode::FORBIDDEN,
                "Already participated or not allowed.",
            ));
        }
        Err(e) => {
            log::error!("check_and_mark_participant_accepted error: {:?}", e);
            return Ok(internal_error_response());
        }
    }

    let signer = match forms_db::get_or_create_blind_signer(&sd.db).await {
        Ok(s) => s,
        Err(_) => return Ok(internal_error_response()),
    };

    match signer.blind_sign(&body_bytes) {
        Ok(sig) => Ok(ok_response(sig)),
        Err(_) => Ok(internal_error_response()),
    }
}

async fn submit_blind_route(
    req: Request<Incoming>,
    sd: Arc<SharedData>,
    form_id: u64,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    // Unauthenticated!
    let body_bytes = match limit_and_collect(req.into_body(), 1024 * 1024 * 5).await {
        // 5MB
        Ok(b) => b,
        Err(_) => return Ok(bad_request_response()),
    };

    let form_bytes = match forms_db::get_form_bytes(&sd.db, form_id).await {
        Ok(b) => b,
        Err(_) => return Ok(not_found_response()),
    };
    let mut reader_f = quick_protobuf::BytesReader::from_bytes(&form_bytes);
    let parsed_form = match Form::from_reader(&mut reader_f, &form_bytes) {
        Ok(f) => f,
        Err(_) => return Ok(internal_error_response()),
    };

    let mut reader = quick_protobuf::BytesReader::from_bytes(&body_bytes);
    let blind_sub = match BlindSubmission::from_reader(&mut reader, &body_bytes) {
        Ok(s) => s,
        Err(e) => {
            log::error!("BlindSubmission parse error: {:?}", e);
            return Ok(bad_request_response());
        }
    };

    let payload = blind_sub.payload.to_vec();
    let signature = blind_sub.signature.to_vec();
    let submission_bytes = blind_sub.submission.to_vec();

    if payload.is_empty() || signature.is_empty() || submission_bytes.is_empty() {
        return Ok(bad_request_response());
    }

    let signer = match forms_db::get_or_create_blind_signer(&sd.db).await {
        Ok(s) => s,
        Err(_) => return Ok(internal_error_response()),
    };

    if !signer.verify(&payload, &signature) {
        return Ok(build_response(
            StatusCode::UNAUTHORIZED,
            "Invalid blind signature",
        ));
    }

    // TODO: We MUST check that `payload` wasn't used before locally in cache or DB to prevent double submissions.

    let mut reader = quick_protobuf::BytesReader::from_bytes(&submission_bytes);
    let mut submission = match FormSubmission::from_reader(&mut reader, &submission_bytes) {
        Ok(s) => s,
        Err(_) => return Ok(bad_request_response()),
    };

    // Validate submission values against form fields
    for field in &parsed_form.fields {
        let field_id: &str = &field.id;
        match submission.values.iter().find(|v| v.field_id == field_id) {
            None => {
                if field.required && field.type_pb != crate::pb::forms::FieldType::CHECKBOX {
                    return Ok(build_response(
                        StatusCode::BAD_REQUEST,
                        format!("Field '{}' is required", field.label.as_ref()),
                    ));
                }
            }
            Some(val) => {
                use crate::pb::forms::mod_FieldValue::OneOfvalue as Value;
                use crate::pb::forms::mod_Form::mod_Field::OneOfconfig as Config;

                if field.required {
                    let is_empty = match &val.value {
                        Value::string_value(s) => s.trim().is_empty(),
                        Value::None => true,
                        // For checkboxes, required means it must be true
                        Value::bool_value(b)
                            if field.type_pb == crate::pb::forms::FieldType::CHECKBOX =>
                        {
                            !*b
                        }
                        _ => false,
                    };
                    if is_empty {
                        return Ok(build_response(
                            StatusCode::BAD_REQUEST,
                            format!("Field '{}' is required", field.label.as_ref()),
                        ));
                    }
                }

                match &val.value {
                    Value::string_value(_) => {
                        use crate::pb::forms::FieldType as FT;
                        if !matches!(
                            field.type_pb,
                            FT::TEXT
                                | FT::TEXTAREA
                                | FT::SELECT
                                | FT::RADIO
                                | FT::DATE
                                | FT::TIME
                                | FT::EMAIL
                                | FT::URL
                        ) {
                            return Ok(build_response(
                                StatusCode::BAD_REQUEST,
                                format!("Field '{}' expects a string value", field.label.as_ref()),
                            ));
                        }
                    }
                    Value::double_value(_) => {
                        if field.type_pb != crate::pb::forms::FieldType::NUMBER {
                            return Ok(build_response(
                                StatusCode::BAD_REQUEST,
                                format!("Field '{}' expects a number value", field.label.as_ref()),
                            ));
                        }
                    }
                    Value::bool_value(_) => {
                        if field.type_pb != crate::pb::forms::FieldType::CHECKBOX {
                            return Ok(build_response(
                                StatusCode::BAD_REQUEST,
                                format!("Field '{}' expects a boolean value", field.label.as_ref()),
                            ));
                        }
                    }
                    Value::bitmask_value(_) => {
                        if field.type_pb != crate::pb::forms::FieldType::MULTI_SELECT {
                            return Ok(build_response(
                                StatusCode::BAD_REQUEST,
                                format!("Field '{}' expects a bitmask value", field.label.as_ref()),
                            ));
                        }
                    }
                    Value::integer_value(_) => {
                        // Integer value is currently unused by frontend but allowed for completeness if we add appropriate types
                    }
                    Value::None => {
                        if field.required {
                            return Ok(build_response(StatusCode::BAD_REQUEST, format!("Field '{}' is required", field.label.as_ref())));
                        }
                    }
                }

                match &val.value {
                    Value::string_value(s) => {
                        if let Config::max_length(ml) = field.config {
                            if ml > 0 && s.len() > ml as usize {
                                return Ok(build_response(
                                    StatusCode::BAD_REQUEST,
                                    format!(
                                        "Field '{}' exceeds maximum length of {}",
                                        field.label.as_ref(),
                                        ml
                                    ),
                                ));
                            }
                        }
                        if let Config::pattern(p) = &field.config {
                            if !p.is_empty() {
                                if let Ok(re) = regex::Regex::new(p.as_ref()) {
                                    if !s.is_empty() && !re.is_match(s.as_ref()) {
                                        return Ok(build_response(
                                            StatusCode::BAD_REQUEST,
                                            format!(
                                                "Field '{}' has invalid format",
                                                field.label.as_ref()
                                            ),
                                        ));
                                    }
                                }
                            }
                        }
                    }
                    Value::double_value(d) => {
                        if let Config::number_config(nc) = &field.config {
                            if nc.min != 0.0 || nc.max != 0.0 {
                                if *d < nc.min || *d > nc.max {
                                    return Ok(build_response(
                                        StatusCode::BAD_REQUEST,
                                        format!(
                                            "Field '{}' is out of allowed range ({} - {})",
                                            field.label.as_ref(),
                                            nc.min,
                                            nc.max
                                        ),
                                    ));
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    submission.form_id = form_id;

    match forms_db::submit_form(&sd.db, submission).await {
        Ok(_) => Ok(ok_response("OK")),
        Err(e) => {
            log::error!("submit_form error: {:?}", e);
            Ok(internal_error_response())
        }
    }
}

async fn get_results_route(
    req: Request<Incoming>,
    sd: Arc<SharedData>,
    form_id: u64,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let participant = match get_authorized_participant(req.headers(), &sd, None).await {
        Some(p) => p,
        None => return Ok(unauthorized_response()),
    };

    // Verify ownership
    let form_bytes = match forms_db::get_form_bytes(&sd.db, form_id).await {
        Ok(b) => b,
        Err(_) => return Ok(not_found_response()),
    };
    let mut reader = quick_protobuf::BytesReader::from_bytes(&form_bytes);
    let form = Form::from_reader(&mut reader, &form_bytes).unwrap_or_default();

    if form.owner.as_ref() != participant {
        return Ok(build_response(
            StatusCode::FORBIDDEN,
            "Only form owner can see results",
        ));
    }

    let query = req.uri().query().unwrap_or("");
    let mut limit = 50;
    let mut offset = 0;

    for part in query.split('&') {
        let mut kv = part.splitn(2, '=');
        let k = kv.next().unwrap_or("");
        let v = kv.next().unwrap_or("");
        if k == "limit" {
            limit = v.parse().unwrap_or(50);
        } else if k == "offset" {
            offset = v.parse().unwrap_or(0);
        }
    }

    let subs_bytes = match forms_db::get_form_submissions(&sd.db, form_id, limit, offset).await {
        Ok(s) => s,
        Err(e) => {
            log::error!("get_form_submissions error: {:?}", e);
            return Ok(internal_error_response());
        }
    };

    let total_count = match forms_db::get_form_submissions_count(&sd.db, form_id).await {
        Ok(c) => c,
        Err(_) => 0,
    };

    let mut out = Vec::new();
    let mut writer = quick_protobuf::Writer::new(&mut out);

    for sub_bytes in subs_bytes {
        // FormResults has field 1 as repeated FormSubmission (tag 10)
        writer.write_tag(10).expect("Failed to write tag");
        writer
            .write_bytes(&sub_bytes)
            .expect("Failed to write bytes");
    }

    // Tag 18: Form form (tag 2, length delimited)
    writer.write_tag(18).expect("Failed to write tag");
    writer
        .write_bytes(&form_bytes)
        .expect("Failed to write bytes");

    // Tag 24: uint64 total_submissions (tag 3, varint)
    writer.write_tag(24).expect("Failed to write tag");
    writer
        .write_uint64(total_count)
        .expect("Failed to write uint64");

    Ok(ok_response(out))
}

async fn list_my_forms_route(
    req: Request<Incoming>,
    sd: Arc<SharedData>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let participant = match get_authorized_participant(req.headers(), &sd, None).await {
        Some(p) => p,
        None => return Ok(unauthorized_response()),
    };

    match forms_db::get_forms_by_owner(&sd.db, &participant).await {
        Ok(forms_bytes) => {
            let mut out = Vec::new();
            let mut writer = quick_protobuf::Writer::new(&mut out);

            for form_bytes in forms_bytes {
                // UserForms has field 1 as repeated Form
                // Tag 10
                writer.write_tag(10).expect("Failed to write tag");
                writer
                    .write_bytes(&form_bytes)
                    .expect("Failed to write bytes");
            }

            Ok(ok_response(out))
        }
        Err(e) => {
            log::error!("get_forms_by_owner error: {:?}", e);
            Ok(internal_error_response())
        }
    }
}

async fn request_otp_route(
    req: Request<Incoming>,
    sd: Arc<SharedData>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let body_bytes = match limit_and_collect(req.into_body(), 1024 * 1024 * 5).await {
        Ok(b) => b,
        Err(_) => return Ok(bad_request_response()),
    };

    let mut reader = quick_protobuf::BytesReader::from_bytes(&body_bytes);
    let otp_request = match OtpRequest::from_reader(&mut reader, &body_bytes) {
        Ok(o) => o,
        Err(_) => return Ok(bad_request_response()),
    };

    let form_id = if otp_request.form_id == 0 {
        None
    } else {
        Some(otp_request.form_id)
    };
    common_request_otp(otp_request.email.to_string(), form_id, sd).await
}

async fn verify_otp_route(
    req: Request<Incoming>,
    sd: Arc<SharedData>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let body_bytes = match limit_and_collect(req.into_body(), 1024 * 1024 * 5).await {
        Ok(b) => b,
        Err(_) => return Ok(bad_request_response()),
    };

    let mut reader = quick_protobuf::BytesReader::from_bytes(&body_bytes);
    let otp_verify = match OtpVerify::from_reader(&mut reader, &body_bytes) {
        Ok(o) => o,
        Err(_) => return Ok(bad_request_response()),
    };

    let form_id = if otp_verify.form_id == 0 {
        None
    } else {
        Some(otp_verify.form_id)
    };
    common_verify_otp(
        otp_verify.email.to_string(),
        otp_verify.code.to_string(),
        form_id,
        sd,
    )
    .await
}

async fn common_request_otp(
    email: String,
    form_id: Option<u64>,
    sd: Arc<SharedData>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let mut display_name = "Noon Forms Email Verification".to_string();

    if let Some(fid) = form_id {
        let form_bytes = match forms_db::get_form_bytes(&sd.db, fid).await {
            Ok(b) => b,
            Err(_) => return Ok(not_found_response()),
        };
        let mut reader = quick_protobuf::BytesReader::from_bytes(&form_bytes);
        let parsed_form = Form::from_reader(&mut reader, &form_bytes).unwrap_or_default();

        let email_prefixed = format!("email:{}", email);
        if !parsed_form
            .allowed_participants
            .iter()
            .any(|e| e.as_ref() == email || e.as_ref() == email_prefixed)
        {
            return Ok(build_response(
                StatusCode::FORBIDDEN,
                "Email not authorized for this form",
            ));
        }
        display_name = parsed_form.name.to_string();
    }

    match forms_db::create_otp(&sd.db, &email, form_id).await {
        Ok(code) => {
            log::info!("Created OTP code for {}: {}", email, code);
            if let Some(emailer) = &sd.emailer {
                if let Err(e) = emailer.send_otp_email(&email, &display_name, &code) {
                    log::error!("Failed to send OTP email: {}", e);
                    return Ok(internal_error_response());
                }
            } else if sd.skip_email_sending {
                log::info!(
                    "SKIP_EMAIL_SENDING is true, OTP code for {}: {}",
                    email,
                    code
                );
            } else {
                log::warn!("Emailer not configured, OTP code not sent: {}", code);
            }
            Ok(ok_response("OK"))
        }
        Err(e) => {
            log::error!("create_otp error: {:?}", e);
            Ok(internal_error_response())
        }
    }
}

async fn common_verify_otp(
    email: String,
    code: String,
    form_id: Option<u64>,
    sd: Arc<SharedData>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    match forms_db::verify_otp(&sd.db, &email, &code, form_id).await {
        Ok(true) => {
            match forms_db::generate_email_jwt(
                &sd.db,
                &email,
                form_id,
                sd.auth_iss.clone(),
                sd.auth_aud.clone(),
            )
            .await
            {
                Ok(token) => Ok(ok_response(token)),
                Err(e) => {
                    log::error!("generate_email_jwt error: {:?}", e);
                    Ok(internal_error_response())
                }
            }
        }
        Ok(false) => Ok(build_response(
            StatusCode::UNAUTHORIZED,
            "Invalid or expired OTP",
        )),
        Err(e) => {
            log::error!("verify_otp error: {:?}", e);
            Ok(internal_error_response())
        }
    }
}
