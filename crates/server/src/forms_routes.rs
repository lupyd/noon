use base64::Engine;
use bytes::Bytes;
use http_body_util::Full;
use hyper::{Method, Request, Response, StatusCode, body::Incoming, header};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::task::JoinSet;

use crate::forms_db;
use crate::pb::forms::{BlindSubmission, Form, FormSubmission, FormResults, OtpRequest, OtpVerify, UserForms};
use crate::shared_data::SharedData;
use crate::{
    bad_request_response, build_response, internal_error_response, limit_and_collect,
    not_found_response, ok_response, proto_response, unauthorized_response,
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
                (Method::POST, "send_reply") => return send_reply_route(req, sd, form_id).await,
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
            forms_db::verify_email_jwt(&sd, token, &sd.config.auth_iss, &sd.config.auth_aud).await
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

    if let Some(guest_id) = auth_str.strip_prefix("Guest ") {
        if guest_id.chars().all(|c| c.is_alphanumeric() || c == '-') {
            return Some(format!("guest:{}", guest_id));
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

    let mut form = match crate::utils::deserialize_proto::<Form>(&body_bytes) {
        Ok(f) => f,
        Err(_) => return Ok(bad_request_response()),
    };

    let owner = match get_authorized_participant(&headers, &sd, None).await {
        Some(o) => o,
        None => return Ok(unauthorized_response()),
    };

    let is_open_submission = form.participant_mode == crate::pb::forms::ParticipantMode::ANY_WITH_EMAIL
        || form.participant_mode == crate::pb::forms::ParticipantMode::NO_EMAIL_REQUIRED;

    if form.allowed_participants.is_empty() && !is_open_submission {
        return Ok(build_response(
            StatusCode::BAD_REQUEST,
            "allowed_participants cannot be empty (enable open submission or add participants)",
        ));
    }

    let tier = match forms_db::get_user_subscription_tier(&sd.db, &owner).await {
        Ok(t) => t,
        Err(e) => {
            log::error!("get_user_subscription_tier error: {:?}", e);
            return Ok(internal_error_response());
        }
    };

    let max_forms = sd.config.limits.max_forms_for(&tier);
    let form_count = match forms_db::get_owner_form_count(&sd.db, &owner).await {
        Ok(c) => c,
        Err(e) => {
            log::error!("get_owner_form_count error: {:?}", e);
            return Ok(internal_error_response());
        }
    };
    if form_count >= max_forms as u64 {
        return Ok(build_response(
            StatusCode::BAD_REQUEST,
            format!(
                "You have reached the form limit for your {} plan ({} forms). Please upgrade your subscription at lupyd.com to create more forms.",
                tier, max_forms
            ),
        ));
    }

    let max_participants = sd.config.limits.max_participants_for(&tier);
    let mut participant_cap = form.participant_cap;

    if is_open_submission {
        if participant_cap == 0 || participant_cap > max_participants as u64 {
            participant_cap = max_participants as u64;
        }
    } else {
        let total_participants = form.allowed_participants.len();
        if total_participants > max_participants {
            return Ok(build_response(
                StatusCode::BAD_REQUEST,
                format!(
                    "Your {} plan allows a maximum of {} participants per form. You have {}. Please upgrade your subscription at lupyd.com to increase this limit.",
                    tier, max_participants, total_participants
                ),
            ));
        }
        participant_cap = total_participants as u64;
    }

    // Save the participant cap back into the form
    form.participant_cap = participant_cap;

    // Validate submission reply message if present
    if !form.submission_reply_message.is_empty() {
        if form.submission_reply_message.len() > 250 {
            return Ok(build_response(
                StatusCode::BAD_REQUEST,
                "Reply message exceeds 250 characters limit",
            ));
        }
        if tier != "pro" && tier != "team" {
            return Ok(build_response(
                StatusCode::BAD_REQUEST,
                "Custom reply messages require a Team or Pro plan",
            ));
        }
        let sanitized = crate::utils::sanitize_reply_message(&form.submission_reply_message);
        form.submission_reply_message = std::borrow::Cow::Owned(sanitized);
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
            let mut join_set = JoinSet::new();
            let owner_display_str = owner_display.to_string();
            let form_name_str = form.name.to_string();

             if !is_open_submission {
                 for participant in &form.allowed_participants {
                     let p = participant.to_string();
                     if !p.contains("@") {
                         continue;
                     }

                     let sd = sd.clone();
                     let form_name = form_name_str.clone();
                     let owner_display = owner_display_str.clone();
                     let frontend_url = frontend_url.clone();
                     let form_id = id;

                     join_set.spawn(async move {
                         if let Ok(token) = forms_db::generate_email_jwt(
                             &sd,
                             &p,
                             Some(form_id),
                             sd.config.auth_iss.clone(),
                             sd.config.auth_aud.clone(),
                         )
                         .await
                         {
                             let form_link =
                                 format!("{}/forms/{}?token={}", frontend_url, form_id, token);
                             if let Some(emailer) = &sd.emailer {
                                 match emailer
                                     .send_form_invitation(&p, &form_name, &owner_display, &form_link)
                                     .await
                                 {
                                     Ok(_) => {}
                                     Err(e) => {
                                         log::error!("Failed to send invitation email to {}: {}", p, e)
                                     }
                                 }
                             } else if sd.config.skip_email_sending {
                                 println!("--- EMAIL INVITATION ---");
                                 println!("To: {}", p);
                                 println!("Subject: Invitation to fill {}", form_name);
                                 println!(
                                     "Body: {} has invited you to fill out the form: {}
Direct Link: {}",
                                     owner_display, form_name, form_link
                                 );
                                 println!("------------------------");
                             }
                         }
                     });
                 }

                 while join_set.join_next().await.is_some() {}
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

    match forms_db::get_form_bytes(&sd.db, form_id).await {
        Ok(bytes) => {
            let parsed_form = crate::utils::deserialize_proto::<Form>(&bytes).unwrap_or_default();

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

            // Verify authorization based on participant mode
            match parsed_form.participant_mode {
                crate::pb::forms::ParticipantMode::NO_EMAIL_REQUIRED => {
                    // Open to everyone, no authentication check needed to view the form structure
                }
                crate::pb::forms::ParticipantMode::ANY_WITH_EMAIL => {
                    let participant = match get_authorized_participant(headers, &sd, Some(form_id)).await {
                        Some(p) => p,
                        None => return Ok(unauthorized_response()),
                    };
                    if !participant.starts_with("email:") {
                        return Ok(build_response(
                            StatusCode::FORBIDDEN,
                            "Email verification required",
                        ));
                    }
                }
                crate::pb::forms::ParticipantMode::LIST_OF_EMAILS => {
                    let participant = match get_authorized_participant(headers, &sd, Some(form_id)).await {
                        Some(p) => p,
                        None => return Ok(unauthorized_response()),
                    };
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
                }
            }

            Ok(proto_response(bytes, "Form"))
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
    match forms_db::get_or_create_blind_signer(&sd).await {
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
    let parsed_form = crate::utils::deserialize_proto::<Form>(&form_bytes).unwrap_or_default();

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

    // Verify authorization based on participant mode
    match parsed_form.participant_mode {
        crate::pb::forms::ParticipantMode::LIST_OF_EMAILS => {
            if !participant.starts_with("email:") {
                return Ok(build_response(
                    StatusCode::FORBIDDEN,
                    "Email verification required",
                ));
            }
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
        }
        crate::pb::forms::ParticipantMode::ANY_WITH_EMAIL => {
            if !participant.starts_with("email:") {
                return Ok(build_response(
                    StatusCode::FORBIDDEN,
                    "Email verification required",
                ));
            }
        }
        crate::pb::forms::ParticipantMode::NO_EMAIL_REQUIRED => {
            // Guest or email allowed
        }
    }

    let accepted = match parsed_form.participant_mode {
        crate::pb::forms::ParticipantMode::LIST_OF_EMAILS => {
            match forms_db::check_and_mark_participant_accepted(&sd.db, form_id, &participant).await {
                Ok(true) => true,
                Ok(false) => false,
                Err(e) => {
                    log::error!("check_and_mark_participant_accepted error: {:?}", e);
                    return Ok(internal_error_response());
                }
            }
        }
        crate::pb::forms::ParticipantMode::ANY_WITH_EMAIL | crate::pb::forms::ParticipantMode::NO_EMAIL_REQUIRED => {
            match forms_db::add_and_mark_open_participant_accepted(&sd.db, form_id, &participant, parsed_form.participant_cap).await {
                Ok(true) => true,
                Ok(false) => false,
                Err(e) => {
                    log::error!("add_and_mark_open_participant_accepted error: {:?}", e);
                    return Ok(internal_error_response());
                }
            }
        }
    };

    if !accepted {
        return Ok(build_response(
            StatusCode::FORBIDDEN,
            "Already participated, not allowed, or participant cap reached.",
        ));
    }

    let body_bytes = match limit_and_collect(req.into_body(), 1024 * 1024 * 5).await {
        // 5MB
        Ok(b) => b,
        Err(_) => return Ok(bad_request_response()),
    };

    let signer = match forms_db::get_or_create_blind_signer(&sd).await {
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
    let parsed_form = match crate::utils::deserialize_proto::<Form>(&form_bytes) {
        Ok(f) => f,
        Err(_) => return Ok(internal_error_response()),
    };

    let blind_sub = match crate::utils::deserialize_proto::<BlindSubmission>(&body_bytes) {
        Ok(s) => s,
        Err(e) => {
            log::error!("BlindSubmission parse error: {:?}", e);
            return Ok(bad_request_response());
        }
    };

    let signature = blind_sub.signature.to_vec();
    let submission_bytes = blind_sub.submission.to_vec();
    let nonce = blind_sub.nonce.to_vec();

    if signature.is_empty() || submission_bytes.is_empty() || nonce.is_empty() {
        return Ok(bad_request_response());
    }

    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(&submission_bytes);
    hasher.update(&nonce);
    let payload = hasher.finalize().to_vec();

    let signer = match forms_db::get_or_create_blind_signer(&sd).await {
        Ok(s) => s,
        Err(e) => {
            log::error!("get_or_create_blind_signer error: {:?}", e);
            return Ok(internal_error_response());
        }
    };

    if !signer.verify(&payload, &signature) {
        log::warn!("Invalid blind signature for form {}", form_id);
        return Ok(build_response(
            StatusCode::UNAUTHORIZED,
            "Invalid blind signature",
        ));
    }

    // TODO: We MUST check that `payload` wasn't used before locally in cache or DB to prevent double submissions.

    let mut submission = match crate::utils::deserialize_proto::<FormSubmission>(&submission_bytes) {
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
                            return Ok(build_response(
                                StatusCode::BAD_REQUEST,
                                format!("Field '{}' is required", field.label.as_ref()),
                            ));
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

    let submission_count = match forms_db::get_form_submissions_count(&sd.db, form_id).await {
        Ok(c) => c,
        Err(_) => 0,
    };
    if parsed_form.participant_cap > 0 && submission_count >= parsed_form.participant_cap {
        return Ok(build_response(
            StatusCode::FORBIDDEN,
            "Participant cap reached",
        ));
    }

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
    let form = crate::utils::deserialize_proto::<Form>(&form_bytes).unwrap_or_default();

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

    let mut submissions = Vec::new();
    for s_bytes in &subs_bytes {
        let sub = crate::utils::deserialize_proto::<FormSubmission>(s_bytes).unwrap_or_default();
        submissions.push(sub);
    }

    let tier = match forms_db::get_user_subscription_tier(&sd.db, &participant).await {
        Ok(t) => t,
        Err(_) => "free".to_string(),
    };

    let submitter_emails_raw = if tier == "team" {
        forms_db::get_form_submitter_emails(&sd.db, form_id).await.unwrap_or_default()
    } else {
        Vec::new()
    };

    let submitter_emails: Vec<std::borrow::Cow<'_, str>> = submitter_emails_raw
        .iter()
        .map(|s| std::borrow::Cow::Borrowed(s.as_str()))
        .collect();

    let form_results = FormResults {
        submissions,
        form: Some(form),
        total_submissions: total_count,
        submitter_emails,
    };

    let out = match crate::utils::serialize_proto(&form_results) {
        Ok(o) => o,
        Err(_) => return Ok(internal_error_response()),
    };

    Ok(proto_response(out, "FormResults"))
}

async fn list_my_forms_route(
    req: Request<Incoming>,
    sd: Arc<SharedData>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let participant = match get_authorized_participant(req.headers(), &sd, None).await {
        Some(p) => p,
        None => return Ok(unauthorized_response()),
    };

    let query = req.uri().query().unwrap_or("");
    let mut page = 1;
    let mut limit = 10;

    for part in query.split('&') {
        let mut kv = part.splitn(2, '=');
        let k = kv.next().unwrap_or("");
        let v = kv.next().unwrap_or("");
        if k == "page" {
            page = v.parse().unwrap_or(1);
        } else if k == "limit" {
            limit = v.parse().unwrap_or(10);
        }
    }

    let offset = (page - 1) * limit;

    let total_forms_count = match forms_db::get_owner_form_count(&sd.db, &participant).await {
        Ok(c) => c,
        Err(e) => {
            log::error!("get_owner_form_count error: {:?}", e);
            return Ok(internal_error_response());
        }
    };

    let total_subs_count = match forms_db::get_owner_total_submissions(&sd.db, &participant).await {
        Ok(c) => c,
        Err(e) => {
            log::error!("get_owner_total_submissions error: {:?}", e);
            return Ok(internal_error_response());
        }
    };

    match forms_db::get_forms_by_owner(&sd.db, &participant, limit as i64, offset as i64).await {
        Ok(forms_bytes) => {
            let forms: Vec<Form> = forms_bytes
                .iter()
                .map(|b| crate::utils::deserialize_proto::<Form>(b).unwrap_or_default())
                .collect();

            let user_forms = UserForms {
                forms,
                total_forms: total_forms_count,
                total_submissions: total_subs_count,
            };

            let out = match crate::utils::serialize_proto(&user_forms) {
                Ok(o) => o,
                Err(_) => return Ok(internal_error_response()),
            };

            Ok(proto_response(out, "UserForms"))
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

    let otp_request = match crate::utils::deserialize_proto::<OtpRequest>(&body_bytes) {
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

    let otp_verify = match crate::utils::deserialize_proto::<OtpVerify>(&body_bytes) {
        Ok(o) => o,
        Err(_) => return Ok(bad_request_response()),
    };

    let form_id = if otp_verify.form_id == 0 {
        None
    } else {
        Some(otp_verify.form_id)
    };

    log::info!(
        "verify_otp_route: email: {}, form_id: {}, code: {}",
        otp_verify.email,
        otp_verify.form_id,
        otp_verify.code,
    );
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
        let parsed_form = crate::utils::deserialize_proto::<Form>(&form_bytes).unwrap_or_default();

        let email_prefixed = format!("email:{}", email);
        if parsed_form.participant_mode == crate::pb::forms::ParticipantMode::LIST_OF_EMAILS
            && !parsed_form
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
                if let Err(e) = emailer.send_otp_email(&email, &display_name, &code).await {
                    log::error!("Failed to send OTP email: {}", e);
                    return Ok(internal_error_response());
                }
            } else if sd.config.skip_email_sending {
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
            log::info!("email {} verified", email);
            match forms_db::generate_email_jwt(
                &sd,
                &email,
                form_id,
                sd.config.auth_iss.clone(),
                sd.config.auth_aud.clone(),
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

#[derive(serde::Deserialize)]
struct SendReplyRequest {
    email: String,
}

async fn send_reply_route(
    req: Request<Incoming>,
    sd: Arc<SharedData>,
    form_id: u64,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let body_bytes = match limit_and_collect(req.into_body(), 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => return Ok(bad_request_response()),
    };

    let request_data: SendReplyRequest = match serde_json::from_slice(&body_bytes) {
        Ok(d) => d,
        Err(_) => return Ok(bad_request_response()),
    };

    // 1. Fetch form
    let form_bytes = match forms_db::get_form_bytes(&sd.db, form_id).await {
        Ok(b) => b,
        Err(_) => return Ok(not_found_response()),
    };
    let form = crate::utils::deserialize_proto::<Form>(&form_bytes).unwrap_or_default();

    // 2. Verify form has custom reply message
    if form.submission_reply_message.is_empty() {
        return Ok(build_response(
            StatusCode::BAD_REQUEST,
            "Form does not support reply messages",
        ));
    }

    // 3. Verify form owner's tier is pro or team
    let tier = match forms_db::get_user_subscription_tier(&sd.db, &form.owner).await {
        Ok(t) => t,
        Err(_) => "free".to_string(),
    };
    if tier != "pro" && tier != "team" {
        return Ok(build_response(
            StatusCode::BAD_REQUEST,
            "Form owner is not eligible for reply messages",
        ));
    }

    // 4. Rate-limit via database check
    match forms_db::check_and_log_reply_sent(&sd.db, form_id, &request_data.email).await {
        Ok(true) => {
            Ok(ok_response("OK"))
        }
        Ok(false) => {
            // Already sent
            Ok(build_response(
                StatusCode::TOO_MANY_REQUESTS,
                "Reply email already queued or sent for this form",
            ))
        }
        Err(e) => {
            log::error!("check_and_log_reply_sent error: {:?}", e);
            Ok(internal_error_response())
        }
    }
}
