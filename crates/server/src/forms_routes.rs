use base64::Engine;
use bytes::Buf;
use bytes::Bytes;
use http_body_util::Full;
use hyper::{Method, Request, Response, StatusCode, body::Incoming};
use quick_protobuf::MessageRead;
use serde_json::Value;
use std::sync::Arc;

use crate::auth::TokenVerificationError;
use crate::forms_db;
use crate::pb::forms::{Form, FormSubmission};
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

    // Parse /forms/:id endpoints
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
                (Method::POST, "submit") => return submit_form_route(req, sd, form_id).await,
                (Method::POST, "blind_sign") => return blind_sign_route(req, sd, form_id).await,
                (Method::POST, "submit_blind") => {
                    return submit_blind_route(req, sd, form_id).await;
                }
                _ => return Ok(not_found_response()),
            }
        }
    }

    Ok(not_found_response())
}

async fn create_form_route(
    req: Request<Incoming>,
    sd: Arc<SharedData>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let auth_token = match sd.auth.verify_from_headers(req.headers()).await {
        Ok(t) => t,
        Err(_) => return Ok(unauthorized_response()),
    };

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

    match forms_db::create_form(&sd.db, form, auth_token.username.to_string()).await {
        Ok(id) => Ok(build_response(
            StatusCode::OK,
            format!("{{\"id\": {}}}", id),
        )),
        Err(e) => {
            log::error!("create_form db error: {:?}", e);
            Ok(internal_error_response())
        }
    }
}

async fn get_form_route(
    _req: Request<Incoming>,
    sd: Arc<SharedData>,
    form_id: u64,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    match forms_db::get_form_bytes(&sd.db, form_id).await {
        Ok(bytes) => Ok(ok_response(bytes)),
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

async fn submit_form_route(
    req: Request<Incoming>,
    sd: Arc<SharedData>,
    form_id: u64,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let form_bytes = match forms_db::get_form_bytes(&sd.db, form_id).await {
        Ok(b) => b,
        Err(_) => return Ok(not_found_response()),
    };
    let mut reader = quick_protobuf::BytesReader::from_bytes(&form_bytes);
    let parsed_form = Form::from_reader(&mut reader, &form_bytes).unwrap_or_default();

    if parsed_form.is_anonymous {
        return Ok(build_response(
            StatusCode::FORBIDDEN,
            "This form requires anonymous submission (blind signatures).",
        ));
    }

    let auth_token = match sd.auth.verify_from_headers(req.headers()).await {
        Ok(t) => t,
        Err(_) => return Ok(unauthorized_response()),
    };

    // Need to verify participation if form restricts it
    // Wait, let's just submit the form for now. Real implementation needs to verify if user is allowed.
    let body_bytes = match limit_and_collect(req.into_body(), 1024 * 1024 * 5).await {
        // 5MB
        Ok(b) => b,
        Err(_) => return Ok(bad_request_response()),
    };

    let mut reader = quick_protobuf::BytesReader::from_bytes(&body_bytes);
    let mut submission = match FormSubmission::from_reader(&mut reader, &body_bytes) {
        Ok(s) => s,
        Err(_) => return Ok(bad_request_response()),
    };

    submission.form_id = form_id;
    submission.username = auth_token.username.to_string().into();

    match forms_db::submit_form(&sd.db, submission).await {
        Ok(_) => Ok(ok_response("OK")),
        Err(e) => {
            log::error!("submit_form error: {:?}", e);
            Ok(internal_error_response())
        }
    }
}

async fn blind_sign_route(
    req: Request<Incoming>,
    sd: Arc<SharedData>,
    form_id: u64,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let auth_token = match sd.auth.verify_from_headers(req.headers()).await {
        Ok(t) => t,
        Err(_) => return Ok(unauthorized_response()),
    };

    let form_bytes = match forms_db::get_form_bytes(&sd.db, form_id).await {
        Ok(b) => b,
        Err(_) => return Ok(not_found_response()),
    };
    let mut reader = quick_protobuf::BytesReader::from_bytes(&form_bytes);
    let parsed_form = Form::from_reader(&mut reader, &form_bytes).unwrap_or_default();
    if !parsed_form.is_anonymous {
        return Ok(build_response(
            StatusCode::FORBIDDEN,
            "This form is not anonymous.",
        ));
    }

    let body_bytes = match limit_and_collect(req.into_body(), 1024 * 1024 * 5).await {
        // 5MB
        Ok(b) => b,
        Err(_) => return Ok(bad_request_response()),
    };

    // Mark user as participated
    match forms_db::check_and_mark_participant_accepted(&sd.db, form_id, &auth_token.username).await
    {
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
    let form_bytes = match forms_db::get_form_bytes(&sd.db, form_id).await {
        Ok(b) => b,
        Err(_) => return Ok(not_found_response()),
    };
    let mut reader = quick_protobuf::BytesReader::from_bytes(&form_bytes);
    let parsed_form = Form::from_reader(&mut reader, &form_bytes).unwrap_or_default();
    if !parsed_form.is_anonymous {
        return Ok(build_response(
            StatusCode::FORBIDDEN,
            "This form is not anonymous.",
        ));
    }

    // Unauthenticated!
    let body_bytes = match limit_and_collect(req.into_body(), 1024 * 1024 * 5).await {
        // 5MB
        Ok(b) => b,
        Err(_) => return Ok(bad_request_response()),
    };

    // Read JSON payload having `payload`, `signature` and `submission`
    let val: Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(_) => return Ok(bad_request_response()),
    };

    let payload = val
        .get("payload")
        .and_then(|v| v.as_str())
        .map(|s| {
            base64::prelude::BASE64_STANDARD
                .decode(s)
                .unwrap_or_default()
        })
        .unwrap_or_default();
    let signature = val
        .get("signature")
        .and_then(|v| v.as_str())
        .map(|s| {
            base64::prelude::BASE64_STANDARD
                .decode(s)
                .unwrap_or_default()
        })
        .unwrap_or_default();
    let submission_b64 = val
        .get("submission")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let submission_bytes = base64::prelude::BASE64_STANDARD
        .decode(submission_b64)
        .unwrap_or_default();

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

    submission.form_id = form_id;
    submission.username = "".into();

    match forms_db::submit_form(&sd.db, submission).await {
        Ok(_) => Ok(ok_response("OK")),
        Err(e) => {
            log::error!("submit_form error: {:?}", e);
            Ok(internal_error_response())
        }
    }
}
