use rand::Rng;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn generate_otp() -> String {
    if *crate::utils::EMULATOR_MODE {
        return "123456".to_string();
    }
    let mut rng = rand::thread_rng();
    let otp: u32 = rng.gen_range(100000..999999);
    otp.to_string()
}

pub fn get_current_timestamp_in_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
