use std::time::{Duration, SystemTime, UNIX_EPOCH};

lazy_static::lazy_static! {
    pub static ref HTTP_CLIENT: reqwest::Client = reqwest::Client::new();
    pub static ref EMULATOR_MODE: bool = std::env::var("EMULATOR_MODE").map(|s| s == "true").unwrap_or(false);
}

const BEARER_WORD: &str = "Bearer ";

pub fn get_datetime_from_millis(milliseconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_millis(milliseconds)
}

pub fn get_system_time_from_secs(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds)
}

pub fn current_timestamp_duration_since_epoch() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time Went Backwards 🚨🚨🚨 !!!")
}

pub fn get_current_timestamp_in_millis() -> u64 {
    current_timestamp_duration_since_epoch().as_millis() as u64
}

pub fn get_current_timestamp_in_secs() -> u64 {
    current_timestamp_duration_since_epoch().as_secs()
}

pub fn get_current_timestamp_in_microsecs() -> u128 {
    current_timestamp_duration_since_epoch().as_micros()
}

pub fn remove_bearer_word<'a>(s: &'a str) -> Option<&'a str> {
    if s.starts_with(BEARER_WORD) {
        Some(&s[BEARER_WORD.len()..])
    } else {
        None
    }
}

const CHARACTERS: &[u8] =
    b"0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\\^_`abcdefghijklmnopqrstuvwxyz{|}~";
// const CHARACTERS: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz";

pub fn number_to_string(mut n: u64) -> String {
    if n == 0 {
        String::new()
    } else {
        let mut cs = Vec::<u8>::with_capacity(12);
        while n > 0 {
            let idx = ((n - 1) as usize) % CHARACTERS.len();
            let c = CHARACTERS[idx];
            cs.push(c);

            n = (n - 1) / CHARACTERS.len() as u64;
        }

        cs.reverse();
        unsafe { String::from_utf8_unchecked(cs) }
    }
}

pub fn number_to_string_write(mut n: u64, s: &mut String) -> usize {
    if n == 0 {
        0
    } else {
        unsafe {
            let mut cs = [0u8; 12];
            let mut cis = 0;
            while n > 0 {
                let idx = ((n - 1) as usize) % CHARACTERS.len();
                let c = CHARACTERS[idx];
                cs[cis] = c;
                *cs.get_unchecked_mut(cis) = c;
                cis += 1;

                n = (n - 1) / CHARACTERS.len() as u64;
            }
            let cs_len = cs.len();

            for i in (0..cis).rev() {
                let c = *cs.get_unchecked(i);
                s.push(char::from_u32_unchecked(c as u32));
            }
            cs_len
        }
    }
}

pub fn string_to_number(s: &str) -> Option<u64> {
    if s.len() > 11 {
        return None;
    }
    let mut n: u64 = 0;

    for (idx, c) in s.as_bytes().iter().rev().enumerate() {
        let pow = CHARACTERS.len().pow(idx as u32);

        let (c_idx, _) = CHARACTERS.iter().enumerate().find(|(_idx, x)| **x == *c)?;

        n = n + (pow * (1 + c_idx)) as u64;
    }

    Some(n)
}


use bytes::{BufMut, Bytes, BytesMut};
use quick_protobuf::{BytesReader, MessageRead, MessageWrite, Writer};

pub fn serialize_proto<T>(message: &T) -> Result<Bytes, quick_protobuf::Error>
where
    T: MessageWrite + Sized,
{
    let mut writer = BytesMut::new().writer();
    message.write_message(&mut Writer::new(&mut writer))?;
    Ok(writer.into_inner().freeze())
}

pub fn deserialize_proto<'a, 'b: 'a, T>(bytes: &'b [u8]) -> Result<T, quick_protobuf::Error>
where
    T: MessageRead<'a> + Sized,
{
    T::from_reader(&mut BytesReader::from_bytes(bytes), &bytes)
}

pub fn sanitize_reply_message(message: &str) -> String {
    let contains_html = message.contains('<') && message.contains('>');
    if contains_html {
        ammonia::clean(message)
    } else {
        let mut escaped = String::new();
        for c in message.chars() {
            match c {
                '<' => escaped.push_str("&lt;"),
                '>' => escaped.push_str("&gt;"),
                '&' => escaped.push_str("&amp;"),
                '"' => escaped.push_str("&quot;"),
                '\'' => escaped.push_str("&#x27;"),
                '/' => escaped.push_str("&#x2F;"),
                _ => escaped.push(c),
            }
        }
        escaped.replace("\n", "<br />")
    }
}
