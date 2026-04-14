// Automatically generated rust module for 'forms.proto' file

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(unused_imports)]
#![allow(unknown_lints)]
#![allow(clippy::all)]
#![cfg_attr(rustfmt, rustfmt_skip)]


use std::borrow::Cow;
use std::collections::HashMap;
type KVMap<K, V> = HashMap<K, V>;
use quick_protobuf::{MessageInfo, MessageRead, MessageWrite, BytesReader, Writer, WriterBackend, Result};
use quick_protobuf::sizeofs::*;
use super::*;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum FieldType {
    TEXT = 0,
    TEXTAREA = 1,
    NUMBER = 2,
    SELECT = 3,
    MULTI_SELECT = 4,
    RADIO = 5,
    CHECKBOX = 6,
    DATE = 7,
    TIME = 8,
    EMAIL = 9,
    URL = 10,
}

impl Default for FieldType {
    fn default() -> Self {
        FieldType::TEXT
    }
}

impl From<i32> for FieldType {
    fn from(i: i32) -> Self {
        match i {
            0 => FieldType::TEXT,
            1 => FieldType::TEXTAREA,
            2 => FieldType::NUMBER,
            3 => FieldType::SELECT,
            4 => FieldType::MULTI_SELECT,
            5 => FieldType::RADIO,
            6 => FieldType::CHECKBOX,
            7 => FieldType::DATE,
            8 => FieldType::TIME,
            9 => FieldType::EMAIL,
            10 => FieldType::URL,
            _ => Self::default(),
        }
    }
}

impl<'a> From<&'a str> for FieldType {
    fn from(s: &'a str) -> Self {
        match s {
            "TEXT" => FieldType::TEXT,
            "TEXTAREA" => FieldType::TEXTAREA,
            "NUMBER" => FieldType::NUMBER,
            "SELECT" => FieldType::SELECT,
            "MULTI_SELECT" => FieldType::MULTI_SELECT,
            "RADIO" => FieldType::RADIO,
            "CHECKBOX" => FieldType::CHECKBOX,
            "DATE" => FieldType::DATE,
            "TIME" => FieldType::TIME,
            "EMAIL" => FieldType::EMAIL,
            "URL" => FieldType::URL,
            _ => Self::default(),
        }
    }
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct Option_pb<'a> {
    pub label: Cow<'a, str>,
    pub value: Cow<'a, str>,
    pub bit: u32,
}

impl<'a> MessageRead<'a> for Option_pb<'a> {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(10) => msg.label = r.read_string(bytes).map(Cow::Borrowed)?,
                Ok(18) => msg.value = r.read_string(bytes).map(Cow::Borrowed)?,
                Ok(24) => msg.bit = r.read_uint32(bytes)?,
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl<'a> MessageWrite for Option_pb<'a> {
    fn get_size(&self) -> usize {
        0
        + if self.label == "" { 0 } else { 1 + sizeof_len((&self.label).len()) }
        + if self.value == "" { 0 } else { 1 + sizeof_len((&self.value).len()) }
        + if self.bit == 0u32 { 0 } else { 1 + sizeof_varint(*(&self.bit) as u64) }
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        if self.label != "" { w.write_with_tag(10, |w| w.write_string(&**&self.label))?; }
        if self.value != "" { w.write_with_tag(18, |w| w.write_string(&**&self.value))?; }
        if self.bit != 0u32 { w.write_with_tag(24, |w| w.write_uint32(*&self.bit))?; }
        Ok(())
    }
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct Options<'a> {
    pub options: Vec<Option_pb<'a>>,
    pub use_bitmask: bool,
}

impl<'a> MessageRead<'a> for Options<'a> {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(10) => msg.options.push(r.read_message::<Option_pb>(bytes)?),
                Ok(16) => msg.use_bitmask = r.read_bool(bytes)?,
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl<'a> MessageWrite for Options<'a> {
    fn get_size(&self) -> usize {
        0
        + self.options.iter().map(|s| 1 + sizeof_len((s).get_size())).sum::<usize>()
        + if self.use_bitmask == false { 0 } else { 1 + sizeof_varint(*(&self.use_bitmask) as u64) }
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        for s in &self.options { w.write_with_tag(10, |w| w.write_message(s))?; }
        if self.use_bitmask != false { w.write_with_tag(16, |w| w.write_bool(*&self.use_bitmask))?; }
        Ok(())
    }
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct Form<'a> {
    pub id: u64,
    pub name: Cow<'a, str>,
    pub description: Cow<'a, str>,
    pub created_at: u64,
    pub updated_at: u64,
    pub owner: Cow<'a, str>,
    pub fields: Vec<mod_Form::Field<'a>>,
    pub allowed_participants: Vec<Cow<'a, str>>,
    pub mentioned_emails: Vec<Cow<'a, str>>,
}

impl<'a> MessageRead<'a> for Form<'a> {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(8) => msg.id = r.read_uint64(bytes)?,
                Ok(18) => msg.name = r.read_string(bytes).map(Cow::Borrowed)?,
                Ok(26) => msg.description = r.read_string(bytes).map(Cow::Borrowed)?,
                Ok(48) => msg.created_at = r.read_uint64(bytes)?,
                Ok(72) => msg.updated_at = r.read_uint64(bytes)?,
                Ok(58) => msg.owner = r.read_string(bytes).map(Cow::Borrowed)?,
                Ok(66) => msg.fields.push(r.read_message::<mod_Form::Field>(bytes)?),
                Ok(82) => msg.allowed_participants.push(r.read_string(bytes).map(Cow::Borrowed)?),
                Ok(98) => msg.mentioned_emails.push(r.read_string(bytes).map(Cow::Borrowed)?),
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl<'a> MessageWrite for Form<'a> {
    fn get_size(&self) -> usize {
        0
        + if self.id == 0u64 { 0 } else { 1 + sizeof_varint(*(&self.id) as u64) }
        + if self.name == "" { 0 } else { 1 + sizeof_len((&self.name).len()) }
        + if self.description == "" { 0 } else { 1 + sizeof_len((&self.description).len()) }
        + if self.created_at == 0u64 { 0 } else { 1 + sizeof_varint(*(&self.created_at) as u64) }
        + if self.updated_at == 0u64 { 0 } else { 1 + sizeof_varint(*(&self.updated_at) as u64) }
        + if self.owner == "" { 0 } else { 1 + sizeof_len((&self.owner).len()) }
        + self.fields.iter().map(|s| 1 + sizeof_len((s).get_size())).sum::<usize>()
        + self.allowed_participants.iter().map(|s| 1 + sizeof_len((s).len())).sum::<usize>()
        + self.mentioned_emails.iter().map(|s| 1 + sizeof_len((s).len())).sum::<usize>()
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        if self.id != 0u64 { w.write_with_tag(8, |w| w.write_uint64(*&self.id))?; }
        if self.name != "" { w.write_with_tag(18, |w| w.write_string(&**&self.name))?; }
        if self.description != "" { w.write_with_tag(26, |w| w.write_string(&**&self.description))?; }
        if self.created_at != 0u64 { w.write_with_tag(48, |w| w.write_uint64(*&self.created_at))?; }
        if self.updated_at != 0u64 { w.write_with_tag(72, |w| w.write_uint64(*&self.updated_at))?; }
        if self.owner != "" { w.write_with_tag(58, |w| w.write_string(&**&self.owner))?; }
        for s in &self.fields { w.write_with_tag(66, |w| w.write_message(s))?; }
        for s in &self.allowed_participants { w.write_with_tag(82, |w| w.write_string(&**s))?; }
        for s in &self.mentioned_emails { w.write_with_tag(98, |w| w.write_string(&**s))?; }
        Ok(())
    }
}

pub mod mod_Form {

use std::borrow::Cow;
use super::*;

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct Field<'a> {
    pub type_pb: FieldType,
    pub name: Cow<'a, str>,
    pub label: Cow<'a, str>,
    pub required: bool,
    pub placeholder: Cow<'a, str>,
    pub help_text: Cow<'a, str>,
    pub config: mod_Form::mod_Field::OneOfconfig<'a>,
}

impl<'a> MessageRead<'a> for Field<'a> {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(8) => msg.type_pb = r.read_enum(bytes)?,
                Ok(18) => msg.name = r.read_string(bytes).map(Cow::Borrowed)?,
                Ok(26) => msg.label = r.read_string(bytes).map(Cow::Borrowed)?,
                Ok(32) => msg.required = r.read_bool(bytes)?,
                Ok(74) => msg.placeholder = r.read_string(bytes).map(Cow::Borrowed)?,
                Ok(82) => msg.help_text = r.read_string(bytes).map(Cow::Borrowed)?,
                Ok(40) => msg.config = mod_Form::mod_Field::OneOfconfig::max_length(r.read_int32(bytes)?),
                Ok(50) => msg.config = mod_Form::mod_Field::OneOfconfig::pattern(r.read_string(bytes).map(Cow::Borrowed)?),
                Ok(58) => msg.config = mod_Form::mod_Field::OneOfconfig::select_options(r.read_message::<Options>(bytes)?),
                Ok(66) => msg.config = mod_Form::mod_Field::OneOfconfig::number_config(r.read_message::<mod_Form::NumberConfig>(bytes)?),
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl<'a> MessageWrite for Field<'a> {
    fn get_size(&self) -> usize {
        0
        + if self.type_pb == forms::FieldType::TEXT { 0 } else { 1 + sizeof_varint(*(&self.type_pb) as u64) }
        + if self.name == "" { 0 } else { 1 + sizeof_len((&self.name).len()) }
        + if self.label == "" { 0 } else { 1 + sizeof_len((&self.label).len()) }
        + if self.required == false { 0 } else { 1 + sizeof_varint(*(&self.required) as u64) }
        + if self.placeholder == "" { 0 } else { 1 + sizeof_len((&self.placeholder).len()) }
        + if self.help_text == "" { 0 } else { 1 + sizeof_len((&self.help_text).len()) }
        + match self.config {
            mod_Form::mod_Field::OneOfconfig::max_length(ref m) => 1 + sizeof_varint(*(m) as u64),
            mod_Form::mod_Field::OneOfconfig::pattern(ref m) => 1 + sizeof_len((m).len()),
            mod_Form::mod_Field::OneOfconfig::select_options(ref m) => 1 + sizeof_len((m).get_size()),
            mod_Form::mod_Field::OneOfconfig::number_config(ref m) => 1 + sizeof_len((m).get_size()),
            mod_Form::mod_Field::OneOfconfig::None => 0,
    }    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        if self.type_pb != forms::FieldType::TEXT { w.write_with_tag(8, |w| w.write_enum(*&self.type_pb as i32))?; }
        if self.name != "" { w.write_with_tag(18, |w| w.write_string(&**&self.name))?; }
        if self.label != "" { w.write_with_tag(26, |w| w.write_string(&**&self.label))?; }
        if self.required != false { w.write_with_tag(32, |w| w.write_bool(*&self.required))?; }
        if self.placeholder != "" { w.write_with_tag(74, |w| w.write_string(&**&self.placeholder))?; }
        if self.help_text != "" { w.write_with_tag(82, |w| w.write_string(&**&self.help_text))?; }
        match self.config {            mod_Form::mod_Field::OneOfconfig::max_length(ref m) => { w.write_with_tag(40, |w| w.write_int32(*m))? },
            mod_Form::mod_Field::OneOfconfig::pattern(ref m) => { w.write_with_tag(50, |w| w.write_string(&**m))? },
            mod_Form::mod_Field::OneOfconfig::select_options(ref m) => { w.write_with_tag(58, |w| w.write_message(m))? },
            mod_Form::mod_Field::OneOfconfig::number_config(ref m) => { w.write_with_tag(66, |w| w.write_message(m))? },
            mod_Form::mod_Field::OneOfconfig::None => {},
    }        Ok(())
    }
}

pub mod mod_Field {

use super::*;

#[derive(Debug, PartialEq, Clone)]
pub enum OneOfconfig<'a> {
    max_length(i32),
    pattern(Cow<'a, str>),
    select_options(Options<'a>),
    number_config(mod_Form::NumberConfig),
    None,
}

impl<'a> Default for OneOfconfig<'a> {
    fn default() -> Self {
        OneOfconfig::None
    }
}

}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct NumberConfig {
    pub min: f64,
    pub max: f64,
    pub step: f64,
}

impl<'a> MessageRead<'a> for NumberConfig {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(9) => msg.min = r.read_double(bytes)?,
                Ok(17) => msg.max = r.read_double(bytes)?,
                Ok(25) => msg.step = r.read_double(bytes)?,
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl MessageWrite for NumberConfig {
    fn get_size(&self) -> usize {
        0
        + if self.min == 0f64 { 0 } else { 1 + 8 }
        + if self.max == 0f64 { 0 } else { 1 + 8 }
        + if self.step == 0f64 { 0 } else { 1 + 8 }
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        if self.min != 0f64 { w.write_with_tag(9, |w| w.write_double(*&self.min))?; }
        if self.max != 0f64 { w.write_with_tag(17, |w| w.write_double(*&self.max))?; }
        if self.step != 0f64 { w.write_with_tag(25, |w| w.write_double(*&self.step))?; }
        Ok(())
    }
}

}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct FormSubmission<'a> {
    pub form_id: u64,
    pub values: KVMap<Cow<'a, str>, FieldValue<'a>>,
    pub submitted_at: u64,
}

impl<'a> MessageRead<'a> for FormSubmission<'a> {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(8) => msg.form_id = r.read_uint64(bytes)?,
                Ok(18) => {
                    let (key, value) = r.read_map(bytes, |r, bytes| Ok(r.read_string(bytes).map(Cow::Borrowed)?), |r, bytes| Ok(r.read_message::<FieldValue>(bytes)?))?;
                    msg.values.insert(key, value);
                }
                Ok(24) => msg.submitted_at = r.read_uint64(bytes)?,
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl<'a> MessageWrite for FormSubmission<'a> {
    fn get_size(&self) -> usize {
        0
        + if self.form_id == 0u64 { 0 } else { 1 + sizeof_varint(*(&self.form_id) as u64) }
        + self.values.iter().map(|(k, v)| 1 + sizeof_len(2 + sizeof_len((k).len()) + sizeof_len((v).get_size()))).sum::<usize>()
        + if self.submitted_at == 0u64 { 0 } else { 1 + sizeof_varint(*(&self.submitted_at) as u64) }
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        if self.form_id != 0u64 { w.write_with_tag(8, |w| w.write_uint64(*&self.form_id))?; }
        for (k, v) in self.values.iter() { w.write_with_tag(18, |w| w.write_map(2 + sizeof_len((k).len()) + sizeof_len((v).get_size()), 10, |w| w.write_string(&**k), 18, |w| w.write_message(v)))?; }
        if self.submitted_at != 0u64 { w.write_with_tag(24, |w| w.write_uint64(*&self.submitted_at))?; }
        Ok(())
    }
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct FieldValue<'a> {
    pub value: mod_FieldValue::OneOfvalue<'a>,
}

impl<'a> MessageRead<'a> for FieldValue<'a> {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(10) => msg.value = mod_FieldValue::OneOfvalue::string_value(r.read_string(bytes).map(Cow::Borrowed)?),
                Ok(16) => msg.value = mod_FieldValue::OneOfvalue::integer_value(r.read_int64(bytes)?),
                Ok(25) => msg.value = mod_FieldValue::OneOfvalue::double_value(r.read_double(bytes)?),
                Ok(32) => msg.value = mod_FieldValue::OneOfvalue::bool_value(r.read_bool(bytes)?),
                Ok(40) => msg.value = mod_FieldValue::OneOfvalue::bitmask_value(r.read_uint64(bytes)?),
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl<'a> MessageWrite for FieldValue<'a> {
    fn get_size(&self) -> usize {
        0
        + match self.value {
            mod_FieldValue::OneOfvalue::string_value(ref m) => 1 + sizeof_len((m).len()),
            mod_FieldValue::OneOfvalue::integer_value(ref m) => 1 + sizeof_varint(*(m) as u64),
            mod_FieldValue::OneOfvalue::double_value(_) => 1 + 8,
            mod_FieldValue::OneOfvalue::bool_value(ref m) => 1 + sizeof_varint(*(m) as u64),
            mod_FieldValue::OneOfvalue::bitmask_value(ref m) => 1 + sizeof_varint(*(m) as u64),
            mod_FieldValue::OneOfvalue::None => 0,
    }    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        match self.value {            mod_FieldValue::OneOfvalue::string_value(ref m) => { w.write_with_tag(10, |w| w.write_string(&**m))? },
            mod_FieldValue::OneOfvalue::integer_value(ref m) => { w.write_with_tag(16, |w| w.write_int64(*m))? },
            mod_FieldValue::OneOfvalue::double_value(ref m) => { w.write_with_tag(25, |w| w.write_double(*m))? },
            mod_FieldValue::OneOfvalue::bool_value(ref m) => { w.write_with_tag(32, |w| w.write_bool(*m))? },
            mod_FieldValue::OneOfvalue::bitmask_value(ref m) => { w.write_with_tag(40, |w| w.write_uint64(*m))? },
            mod_FieldValue::OneOfvalue::None => {},
    }        Ok(())
    }
}

pub mod mod_FieldValue {

use super::*;

#[derive(Debug, PartialEq, Clone)]
pub enum OneOfvalue<'a> {
    string_value(Cow<'a, str>),
    integer_value(i64),
    double_value(f64),
    bool_value(bool),
    bitmask_value(u64),
    None,
}

impl<'a> Default for OneOfvalue<'a> {
    fn default() -> Self {
        OneOfvalue::None
    }
}

}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct OtpRequest<'a> {
    pub email: Cow<'a, str>,
    pub form_id: u64,
}

impl<'a> MessageRead<'a> for OtpRequest<'a> {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(10) => msg.email = r.read_string(bytes).map(Cow::Borrowed)?,
                Ok(16) => msg.form_id = r.read_uint64(bytes)?,
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl<'a> MessageWrite for OtpRequest<'a> {
    fn get_size(&self) -> usize {
        0
        + if self.email == "" { 0 } else { 1 + sizeof_len((&self.email).len()) }
        + if self.form_id == 0u64 { 0 } else { 1 + sizeof_varint(*(&self.form_id) as u64) }
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        if self.email != "" { w.write_with_tag(10, |w| w.write_string(&**&self.email))?; }
        if self.form_id != 0u64 { w.write_with_tag(16, |w| w.write_uint64(*&self.form_id))?; }
        Ok(())
    }
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct OtpVerify<'a> {
    pub email: Cow<'a, str>,
    pub code: Cow<'a, str>,
    pub form_id: u64,
}

impl<'a> MessageRead<'a> for OtpVerify<'a> {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(10) => msg.email = r.read_string(bytes).map(Cow::Borrowed)?,
                Ok(18) => msg.code = r.read_string(bytes).map(Cow::Borrowed)?,
                Ok(24) => msg.form_id = r.read_uint64(bytes)?,
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl<'a> MessageWrite for OtpVerify<'a> {
    fn get_size(&self) -> usize {
        0
        + if self.email == "" { 0 } else { 1 + sizeof_len((&self.email).len()) }
        + if self.code == "" { 0 } else { 1 + sizeof_len((&self.code).len()) }
        + if self.form_id == 0u64 { 0 } else { 1 + sizeof_varint(*(&self.form_id) as u64) }
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        if self.email != "" { w.write_with_tag(10, |w| w.write_string(&**&self.email))?; }
        if self.code != "" { w.write_with_tag(18, |w| w.write_string(&**&self.code))?; }
        if self.form_id != 0u64 { w.write_with_tag(24, |w| w.write_uint64(*&self.form_id))?; }
        Ok(())
    }
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct EmailVerificationRequest<'a> {
    pub email: Cow<'a, str>,
}

impl<'a> MessageRead<'a> for EmailVerificationRequest<'a> {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(10) => msg.email = r.read_string(bytes).map(Cow::Borrowed)?,
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl<'a> MessageWrite for EmailVerificationRequest<'a> {
    fn get_size(&self) -> usize {
        0
        + if self.email == "" { 0 } else { 1 + sizeof_len((&self.email).len()) }
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        if self.email != "" { w.write_with_tag(10, |w| w.write_string(&**&self.email))?; }
        Ok(())
    }
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct EmailVerificationVerify<'a> {
    pub email: Cow<'a, str>,
    pub code: Cow<'a, str>,
}

impl<'a> MessageRead<'a> for EmailVerificationVerify<'a> {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(10) => msg.email = r.read_string(bytes).map(Cow::Borrowed)?,
                Ok(18) => msg.code = r.read_string(bytes).map(Cow::Borrowed)?,
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl<'a> MessageWrite for EmailVerificationVerify<'a> {
    fn get_size(&self) -> usize {
        0
        + if self.email == "" { 0 } else { 1 + sizeof_len((&self.email).len()) }
        + if self.code == "" { 0 } else { 1 + sizeof_len((&self.code).len()) }
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        if self.email != "" { w.write_with_tag(10, |w| w.write_string(&**&self.email))?; }
        if self.code != "" { w.write_with_tag(18, |w| w.write_string(&**&self.code))?; }
        Ok(())
    }
}

