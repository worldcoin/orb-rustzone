#![no_std]

extern crate alloc;

use alloc::{string::String, vec::Vec};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Eq, PartialEq, TryFromPrimitive, IntoPrimitive)]
#[repr(u32)]
pub enum CommandId {
    Put = 1,
    Get = 2,
}

pub trait ResponseT: Sized + serde::Serialize + for<'a> serde::Deserialize<'a> {
    fn deserialize<B: AsRef<[u8]>>(
        buf: B,
    ) -> Result<Self, impl core::error::Error + Send + Sync + 'static> {
        serde_json::from_slice(buf.as_ref())
    }

    fn serialize(&self, out_buf: &mut [u8]) -> Result<usize, BufferTooSmallErr> {
        let serialized = serde_json::to_vec(self).expect("infallible");
        let nbytes = serialized.len();
        if out_buf.len() < nbytes {
            return Err(BufferTooSmallErr);
        }
        let out_buf = &mut out_buf[0..nbytes];
        out_buf.copy_from_slice(&serialized);

        Ok(nbytes)
    }
}

pub trait RequestT: Sized + serde::Serialize + for<'a> serde::Deserialize<'a> {
    const MAX_RESPONSE_SIZE: u32;
    type Response: ResponseT;
    fn id(&self) -> CommandId;
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    Put(PutRequest),
    Get(GetRequest),
}

impl Request {
    pub fn id(&self) -> CommandId {
        match self {
            Request::Put(_) => CommandId::Put,
            Request::Get(_) => CommandId::Get,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    Ping,
    Put(PutResponse),
    Get(GetResponse),
}

#[derive(Debug, thiserror::Error)]
#[error("could not deserialize because the provided buffer was too small")]
pub struct BufferTooSmallErr;

#[derive(Debug, Serialize, Deserialize)]
pub struct PutRequest {
    pub key: String,
    pub val: Vec<u8>,
}

impl RequestT for PutRequest {
    const MAX_RESPONSE_SIZE: u32 = 1024 * 1024;

    type Response = PutResponse;

    fn id(&self) -> CommandId {
        CommandId::Put
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PutResponse {
    /// returns the previously stored value (or None if no prior value existed)
    pub prev_val: Option<Vec<u8>>,
}

impl ResponseT for PutResponse {}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetRequest {
    pub key: String,
}

impl RequestT for GetRequest {
    const MAX_RESPONSE_SIZE: u32 = 1024 * 1024;

    type Response = GetResponse;

    fn id(&self) -> CommandId {
        CommandId::Get
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetResponse {
    pub val: Option<Vec<u8>>,
}

impl ResponseT for GetResponse {}

/// Different domains for storage. Each domain maps to a different TA with its storage
/// isolated from other domains.
#[derive(Debug, Eq, PartialEq, Copy, Clone, Hash)]
pub enum StorageDomain {
    WifiProfiles,
}

impl StorageDomain {
    pub const fn as_uuid(&self) -> &'static str {
        match self {
            // If Uuid::parse_str() returns an InvalidLength error, there may be an extra
            // newline in your uuid.txt file. You can remove it by running
            // `truncate -s 36 uuid.txt`.
            StorageDomain::WifiProfiles => include_str!("../../uuid.txt"),
        }
    }
}
