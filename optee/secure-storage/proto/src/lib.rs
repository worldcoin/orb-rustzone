#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use core::{fmt::Display, str::FromStr};

use alloc::{borrow::ToOwned, collections::BTreeSet, string::String, vec::Vec};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Eq, PartialEq, TryFromPrimitive, IntoPrimitive)]
#[repr(u32)]
pub enum CommandId {
    Put = 1,
    Get = 2,
    Version = 3,
    List = 4,
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
    Version(VersionRequest),
    List(ListRequest),
}

impl Request {
    pub fn id(&self) -> CommandId {
        match self {
            Request::Put(_) => CommandId::Put,
            Request::Get(_) => CommandId::Get,
            Request::Version(_) => CommandId::Version,
            Request::List(_) => CommandId::List,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    Put(PutResponse),
    Get(GetResponse),
    Version(VersionResponse),
    List(ListResponse),
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

#[derive(Debug, Serialize, Deserialize)]
pub struct VersionRequest;

impl RequestT for VersionRequest {
    const MAX_RESPONSE_SIZE: u32 = 1024;

    type Response = VersionResponse;

    fn id(&self) -> CommandId {
        CommandId::Version
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VersionResponse(pub String);

impl ResponseT for VersionResponse {}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListRequest {
    /// Optional effective user id to filter results by
    pub euid: Option<u32>,
    /// Optional prefix to filter results by, can be empty string.
    pub prefix: String,
}

impl RequestT for ListRequest {
    const MAX_RESPONSE_SIZE: u32 = 1024 * 1024;

    type Response = ListResponse;

    fn id(&self) -> CommandId {
        CommandId::List
    }
}

/// A key in secure storage.
#[derive(
    Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Hash, Ord, PartialOrd,
)]
pub struct Key {
    pub euid: u32,
    pub user_key: String,
}

impl Display for Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "v=1,euid={:#x}/{}", self.euid, self.user_key)
    }
}

#[derive(Debug, thiserror::Error, Eq, PartialEq, Clone, Copy)]
pub enum ParseKeyErr {
    #[error("unsupported key version")]
    UnsupportedVersion,
    #[error("key has invalid syntax")]
    InvalidSyntax,
}

impl FromStr for Key {
    type Err = ParseKeyErr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let Some((version, suffix)) =
            s.strip_prefix("v=").and_then(|k| k.split_once(","))
        else {
            return Err(ParseKeyErr::InvalidSyntax);
        };
        let Ok(version) = version.parse::<u64>() else {
            return Err(ParseKeyErr::InvalidSyntax);
        };
        if version != 1 {
            return Err(ParseKeyErr::UnsupportedVersion);
        }
        let Some((euid, user_key)) =
            suffix.strip_prefix("euid=").and_then(|k| k.split_once("/"))
        else {
            return Err(ParseKeyErr::InvalidSyntax);
        };
        let Some(euid) = euid
            .strip_prefix("0x")
            .and_then(|hex| u32::from_str_radix(hex, 16).ok())
        else {
            return Err(ParseKeyErr::InvalidSyntax);
        };

        Ok(Key {
            euid,
            user_key: user_key.to_owned(),
        })
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ListResponse {
    pub keys: BTreeSet<Key>,
}

impl ResponseT for ListResponse {}

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

#[cfg(test)]
mod test_key {
    use super::*;

    #[test]
    fn fails_non_hex_encoded_euid() {
        let examples = [
            "v=1,euid=0/zero",
            "v=1,euid=9/nine",
            "v=1,euid=10/ten",
            "v=1,euid=A/ten_but_in_upper_hex_without_0x",
            "v=1,euid=a/ten_but_in_lower_hex_without_0x",
        ];

        for e in examples {
            assert_eq!(e.parse::<Key>(), Err(ParseKeyErr::InvalidSyntax));
        }
    }

    #[test]
    fn fails_capital_x_hex_encoded_euid() {
        let examples = ["v=1,euid=0X0/zero", "v=1,euid=0X9/nine", "v=1,euid=0XA/ten"];

        for e in examples {
            assert_eq!(e.parse::<Key>(), Err(ParseKeyErr::InvalidSyntax));
        }
    }

    #[test]
    fn fails_unknown_version() {
        assert_eq!(
            "v=0,euid=0x0/zero".parse::<Key>(),
            Err(ParseKeyErr::UnsupportedVersion)
        );
        assert_eq!(
            "v=2,euid=0x0/two".parse::<Key>(),
            Err(ParseKeyErr::UnsupportedVersion)
        );
    }

    #[test]
    fn fails_hex_version() {
        let examples = [
            "v=A,euid=0x0/foo",
            "v=a,euid=0x0/foo",
            "v=0xA,euid=0x0/foo",
            "v=0xa,euid=0x0/foo",
            "v=0XA,euid=0x0/foo",
            "v=0Xa,euid=0x0/foo",
        ];
        for e in examples {
            assert_eq!(e.parse::<Key>(), Err(ParseKeyErr::InvalidSyntax), "{e}");
        }
    }

    #[test]
    fn parses_known_good_values() {
        let examples = [
            (0, "zero", "v=1,euid=0x0/zero"),
            (9, "nine", "v=1,euid=0x9/nine"),
            (10, "ten", "v=1,euid=0xA/ten"),
            (255, "two-fifty-five", "v=1,euid=0xFF/two-fifty-five"),
            (256, "two-fifty-six", "v=1,euid=0x100/two-fifty-six"),
        ];

        for (euid, user_key, s) in examples {
            assert_eq!(
                Ok(Key {
                    euid,
                    user_key: user_key.to_owned()
                }),
                s.parse(),
                "failed string {s}"
            )
        }
    }
}
