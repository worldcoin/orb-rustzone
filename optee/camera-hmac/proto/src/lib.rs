#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{Deserialize, Serialize};

/// Number of 64-byte pixel blocks to hash per frame.
pub const BLOCKS_TO_HASH: u32 = 100;

/// Number of pixel blocks in a 64-wide column (64 / 2).
pub const PIXEL_BLOCKS: u32 = 32;

/// Bytes read from the frame tail to extract the embedded HMAC.
/// Layout: [4 bytes header][32 bytes HMAC] (total 36).
pub const HMAC_TAIL_BYTES: usize = 36;

/// Offset of the 32-byte HMAC within the tail region.
pub const HMAC_OFFSET_IN_TAIL: usize = 4;

/// Length of the per-frame HMAC signature in bytes.
pub const HMAC_LEN: usize = 32;

/// Length of the frame counter field extracted from embedded lines.
pub const FRAME_NUM_LEN: usize = 8;

#[derive(Debug, Clone, Copy, Eq, PartialEq, TryFromPrimitive, IntoPrimitive)]
#[repr(u32)]
pub enum CommandId {
    ProvisionKey = 1,
    GetRowStart = 2,
    VerifyHmac = 3,
    Version = 4,
}

#[derive(Debug, thiserror::Error)]
#[error("output buffer too small for serialized response")]
pub struct BufferTooSmallErr;

pub trait ResponseT: Sized + Serialize + for<'a> Deserialize<'a> {
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
        out_buf[..nbytes].copy_from_slice(&serialized);
        Ok(nbytes)
    }
}

pub trait RequestT: Sized + Serialize + for<'a> Deserialize<'a> {
    /// Upper bound on the serialized response size in bytes.
    const MAX_RESPONSE_SIZE: u32;
    type Response: ResponseT;
    fn id(&self) -> CommandId;
}

/// Describes the number of special rows embedded at the top and bottom of each
/// raw frame produced by the OX05B1S + OAX4000 ISP pair.
/// For the Diamond platform the values are `(2, 2, 2, 2, 0)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmblParams {
    pub pre_sei: u32,
    pub post_sei: u32,
    pub pre_ovi: u32,
    pub post_ovi: u32,
    pub sta: u32,
}

impl EmblParams {
    /// Default parameters for the Diamond ISP configuration.
    pub const fn default_diamond() -> Self {
        Self {
            pre_sei: 2,
            post_sei: 2,
            pre_ovi: 2,
            post_ovi: 2,
            sta: 0,
        }
    }

    /// Total number of non-image rows in the frame.
    pub fn total_embl_rows(&self) -> u32 {
        self.pre_sei + self.post_sei + self.pre_ovi + self.post_ovi + self.sta
    }

    /// Number of actual image rows.
    pub fn image_rows(&self, vsize: u32) -> u32 {
        vsize.saturating_sub(self.total_embl_rows())
    }
}

/// Store the 32-byte PPK inside OPTEE secure storage.
/// This operation is idempotent (calling it again overwrites the previous key).
/// It should be restricted to the provisioning / manufacturing workflow.
#[derive(Debug, Serialize, Deserialize)]
pub struct ProvisionKeyRequest {
    /// The 32-byte Pre-Provisioned Key obtained from OmniVision.
    pub ppk: [u8; 32],
}

impl RequestT for ProvisionKeyRequest {
    const MAX_RESPONSE_SIZE: u32 = 256;
    type Response = ProvisionKeyResponse;
    fn id(&self) -> CommandId {
        CommandId::ProvisionKey
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProvisionKeyResponse;

impl ResponseT for ProvisionKeyResponse {}

/// Ask OPTEE to compute the randomly-selected starting image row (`SR2H`) for
/// this frame.  `SR2H` is derived from `RSKEY` (which is itself derived from
/// the secret PPK) so it never crosses the security boundary in cleartext form
/// beyond a 32-bit row index.
/// The normal world uses `SR2H` in [`gather_src_data`] to slice out the
/// correct pixel region before calling [`VerifyHmacRequest`].
#[derive(Debug, Serialize, Deserialize)]
pub struct GetRowStartRequest {
    /// 6-byte sensor UID read from registers EE44–EE49.
    pub uid: [u8; 6],
    /// 16-byte NONCE read from registers EB40–EB4F.
    pub nonce: [u8; 16],
    /// 8-byte frame counter extracted from the first bottom-OVI line
    /// (bytes 0..8 reversed) and converted to big-endian representation.
    pub frame_num: [u8; FRAME_NUM_LEN],
    /// Horizontal pixel count (e.g. 2592 for the OX05B1S 5 MP mode).
    pub hsize_raw: u32,
    /// Total row count of the raw frame including embedding lines (e.g. 1952).
    pub vsize: u32,
    /// Frame embedding parameters describing the layout of special rows.
    pub embl: EmblParams,
}

impl RequestT for GetRowStartRequest {
    const MAX_RESPONSE_SIZE: u32 = 256;
    type Response = GetRowStartResponse;
    fn id(&self) -> CommandId {
        CommandId::GetRowStart
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetRowStartResponse {
    /// Starting image row index (0-based) within the image-data region.
    /// Add `embl.pre_sei + embl.pre_ovi` to get the absolute row in the frame.
    pub sr2h: u32,
}

impl ResponseT for GetRowStartResponse {}

/// Verify the HMAC embedded in a camera frame entirely inside OPTEE.
///
/// Caller responsibilities before invoking this command
/// 1. Obtain `SR2H` from [`GetRowStartRequest`].
/// 2. Gather the appropriate byte ranges from the raw frame with
///    [`gather_src_data`] (or equivalent logic).
/// 3. Apply the format-specific pixel conversion for the sensor's `dtype`
///    (for `dtype=0x1e` YUV422-8 this is a no-op).
/// 4. Apply [`pix_swap`] to the gathered data.
/// 5. Extract the 32-byte HMAC from the frame tail with
///    [`extract_embedded_hmac`].
/// 6. Fill this struct and invoke the command.
///
/// The TA derives `AKEY` from the stored PPK, computes
/// `HMAC-SHA256(AKEY, SHA256(P0)‖SHA256(P1)‖SHA256(P2)‖SHA256(P3))`
/// and compares it to `embedded_hmac` using a constant-time comparison.
/// Only a boolean result is returned; the key material stays inside OPTEE.
///
/// ## Buffer size
///
/// The JSON-serialized request for a typical 5 MP YUV422-8 frame is roughly
/// **120–160 KB** (src_data ≈ 37 KB encoded as a JSON byte array).  Callers
/// must allocate at least 256 KB for the request shared-memory buffer.
#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyHmacRequest {
    /// 6-byte sensor UID (registers EE44–EE49).
    pub uid: [u8; 6],
    /// 16-byte NONCE (registers EB40–EB4F).
    pub nonce: [u8; 16],
    /// Processed pixel data gathered from the frame.  Must already have
    /// the format-specific pixel conversion and [`pix_swap`] applied.
    pub src_data: Vec<u8>,
    /// 32-byte HMAC extracted from the tail of the raw frame
    /// (bytes `[4..36]` of the last 36 bytes, per [`extract_embedded_hmac`]).
    pub embedded_hmac: [u8; HMAC_LEN],
}

impl RequestT for VerifyHmacRequest {
    /// The response is just `{"valid":true}` or `{"valid":false}`.
    const MAX_RESPONSE_SIZE: u32 = 64;
    type Response = VerifyHmacResponse;
    fn id(&self) -> CommandId {
        CommandId::VerifyHmac
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyHmacResponse {
    /// `true` if the frame HMAC matches the expected value; `false` otherwise.
    pub valid: bool,
}

impl ResponseT for VerifyHmacResponse {}

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

/// The camera HMAC TA has its own UUID and therefore its own isolated OPTEE
/// secure-storage partition, separate from every other TA in the system.
pub struct CameraHmacDomain;

impl CameraHmacDomain {
    /// UUID of the `orb-camera-hmac-ta` Trusted Application.
    ///
    /// If [`uuid::Uuid::parse_str`] returns an `InvalidLength` error, there
    /// may be a trailing newline in `uuid.txt`.  Remove it with:
    /// `truncate -s 36 uuid.txt`
    pub const fn as_uuid() -> &'static str {
        include_str!("../../uuid.txt")
    }
}

/// Apply the OX05B1S pixel-swap transformation in-place.
///
/// The sensor arranges pixel data in 8-byte blocks where the four 16-bit
/// pixels are stored in reversed order.  This function reverses them back to
/// natural order so that the HMAC computation matches the sensor's expectation.
///
/// Input  bytes `[a, b, c, d, e, f, g, h]` (a 4-pixel block) →
/// Output bytes `[g, h, e, f, c, d, a, b]`.
///
/// `data.len()` must be a multiple of 8.
pub fn pix_swap(data: &mut [u8]) -> Result<(), PixSwapError> {
    if data.len() % 8 != 0 {
        return Err(PixSwapError::LengthNotMultipleOf8 { len: data.len() });
    }
    for chunk in data.chunks_exact_mut(8) {
        // Reverse the order of the four 16-bit (LE) pixels inside each block.
        // [a,b, c,d, e,f, g,h] → [g,h, e,f, c,d, a,b]
        let mut tmp = [0u8; 8];
        tmp[0..2].copy_from_slice(&chunk[6..8]);
        tmp[2..4].copy_from_slice(&chunk[4..6]);
        tmp[4..6].copy_from_slice(&chunk[2..4]);
        tmp[6..8].copy_from_slice(&chunk[0..2]);
        chunk.copy_from_slice(&tmp);
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum PixSwapError {
    #[error("pix_swap requires data length to be a multiple of 8, got {len}")]
    LengthNotMultipleOf8 { len: usize },
}

/// Extract the 32-byte HMAC that the sensor embeds at the tail of each frame.
///
/// Layout of the last 36 raw bytes (for `dtype=0x1e`, `gEmblDatStep=1`):
/// ```text
/// bytes[0..3]  – reserved header
/// bytes[3]     – toggle bit
/// bytes[4..36] – 32-byte HMAC-SHA256 signature  ← returned here
/// ```
///
/// Returns `None` if `raw_frame` is shorter than 36 bytes.
pub fn extract_embedded_hmac(raw_frame: &[u8]) -> Option<[u8; HMAC_LEN]> {
    if raw_frame.len() < HMAC_TAIL_BYTES {
        return None;
    }
    let tail = &raw_frame[raw_frame.len() - HMAC_TAIL_BYTES..];
    let mut hmac = [0u8; HMAC_LEN];
    hmac.copy_from_slice(&tail[HMAC_OFFSET_IN_TAIL..HMAC_TAIL_BYTES]);
    Some(hmac)
}

/// Extract the 8-byte frame counter from the first bottom-OVI line.
///
/// The frame counter is stored little-endian at the first 8 bytes of the row
/// at index `vsize - embl.post_ovi`; this function reverses them to produce
/// the big-endian representation used in key derivation.
///
/// `bytes_per_raw_line` = `hsize_raw * gPixNum[dtype]`
/// (for `dtype=0x1e`: `hsize_raw * 2`).
///
/// Returns `None` if the frame is too short.
pub fn extract_frame_num(
    raw_frame: &[u8],
    vsize: u32,
    post_ovi: u32,
    bytes_per_raw_line: u32,
) -> Option<[u8; FRAME_NUM_LEN]> {
    let start_row = vsize.checked_sub(post_ovi)? as usize;
    let byte_offset = start_row * bytes_per_raw_line as usize;
    let slice = raw_frame.get(byte_offset..byte_offset + FRAME_NUM_LEN)?;
    let mut frame_num = [0u8; FRAME_NUM_LEN];
    // The Python reference reverses the byte order: `getEmbl(...)[::-1]`
    for (i, &b) in slice.iter().enumerate() {
        frame_num[FRAME_NUM_LEN - 1 - i] = b;
    }
    Some(frame_num)
}

/// Gather the byte regions from a raw frame that the HMAC covers.
///
/// This implements the `getSrcData` logic from `hmac_check.py` for
/// `dtype=0x1e` (YUV422-8, no format conversion needed).  For other dtypes
/// the caller must apply the appropriate conversion to `raw_frame` first.
///
/// After calling this function, apply [`pix_swap`] to the returned buffer
/// before passing it to [`VerifyHmacRequest`].
///
/// # Parameters
/// * `raw_frame`      – entire raw frame bytes.
/// * `hsize_raw`      – horizontal pixel count.
/// * `vsize`          – total row count (including embedding lines).
/// * `sr2h`           – row offset within the image region (from
///                      [`GetRowStartResponse::sr2h`]).
/// * `embl`           – frame embedding parameters.
/// * `bytes_per_pixel` – `gPixNum[dtype]` (e.g. 2 for `dtype=0x1e`).
///
/// Returns `None` if the frame is too short or the parameters are inconsistent.
pub fn gather_src_data(
    raw_frame: &[u8],
    hsize_raw: u32,
    vsize: u32,
    sr2h: u32,
    embl: &EmblParams,
    bytes_per_pixel: u32,
) -> Option<Vec<u8>> {
    let bpl = hsize_raw as usize * bytes_per_pixel as usize; // bytes per raw line
    let b2h = BLOCKS_TO_HASH as usize;
    let pblocks = PIXEL_BLOCKS as usize;

    let mut src = Vec::new();

    // Top SEI lines (preseiNum)
    if embl.pre_sei > 0 {
        let len = embl.pre_sei as usize * bpl;
        let region = raw_frame.get(0..len)?;
        src.extend_from_slice(region);
    }

    // Top OVI lines (preoviNum) – immediately after top SEI
    if embl.pre_ovi > 0 {
        let start = embl.pre_sei as usize * bpl;
        let len = embl.pre_ovi as usize * bpl;
        let region = raw_frame.get(start..start + len)?;
        src.extend_from_slice(region);
    }

    // Selected image rows (SR2H .. SR2H + ROWS2HASH)
    {
        let start_row = (embl.pre_sei + embl.pre_ovi + sr2h) as usize;
        let byte_start = start_row * bpl;
        // length = B2H * pixBlocks * gPixNum[dtype]
        let selected_len = b2h * pblocks * bytes_per_pixel as usize;
        let region = raw_frame.get(byte_start..byte_start + selected_len)?;
        src.extend_from_slice(region);
    }

    // Bottom SEI lines (postseiNum) – at vsize - post_ovi - sta - post_sei
    if embl.post_sei > 0 {
        let start_row =
            (vsize - embl.post_ovi - embl.sta - embl.post_sei) as usize;
        let byte_start = start_row * bpl;
        let len = embl.post_sei as usize * bpl;
        let region = raw_frame.get(byte_start..byte_start + len)?;
        src.extend_from_slice(region);
    }

    // Statistics lines (staNum) – at vsize - post_ovi - sta
    if embl.sta > 0 {
        let start_row = (vsize - embl.post_ovi - embl.sta) as usize;
        let byte_start = start_row * bpl;
        let len = embl.sta as usize * bpl;
        let region = raw_frame.get(byte_start..byte_start + len)?;
        src.extend_from_slice(region);
    }

    Some(src)
}

/// Tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pix_swap_known_vector() {
        // Reference: Python pixSwap([a,b,c,d,e,f,g,h]) → [g,h,e,f,c,d,a,b]
        let mut data = [1u8, 2, 3, 4, 5, 6, 7, 8];
        pix_swap(&mut data).unwrap();
        assert_eq!(data, [7, 8, 5, 6, 3, 4, 1, 2]);
    }

    #[test]
    fn pix_swap_rejects_non_multiple_of_8() {
        let mut data = [0u8; 7];
        assert!(pix_swap(&mut data).is_err());
    }

    #[test]
    fn pix_swap_identity_over_two_blocks() {
        // Applying pix_swap twice should return to original.
        let original = [10u8, 20, 30, 40, 50, 60, 70, 80,
                         11,  21, 31, 41, 51, 61, 71, 81];
        let mut data = original;
        pix_swap(&mut data).unwrap();
        pix_swap(&mut data).unwrap();
        assert_eq!(data, original);
    }

    #[test]
    fn extract_embedded_hmac_correct_offset() {
        let mut frame = alloc::vec![0u8; 100];
        // Place a known pattern at the HMAC position (last 36 bytes, offset 4..36)
        for i in 0..32u8 {
            frame[100 - 36 + 4 + i as usize] = i + 1;
        }
        let hmac = extract_embedded_hmac(&frame).unwrap();
        for (i, &b) in hmac.iter().enumerate() {
            assert_eq!(b, i as u8 + 1, "byte {i} mismatch");
        }
    }

    #[test]
    fn extract_frame_num_reverses_bytes() {
        // Frame num bytes in the frame: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        // Expected (reversed):           [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
        let bpl = 10usize;
        let vsize = 4u32;
        let post_ovi = 2u32;
        // Row 2 (vsize - post_ovi = 4 - 2 = 2) starts at byte 20.
        let mut frame = alloc::vec![0u8; 60];
        for i in 0..8u8 {
            frame[20 + i as usize] = i + 1;
        }
        let num = extract_frame_num(&frame, vsize, post_ovi, bpl as u32).unwrap();
        assert_eq!(num, [8, 7, 6, 5, 4, 3, 2, 1]);
    }

    #[test]
    fn embl_params_image_rows() {
        let embl = EmblParams::default_diamond();
        assert_eq!(embl.image_rows(1952), 1944);
    }

    #[test]
    fn domain_uuid_parses() {
        // Ensure the UUID string embeds without trailing whitespace issues.
        let s = CameraHmacDomain::as_uuid();
        assert_eq!(s.len(), 36, "UUID must be exactly 36 chars (no newline)");
    }
}
