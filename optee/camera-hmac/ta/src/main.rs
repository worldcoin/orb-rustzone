#![no_std]
#![no_main]

mod trace;

extern crate alloc;

include!(concat!(env!("OUT_DIR"), "/user_ta_header.rs"));

use alloc::boxed::Box;
use alloc::format;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;
use anyhow::{bail, Context, Result};
use optee_utee::object::PersistentObject;
use optee_utee::property::PropertyKey;
use optee_utee::GenericObject;
use optee_utee::{
    ta_close_session, ta_create, ta_destroy, ta_invoke_command, ta_open_session,
};
use optee_utee::{
    AlgorithmId, Attribute, AttributeId, AttributeMemref, DataFlag, Digest, Error as TeeError,
    ErrorKind, LoginType, Mac, ObjectStorageConstants, Parameters, Result as TeeResult,
    TransientObject, TransientObjectType, Whence,
};
use orb_camera_hmac_proto::{
    BufferTooSmallErr, CommandId, EmblParams, GetRowStartRequest, GetRowStartResponse,
    ProvisionKeyRequest, ProvisionKeyResponse, RequestT, ResponseT, VersionRequest,
    VersionResponse, VerifyHmacRequest, VerifyHmacResponse,
    BLOCKS_TO_HASH, HMAC_LEN, PIXEL_BLOCKS,
};
use uuid::Uuid;

const STORAGE_ID: ObjectStorageConstants = ObjectStorageConstants::Private;

// Persistent object ID used to store the PPK.
const PPK_OBJECT_ID: &[u8] = b"camera-hmac/ppk-v1";

// Expected PPK length in bytes.
const PPK_LEN: usize = 32;

#[derive(Default)]
struct Ctx {
    client_info: ClientInfo,
    // Reusable heap buffer to reduce allocations.
    buf: Vec<u8>,
}

#[ta_create]
fn create() -> TeeResult<()> {
    let ta_version = optee_utee::property::TaVersion.get().expect("infallible");
    error!("camera-hmac TA version {}", ta_version);
    Ok(())
}

#[ta_open_session]
fn open_session(params: &mut Parameters, ctx: &mut Ctx) -> TeeResult<()> {
    debug!("TA open session");
    ctx.client_info = match open_session_inner(params) {
        Ok(info) => info,
        Err(err) => {
            error!("open_session error: {}", err);
            return Err(TeeError::new(ErrorKind::Generic));
        }
    };
    Ok(())
}

#[ta_close_session]
fn close_session(_ctx: &mut Ctx) {
    trace!("TA close session");
}

#[ta_destroy]
fn destroy() {
    trace!("TA destroy");
}

#[ta_invoke_command]
fn invoke_command(
    ctx: &mut Ctx,
    cmd_id: u32,
    params: &mut Parameters,
) -> TeeResult<()> {
    let cmd_id: CommandId = cmd_id.try_into().map_err(|err| {
        error!("unknown command id: {:?}", err);
        TeeError::new(ErrorKind::BadFormat)
    })?;

    match cmd_id {
        CommandId::ProvisionKey => response_to_params(
            ctx.handle_provision_key(request_from_params(params)?)?,
            params,
        ),
        CommandId::GetRowStart => response_to_params(
            ctx.handle_get_row_start(request_from_params(params)?)?,
            params,
        ),
        CommandId::VerifyHmac => response_to_params(
            ctx.handle_verify_hmac(request_from_params(params)?)?,
            params,
        ),
        CommandId::Version => response_to_params(
            ctx.handle_version(request_from_params(params)?)?,
            params,
        ),
    }
}

impl Ctx {
    // Store the 32-byte PPK in OPTEE persistent secure storage.
    fn handle_provision_key(
        &mut self,
        req: ProvisionKeyRequest,
    ) -> TeeResult<ProvisionKeyResponse> {
        debug!(
            "ProvisionKey: euid={}",
            self.client_info.effective_user_id
        );

        let obj_result = PersistentObject::open(
            STORAGE_ID,
            PPK_OBJECT_ID,
            DataFlag::ACCESS_WRITE | DataFlag::ACCESS_READ,
        );
        let mut obj = match obj_result {
            Ok(obj) => {
                debug!("overwriting existing PPK");
                obj
            }
            Err(err) if err.kind() == ErrorKind::ItemNotFound => {
                debug!("creating new PPK object");
                PersistentObject::create(
                    STORAGE_ID,
                    PPK_OBJECT_ID,
                    DataFlag::ACCESS_WRITE | DataFlag::ACCESS_READ,
                    None,
                    &[],
                )?
            }
            Err(err) => return Err(err),
        };

        obj.seek(0, Whence::DataSeekSet)?;
        obj.truncate(0)?;
        obj.write(&req.ppk)?;

        debug!("PPK stored successfully ({} bytes)", req.ppk.len());
        Ok(ProvisionKeyResponse)
    }

    // Derive the per-frame row-start index SR2H using RSKEY.
    // RSKEY = SHA-256(PPK ‖ UID ‖ NONCE ‖ 0x02)
    // SR2H  = u32::from_be(SHA-256(RSKEY ‖ frame_num)[0..4]) % (ROWS − ROWS2HASH)
    fn handle_get_row_start(
        &mut self,
        req: GetRowStartRequest,
    ) -> TeeResult<GetRowStartResponse> {
        debug!(
            "GetRowStart: euid={} hsize_raw={} vsize={}",
            self.client_info.effective_user_id, req.hsize_raw, req.vsize
        );

        let ppk = self.load_ppk()?;
        let rskey = derive_key(&ppk, &req.uid, &req.nonce, 2)?;
        let sr2h = compute_sr2h(&rskey, &req.frame_num, req.hsize_raw, req.vsize, &req.embl)
            .map_err(|err| {
                error!("compute_sr2h error: {}", err);
                TeeError::new(ErrorKind::BadParameters)
            })?;

        debug!("SR2H = {}", sr2h);
        Ok(GetRowStartResponse { sr2h })
    }

    // Verify the HMAC signature embedded in the frame.
    // AKEY = SHA-256(PPK ‖ UID ‖ NONCE ‖ 0x01)
    // Final HMAC = HMAC-SHA-256(AKEY, SHA-256(P0) ‖ SHA-256(P1) ‖ SHA-256(P2) ‖ SHA-256(P3))
    fn handle_verify_hmac(
        &mut self,
        req: VerifyHmacRequest,
    ) -> TeeResult<VerifyHmacResponse> {
        debug!(
            "VerifyHmac: euid={} src_data_len={}",
            self.client_info.effective_user_id,
            req.src_data.len()
        );

        let ppk = self.load_ppk()?;
        let akey = derive_key(&ppk, &req.uid, &req.nonce, 1)?;

        // Partition src_data into four round-robin 64-byte-block buckets.
        let partitions = partition_src_data(&req.src_data);

        // SHA-256 each partition, then concatenate the four digests.
        let mut s_data: Vec<u8> = Vec::with_capacity(4 * 32);
        for p in &partitions {
            let hash = sha256_one_shot(p)?;
            s_data.extend_from_slice(&hash);
        }

        // Compute HMAC-SHA-256(AKEY, S0‖S1‖S2‖S3).
        let computed_hmac = hmac_sha256(&akey, &s_data)?;

        // Constant-time comparison to prevent timing side-channels.
        let valid = ct_eq(&computed_hmac, &req.embedded_hmac);
        debug!("VerifyHmac: {}", if valid { "PASS" } else { "FAIL" });

        Ok(VerifyHmacResponse { valid })
    }

    fn handle_version(&mut self, _req: VersionRequest) -> TeeResult<VersionResponse> {
        debug!("VersionRequest");
        let v = optee_utee::property::TaVersion.get().expect("infallible");
        Ok(VersionResponse(v))
    }
}

impl Ctx {
    // Load the 32-byte PPK from persistent secure storage.
    fn load_ppk(&mut self) -> TeeResult<[u8; PPK_LEN]> {
        let obj = PersistentObject::open(
            STORAGE_ID,
            PPK_OBJECT_ID,
            DataFlag::ACCESS_READ,
        )
        .map_err(|err| {
            if err.kind() == ErrorKind::ItemNotFound {
                error!("PPK not found – call ProvisionKey first");
            } else {
                error!("failed to open PPK object: {:?}", err.kind());
            }
            err
        })?;

        let nbytes = obj.info()?.data_size();
        if nbytes != PPK_LEN {
            error!("PPK object has wrong size: {} (expected {})", nbytes, PPK_LEN);
            return Err(TeeError::new(ErrorKind::BadState));
        }

        self.buf.resize(PPK_LEN, 0);
        obj.seek(0, Whence::DataSeekSet)?;
        let read = obj.read(&mut self.buf)?;
        if read as usize != PPK_LEN {
            error!("short read of PPK: {} bytes", read);
            return Err(TeeError::new(ErrorKind::BadState));
        }

        let mut ppk = [0u8; PPK_LEN];
        ppk.copy_from_slice(&self.buf[..PPK_LEN]);
        Ok(ppk)
    }
}

// Derive an authentication or row-selection key.
// key = SHA-256(PPK ‖ UID ‖ NONCE ‖ index)
// index = 1 → AKEY (authentication key)
// index = 2 → RSKEY (row-selection key)
fn derive_key(
    ppk: &[u8; PPK_LEN],
    uid: &[u8; 6],
    nonce: &[u8; 16],
    index: u8,
) -> TeeResult<[u8; 32]> {
    // Build PPK ‖ UID ‖ NONCE ‖ index without an extra heap alloc.
    let mut input = vec![0u8; PPK_LEN + 6 + 16 + 1];
    input[..PPK_LEN].copy_from_slice(ppk);
    input[PPK_LEN..PPK_LEN + 6].copy_from_slice(uid);
    input[PPK_LEN + 6..PPK_LEN + 22].copy_from_slice(nonce);
    input[PPK_LEN + 22] = index;
    sha256_one_shot(&input)
}

// Compute SR2H
// BPR        = 2 × hsize_raw               (bytes per pixel row)
// ROWS       = vsize − Σ(embedding rows)   (actual image rows)
// ROWS2HASH  = ceil(B2H × PIXEL_BLOCKS × 2 / BPR)
// seed       = SHA-256(RSKEY ‖ frame_num)
// SR2H       = u32_be(seed[0..4]) % (ROWS − ROWS2HASH)
fn compute_sr2h(
    rskey: &[u8; 32],
    frame_num: &[u8; 8],
    hsize_raw: u32,
    vsize: u32,
    embl: &EmblParams,
) -> Result<u32, &'static str> {
    let bpr = 2u64 * hsize_raw as u64;
    if bpr == 0 {
        return Err("hsize_raw must be non-zero");
    }

    let rows = vsize
        .checked_sub(embl.total_embl_rows())
        .ok_or("vsize is smaller than total embedding rows")?;

    // rows_to_hash = ceil(B2H × PIXEL_BLOCKS × 2 / BPR)
    // Matches Python: (B2H * pixBlocks * 2 - 1) // BPR + 1
    let numerator = (BLOCKS_TO_HASH as u64) * (PIXEL_BLOCKS as u64) * 2;
    let rows_to_hash = ((numerator - 1) / bpr + 1) as u32;

    let usable = rows
        .checked_sub(rows_to_hash)
        .filter(|&n| n > 0)
        .ok_or("ROWS − ROWS2HASH is zero or negative; frame dimensions too small")?;

    // seed = SHA-256(RSKEY ‖ frame_num)
    let mut seed_input = vec![0u8; 32 + 8];
    seed_input[..32].copy_from_slice(rskey);
    seed_input[32..].copy_from_slice(frame_num);
    let seed = sha256_one_shot(&seed_input).map_err(|_| "SHA-256 of seed failed")?;

    // First 4 bytes interpreted as big-endian u32
    let raw = u32::from_be_bytes([seed[0], seed[1], seed[2], seed[3]]);
    Ok(raw % usable)
}

// Distribute data into 4 round-robin buckets of 64-byte blocks.
fn partition_src_data(data: &[u8]) -> [Vec<u8>; 4] {
    let mut parts: [Vec<u8>; 4] =
        [Vec::new(), Vec::new(), Vec::new(), Vec::new()];
    let mut pos = 0usize;
    let mut count = 0usize;
    while pos < data.len() {
        let chunk_len = 64.min(data.len() - pos);
        parts[count % 4].extend_from_slice(&data[pos..pos + chunk_len]);
        pos += chunk_len;
        count += 1;
    }
    parts
}

// Compute SHA-256 of data using the TEE Digest API.
// Corresponds to TEE_DigestDoFinal (GP TEE Internal Core API §6.2.3).
fn sha256_one_shot(data: &[u8]) -> TeeResult<[u8; 32]> {
    let digest = Digest::allocate(AlgorithmId::Sha256)?;
    let mut hash = [0u8; 32];
    digest.do_final(data, &mut hash)?;
    Ok(hash)
}

// Compute HMAC-SHA-256(key, data) using the TEE MAC API.
// TEE_AllocateOperation(HmacSha256, TEE_MODE_MAC, 256)
// TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA256, 256)
// TEE_InitRefAttribute(TEE_ATTR_SECRET_VALUE, key)
// TEE_PopulateTransientObject(key_obj, attrs)
// TEE_SetOperationKey(op, key_obj)
// TEE_MACInit(op, NULL, 0)
// TEE_MACComputeFinal(op, data, result)
fn hmac_sha256(key: &[u8; 32], data: &[u8]) -> TeeResult<[u8; 32]> {
    const KEY_BITS: usize = 256;

    // Build a transient key object holding the HMAC-SHA-256 key.
    let mut key_obj = TransientObject::allocate(TransientObjectType::HmacSha256, KEY_BITS)?;
    let attr: Attribute = AttributeMemref::from_ref(AttributeId::SecretValue, key.as_slice()).into();
    key_obj.populate(&[attr])?;

    // Allocate the MAC operation and bind the key.
    let mac = Mac::allocate(AlgorithmId::HmacSha256, KEY_BITS)?;
    mac.set_key(&key_obj)?;
    mac.init(&[]);

    let mut result = [0u8; 32];
    mac.compute_final(data, &mut result)?;
    Ok(result)
}

// Constant-time byte-slice equality (prevents HMAC timing oracle).
fn ct_eq(a: &[u8; HMAC_LEN], b: &[u8; HMAC_LEN]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn request_from_params<T: RequestT>(params: &mut Parameters) -> TeeResult<T> {
    let mut prequest = unsafe { params.0.as_memref() }?;
    serde_json::from_slice(prequest.buffer()).map_err(|err| {
        error!("failed to deserialize request: {:?}", err);
        TeeError::new(ErrorKind::BadFormat)
    })
}

fn response_to_params<T: ResponseT>(
    response: T,
    params: &mut Parameters,
) -> TeeResult<()> {
    let mut presponse = unsafe { params.1.as_memref() }?;
    let nbytes = ResponseT::serialize(&response, presponse.buffer())
        .map_err(|BufferTooSmallErr {}| TeeError::new(ErrorKind::ShortBuffer))?;
    presponse.set_updated_size(nbytes);
    Ok(())
}

fn open_session_inner(params: &mut Parameters) -> Result<ClientInfo> {
    let client_info = validate_euid(params)?;
    debug!(
        "session opened: uuid={} login_type={} euid={}",
        client_info.uuid, client_info.login_type, client_info.effective_user_id,
    );
    Ok(client_info)
}

fn uuidv5_from_euserid(euid: u32) -> Uuid {
    const NAMESPACE: Uuid = Uuid::from_fields(
        0x58ac9ca0,
        0x2086,
        0x4683,
        &[0xa1, 0xb8, 0xec, 0x4b, 0xc0, 0x8e, 0x01, 0xb6],
    );
    Uuid::new_v5(&NAMESPACE, format!("uid={:x}", euid).as_bytes())
}

struct ClientInfo {
    uuid: Uuid,
    effective_user_id: u32,
    login_type: LoginType,
}

impl Default for ClientInfo {
    fn default() -> Self {
        Self {
            uuid: Default::default(),
            effective_user_id: Default::default(),
            login_type: LoginType::Public,
        }
    }
}

fn validate_euid(session_params: &mut Parameters) -> Result<ClientInfo> {
    let alleged_euid = unsafe { session_params.0.as_value() }
        .context("failed to get session params")?
        .a();
    let alleged_uuid = uuidv5_from_euserid(alleged_euid);
    let alleged_uuid_string = alleged_uuid.to_string();

    let identity = optee_utee::property::ClientIdentity
        .get()
        .expect("infallible");
    let login_type = identity.login_type();
    if login_type != LoginType::User {
        bail!("expected login type USER but got {}", login_type);
    }

    let optee_uuid = identity.uuid();
    let actual_uuid_string = optee_uuid.to_string();
    if alleged_uuid_string != actual_uuid_string {
        bail!(
            "alleged euid {} maps to uuid {} but actual client uuid is {}",
            alleged_euid,
            alleged_uuid_string,
            actual_uuid_string,
        );
    }

    Ok(ClientInfo {
        uuid: alleged_uuid,
        effective_user_id: alleged_euid,
        login_type,
    })
}
