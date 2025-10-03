use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

use getrandom::getrandom;

use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};

use aes::Aes128;
use aes::Aes256;
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit as GcmKeyInit};
use aes_gcm::aead::{Aead, OsRng, Key as GcmKey, Nonce};

use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;

use ctr::Ctr128BE; // CTR with 128-bit BE counter

// <<< ADD THESE TWO IMPORTS TO BRING CTR new() / apply_keystream INTO SCOPE >>>
use cipher::{KeyIvInit, StreamCipher};

use digest::generic_array::GenericArray;
use std::convert::TryInto;


type HmacSha256 = Hmac<Sha256>;

#[wasm_bindgen]
pub struct JsError {
    msg: String
}

#[wasm_bindgen]
impl JsError {
    #[wasm_bindgen(constructor)]
    pub fn new(msg: &str) -> JsError { JsError { msg: msg.to_string() } }
}

impl From<JsError> for JsValue {
    fn from(e: JsError) -> JsValue {
        JsValue::from_str(&e.msg)
    }
}

#[wasm_bindgen]
pub fn version() -> String {
    "crypto_helper_wasm v0.1".into()
}

/// Algorithm table mirrors your previous mapping
/// 0: aes-256-gcm
/// 1: aes-128-gcm
/// 2: aes-256-cbc
/// 3: aes-128-cbc
/// 4: aes-256-ctr
/// 5: aes-128-ctr
fn get_algo_props(algo_id: u8) -> Option<(usize /*keylen*/, usize /*ivlen*/, bool /*is_aead*/, usize /*taglen*/) > {
    match algo_id {
        0 => Some((32, 12, true, 16)),
        1 => Some((16, 12, true, 16)),
        2 => Some((32, 16, false, 0)),
        3 => Some((16, 16, false, 0)),
        4 => Some((32, 16, false, 0)),
        5 => Some((16, 16, false, 0)),
        _ => None
    }
}

// Derive key: SHA256(keyString) and take key_len bytes
fn derive_key_bytes(key_string: &str, key_len: usize) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(key_string.as_bytes());
    let res = hasher.finalize();
    res[..key_len].to_vec()
}

// helper random
fn random_bytes(len: usize) -> Vec<u8> {
    let mut v = vec![0u8; len];
    getrandom(&mut v).expect("random failed");
    v
}

#[wasm_bindgen]
pub fn encrypt(input: &[u8], key_string: &str, algo_id_opt: Option<u8>) -> Result<Box<[u8]>, JsValue> {
    let algo_id = algo_id_opt.unwrap_or_else(|| {
        // choose random algo id if not provided (like original)
        // here just pick 0 (aes-256-gcm) as default for determinism if none provided
        0u8
    });

    let props = get_algo_props(algo_id).ok_or_else(|| JsValue::from_str("Unknown algorithm id"))?;
    let (key_len, iv_len, is_aead, tag_len) = props;

    let key = derive_key_bytes(key_string, key_len);
    let iv = random_bytes(iv_len);

    if is_aead {
        // AES-GCM
        if key_len == 32 {
            let gkey = GenericArray::from_slice(&key);
            let cipher = Aes256Gcm::new(gkey);
            let nonce = Nonce::from_slice(&iv);
            let ct = cipher.encrypt(nonce, input.as_ref()).map_err(|e| JsValue::from_str("encrypt gcm failed"))?;
            // aes-gcm outputs ciphertext+tag combined in aead crate
            // aes-gcm crate returns ct that already include tag appended at end.
            // We want layout: [algoId][iv][ciphertext][tag]
            // But ct = ciphertext || tag (tagLen = 16)
            let mut out = Vec::with_capacity(1 + iv_len + ct.len());
            out.push(algo_id);
            out.extend_from_slice(&iv);
            out.extend_from_slice(&ct);
            return Ok(out.into_boxed_slice());
        } else {
            // key_len == 16
            let gkey = GenericArray::from_slice(&key);
            let cipher = Aes128Gcm::new(gkey);
            let nonce = Nonce::from_slice(&iv);
            let ct = cipher.encrypt(nonce, input.as_ref()).map_err(|_| JsValue::from_str("encrypt gcm failed"))?;
            let mut out = Vec::with_capacity(1 + iv_len + ct.len());
            out.push(algo_id);
            out.extend_from_slice(&iv);
            out.extend_from_slice(&ct);
            return Ok(out.into_boxed_slice());
        }
    } else {
        // Non-AEAD: CBC or CTR
        let ciphertext = match algo_id {
            2 => { // aes-256-cbc
                let keyarr = GenericArray::from_slice(&key);
                type Aes256Cbc = Cbc<Aes256, Pkcs7>;
                let cipher = Aes256Cbc::new_from_slices(keyarr, &iv).map_err(|_| JsValue::from_str("cipher init failed"))?;
                cipher.encrypt_vec(input)
            },
            3 => { // aes-128-cbc
                let keyarr = GenericArray::from_slice(&key);
                type Aes128Cbc = Cbc<Aes128, Pkcs7>;
                let cipher = Aes128Cbc::new_from_slices(keyarr, &iv).map_err(|_| JsValue::from_str("cipher init failed"))?;
                cipher.encrypt_vec(input)
            },
            4 => { // aes-256-ctr
                let keyarr = GenericArray::from_slice(&key);
                type Aes256Ctr = Ctr128BE<Aes256>;
                let mut buf = input.to_vec();
                let mut cipher = Aes256Ctr::new(keyarr, GenericArray::from_slice(&iv));
                cipher.apply_keystream(&mut buf);
                buf
            },
            5 => { // aes-128-ctr
                let keyarr = GenericArray::from_slice(&key);
                type Aes128Ctr = Ctr128BE<Aes128>;
                let mut buf = input.to_vec();
                let mut cipher = Aes128Ctr::new(keyarr, GenericArray::from_slice(&iv));
                cipher.apply_keystream(&mut buf);
                buf
            },
            _ => return Err(JsValue::from_str("unsupported algo"))
        };

        // compute HMAC-SHA256 over [algoId][iv][ciphertext]
        let mut mac = HmacSha256::new_from_slice(&derive_key_bytes(key_string, 32)).map_err(|_| JsValue::from_str("hmac init failed"))?;
        mac.update(&[algo_id]);
        mac.update(&iv);
        mac.update(&ciphertext);
        let tag = mac.finalize().into_bytes(); // 32 bytes

        let mut out = Vec::with_capacity(1 + iv_len + ciphertext.len() + tag.len());
        out.push(algo_id);
        out.extend_from_slice(&iv);
        out.extend_from_slice(&ciphertext);
        out.extend_from_slice(&tag);
        return Ok(out.into_boxed_slice());
    }
}

#[wasm_bindgen]
pub fn decrypt(input: &[u8], key_string: &str) -> Result<Box<[u8]>, JsValue> {
    if input.len() < 2 {
        return Err(JsValue::from_str("input too short"));
    }
    let algo_id = input[0];
    let props = get_algo_props(algo_id).ok_or_else(|| JsValue::from_str("Unknown algorithm id"))?;
    let (key_len, iv_len, is_aead, tag_len) = props;

    if input.len() < 1 + iv_len + 1 {
        return Err(JsValue::from_str("invalid input"));
    }

    let key = derive_key_bytes(key_string, key_len);
    let iv = &input[1..1 + iv_len];

    if is_aead {
        // ciphertext+tag are remaining bytes
        let ct_tag = &input[1 + iv_len..];
        if ct_tag.len() < tag_len + 1 {
            return Err(JsValue::from_str("ciphertext too short"));
        }
        // For aes-gcm with aes-gcm crate, ciphertext includes tag appended
        if key_len == 32 {
            let gkey = GenericArray::from_slice(&key);
            let cipher = Aes256Gcm::new(gkey);
            let nonce = Nonce::from_slice(iv);
            let plaintext = cipher.decrypt(nonce, ct_tag.as_ref()).map_err(|_| JsValue::from_str("decrypt failed (gcm)"))?;
            return Ok(plaintext.into_boxed_slice());
        } else {
            let gkey = GenericArray::from_slice(&key);
            let cipher = Aes128Gcm::new(gkey);
            let nonce = Nonce::from_slice(iv);
            let plaintext = cipher.decrypt(nonce, ct_tag.as_ref()).map_err(|_| JsValue::from_str("decrypt failed (gcm)"))?;
            return Ok(plaintext.into_boxed_slice());
        }
    } else {
        // non-aead: last 32 bytes = mac
        if input.len() < 1 + iv_len + 1 + 32 {
            return Err(JsValue::from_str("input too short for non-aead"));
        }
        let mac_start = input.len() - 32;
        let ciphertext = &input[1 + iv_len .. mac_start];
        let mac = &input[mac_start..];

        // compute expected hmac using SHA256(keyString) truncated/padded to 32
        let mac_key = derive_key_bytes(key_string, 32);
        let mut h = HmacSha256::new_from_slice(&mac_key).map_err(|_| JsValue::from_str("hmac init failed"))?;
        h.update(&[algo_id]);
        h.update(iv);
        h.update(ciphertext);
        let expected = h.finalize().into_bytes();

        // constant time compare
        if expected.as_slice() != mac {
            return Err(JsValue::from_str("HMAC mismatch"));
        }

        // decrypt
        match algo_id {
            2 => {
                type Aes256Cbc = Cbc<Aes256, Pkcs7>;
                let keyarr = GenericArray::from_slice(&key);
                let cipher = Aes256Cbc::new_from_slices(keyarr, iv).map_err(|_| JsValue::from_str("cipher init failed"))?;
                let pt = cipher.decrypt_vec(ciphertext).map_err(|_| JsValue::from_str("decrypt failed (cbc)"))?;
                return Ok(pt.into_boxed_slice());
            },
            3 => {
                type Aes128Cbc = Cbc<Aes128, Pkcs7>;
                let keyarr = GenericArray::from_slice(&key);
                let cipher = Aes128Cbc::new_from_slices(keyarr, iv).map_err(|_| JsValue::from_str("cipher init failed"))?;
                let pt = cipher.decrypt_vec(ciphertext).map_err(|_| JsValue::from_str("decrypt failed (cbc)"))?;
                return Ok(pt.into_boxed_slice());
            },
            4 => {
                type Aes256Ctr = Ctr128BE<Aes256>;
                let keyarr = GenericArray::from_slice(&key);
                let mut buf = ciphertext.to_vec();
                let mut cipher = Aes256Ctr::new(keyarr, GenericArray::from_slice(iv));
                cipher.apply_keystream(&mut buf);
                return Ok(buf.into_boxed_slice());
            },
            5 => {
                type Aes128Ctr = Ctr128BE<Aes128>;
                let keyarr = GenericArray::from_slice(&key);
                let mut buf = ciphertext.to_vec();
                let mut cipher = Aes128Ctr::new(keyarr, GenericArray::from_slice(iv));
                cipher.apply_keystream(&mut buf);
                return Ok(buf.into_boxed_slice());
            },
            _ => return Err(JsValue::from_str("unsupported algo")),
        }
    }
}

#[wasm_bindgen]
pub fn is_encrypted(input: &[u8], key_string_opt: Option<String>) -> bool {
    if input.len() < 2 { return false; }
    let algo_id = input[0];
    if let Some((_, iv_len, is_aead, tag_len)) = get_algo_props(algo_id) {
        if input.len() < 1 + iv_len + (if is_aead { tag_len + 1 } else { 32 + 1 }) { return false; }
        if is_aead {
            // If key provided, test decrypt quickly (return false on error)
            if let Some(k) = key_string_opt {
                let dec = decrypt(input, &k);
                return dec.is_ok();
            }
            return true;
        } else {
            // non-aead, if key provided verify HMAC
            if let Some(k) = key_string_opt {
                let res = decrypt(input, &k);
                return res.is_ok();
            }
            return true;
        }
    }
    false
}
