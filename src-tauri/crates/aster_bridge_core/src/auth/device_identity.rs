//
// Aster Communications Inc.
//
// Copyright (c) 2026 Aster Communications Inc.
//
// This file is part of this project.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.
//
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signer, SigningKey};
use hkdf::Hkdf;
use ml_kem::array::Array;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Ciphertext, EncodedSizeUser, KemCore, MlKem768};
use rand::Rng;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::path::Path;
use subtle::ConstantTimeEq;
use uuid::Uuid;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

type MlKemDecapKey = <MlKem768 as KemCore>::DecapsulationKey;
type MlKemEncapKey = <MlKem768 as KemCore>::EncapsulationKey;

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct StoredIdentity {
    #[zeroize(skip)]
    device_id: Option<Uuid>,
    ed25519_sk_bytes: [u8; 32],
    mlkem_sk_bytes: Vec<u8>,
    mlkem_pk_bytes: Vec<u8>,
    x25519_sk_bytes: [u8; 32],
}

pub struct DeviceIdentity {
    pub device_id: Option<Uuid>,
    pub ed25519_signing_key: SigningKey,
    pub mlkem_decaps_key: MlKemDecapKey,
    pub mlkem_encaps_key_bytes: Vec<u8>,
    pub x25519_static_secret: StaticSecret,
    pub x25519_public_bytes: [u8; 32],
}

fn identity_file_path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join("device_identity.bin")
}

fn passphrase_file_path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join("device_passphrase.bin")
}

fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn b64url_decode(s: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(s.as_bytes())
        .map_err(|e| e.to_string())
}

fn set_file_permissions_restrictive(path: &Path) -> Result<(), String> {
    crate::system_tools::restrict_to_current_user(path)
}

fn restrict_legacy_file(path: &Path) {
    if let Err(e) = set_file_permissions_restrictive(path) {
        tracing::warn!("{}", e);
    }
}

const MAGIC_ID: &[u8; 8] = b"ASTERID\x01";
const MAGIC_PP: &[u8; 8] = b"ASTERPP\x01";
const KEYRING_WRAP_USER: &str = "device-identity-wrap-v1";

fn aead_seal(wrap_key: &[u8; 32], magic: &[u8; 8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let mut nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);
    let cipher = XChaCha20Poly1305::new(wrap_key.into());
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, Payload { msg: plaintext, aad: magic })
        .map_err(|e| format!("aead seal: {:?}", e))?;
    let mut out = Vec::with_capacity(8 + 24 + ct.len());
    out.extend_from_slice(magic);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn aead_open(wrap_key: &[u8; 32], magic: &[u8; 8], data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < 8 + 24 + 16 || &data[..8] != magic {
        return Err("aead open: bad header".to_string());
    }
    let nonce = XNonce::from_slice(&data[8..32]);
    let ct = &data[32..];
    let cipher = XChaCha20Poly1305::new(wrap_key.into());
    cipher
        .decrypt(nonce, Payload { msg: ct, aad: magic })
        .map_err(|e| format!("aead open: {:?}", e))
}

fn wrap_key_load() -> Result<Option<[u8; 32]>, String> {
    match crate::secrets::get(KEYRING_WRAP_USER)? {
        Some(encoded) => {
            let bytes = b64url_decode(&encoded)?;
            let key: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| "wrap key wrong size".to_string())?;
            Ok(Some(key))
        }
        None => Ok(None),
    }
}

fn wrap_key_load_or_create() -> Result<[u8; 32], String> {
    if let Some(key) = wrap_key_load()? {
        return Ok(key);
    }
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    crate::secrets::set(KEYRING_WRAP_USER, &b64url(&key))?;
    Ok(key)
}

fn wrap_key_delete() -> Result<(), String> {
    crate::secrets::delete(KEYRING_WRAP_USER)
}

fn atomic_write(path: &Path, data: &[u8]) -> Result<(), String> {
    use std::io::Write as _;
    let tmp = path.with_extension("tmp");
    let written = (|| -> Result<(), String> {
        let mut f = std::fs::File::create(&tmp).map_err(|e| e.to_string())?;
        set_file_permissions_restrictive(&tmp)?;
        f.write_all(data).map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())
    })();
    let replaced =
        written.and_then(|()| std::fs::rename(&tmp, path).map_err(|e| e.to_string()));

    if replaced.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    replaced
}

fn seal_verified(
    magic: &[u8; 8],
    plaintext: &[u8],
    wrap_key: &[u8; 32],
    reloaded_key: Option<[u8; 32]>,
) -> Result<Vec<u8>, String> {
    let reloaded = reloaded_key
        .ok_or_else(|| "wrap key did not read back from the keystore".to_string())?;
    let blob = aead_seal(wrap_key, magic, plaintext)?;
    let mut opened = aead_open(&reloaded, magic, &blob)?;
    let same = opened.as_slice() == plaintext;
    opened.zeroize();
    if !same {
        return Err("sealed copy did not read back to the same bytes".to_string());
    }
    Ok(blob)
}

fn replace_with_verified(path: &Path, blob: &[u8]) -> Result<(), String> {
    use std::io::Write as _;
    let tmp = crate::atomic_file::temp_path_beside(path);
    let written = (|| -> Result<(), String> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(|e| e.to_string())?;
        f.write_all(blob).map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
        drop(f);
        if std::fs::read(&tmp).map_err(|e| e.to_string())? != blob {
            return Err("sealed copy did not read back from disk".to_string());
        }
        set_file_permissions_restrictive(&tmp)?;
        Ok(())
    })();
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    crate::atomic_file::replace(&tmp, path)?;
    crate::atomic_file::sync_parent_dir(path);
    Ok(())
}

fn reseal_with_keys(
    path: &Path,
    magic: &[u8; 8],
    plaintext: &[u8],
    wrap_key: &[u8; 32],
    reloaded_key: Option<[u8; 32]>,
) -> Result<(), String> {
    let blob = seal_verified(magic, plaintext, wrap_key, reloaded_key)?;
    replace_with_verified(path, &blob)
}

fn reseal_legacy_file(path: &Path, magic: &[u8; 8], plaintext: &[u8]) -> Result<(), String> {
    let wrap_key = wrap_key_load_or_create()?;
    let reloaded_key = wrap_key_load()?;
    reseal_with_keys(path, magic, plaintext, &wrap_key, reloaded_key)
}

fn load_stored(data_dir: &Path) -> Result<Option<StoredIdentity>, String> {
    let path = identity_file_path(data_dir);
    if !path.exists() {
        return Ok(None);
    }
    let data = std::fs::read(&path).map_err(|e| e.to_string())?;

    if data.len() >= 8 && &data[..8] == MAGIC_ID {
        let wrap_key = wrap_key_load()?
            .ok_or_else(|| "identity locked: wrap key missing from keystore".to_string())?;
        let plaintext = aead_open(&wrap_key, MAGIC_ID, &data)?;
        let stored: StoredIdentity =
            serde_json::from_slice(&plaintext).map_err(|e| e.to_string())?;
        return Ok(Some(stored));
    }

    let mut bytes = URL_SAFE_NO_PAD.decode(&data).map_err(|e| e.to_string())?;
    let parsed = serde_json::from_slice::<StoredIdentity>(&bytes).map_err(|e| e.to_string());
    let stored = match parsed {
        Ok(stored) => stored,
        Err(e) => {
            bytes.zeroize();
            return Err(e);
        }
    };
    if let Err(e) = reseal_legacy_file(&path, MAGIC_ID, &bytes) {
        tracing::warn!("identity legacy-to-v2 migration deferred: {}", e);
        restrict_legacy_file(&path);
    }
    bytes.zeroize();
    Ok(Some(stored))
}

fn save_stored(data_dir: &Path, stored: &StoredIdentity) -> Result<(), String> {
    let path = identity_file_path(data_dir);
    let json = serde_json::to_vec(stored).map_err(|e| e.to_string())?;
    let wrap_key = wrap_key_load_or_create()?;
    let blob = aead_seal(&wrap_key, MAGIC_ID, &json)?;
    atomic_write(&path, &blob)
}

const MLKEM_SK_LEN: usize = 2400;
const MLKEM_SK_PKE_LEN: usize = 1152;
const MLKEM_PK_SEED_LEN: usize = 32;
const MLKEM_MODULUS: u16 = 3329;

fn mlkem_encaps_key_from_bytes(bytes: &[u8]) -> Result<MlKemEncapKey, String> {
    if bytes.len() != MLKEM_PK_LEN {
        return Err("mlkem public size".to_string());
    }
    let canonical = bytes[..MLKEM_PK_LEN - MLKEM_PK_SEED_LEN]
        .chunks_exact(3)
        .all(|chunk| {
            let low = u16::from(chunk[0]) | (u16::from(chunk[1] & 0x0f) << 8);
            let high = u16::from(chunk[1] >> 4) | (u16::from(chunk[2]) << 4);
            low < MLKEM_MODULUS && high < MLKEM_MODULUS
        });
    if !canonical {
        return Err("mlkem public key is not canonical".to_string());
    }
    let encoded = ml_kem::Encoded::<MlKemEncapKey>::try_from(bytes)
        .map_err(|_| "mlkem public size".to_string())?;
    Ok(MlKemEncapKey::from_bytes(&encoded))
}

fn mlkem_decaps_key_from_bytes(sk_bytes: &[u8], pk_bytes: &[u8]) -> Result<MlKemDecapKey, String> {
    if sk_bytes.len() != MLKEM_SK_LEN {
        return Err("mlkem secret size".to_string());
    }
    let encaps_key = mlkem_encaps_key_from_bytes(pk_bytes)?;
    let embedded = &sk_bytes[MLKEM_SK_PKE_LEN..MLKEM_SK_PKE_LEN + MLKEM_PK_LEN];
    if !bool::from(embedded.ct_eq(pk_bytes)) {
        return Err("mlkem key pair mismatch".to_string());
    }
    let mut encoded = ml_kem::Encoded::<MlKemDecapKey>::try_from(sk_bytes)
        .map_err(|_| "mlkem secret size".to_string())?;
    let decaps_key = MlKemDecapKey::from_bytes(&encoded);
    encoded.zeroize();

    let (ct, mut sent) = encaps_key
        .encapsulate(&mut OsRng)
        .map_err(|_| "mlkem self check".to_string())?;
    let mut received = decaps_key
        .decapsulate(&ct)
        .map_err(|_| "mlkem self check".to_string())?;
    let consistent = bool::from(sent.as_slice().ct_eq(received.as_slice()));
    sent.zeroize();
    received.zeroize();
    if !consistent {
        return Err("mlkem key pair mismatch".to_string());
    }
    Ok(decaps_key)
}

fn identity_from_stored(stored: StoredIdentity) -> Result<DeviceIdentity, String> {
    let ed25519_signing_key = SigningKey::from_bytes(&stored.ed25519_sk_bytes);
    let mlkem_decaps_key =
        mlkem_decaps_key_from_bytes(&stored.mlkem_sk_bytes, &stored.mlkem_pk_bytes)?;
    let x25519_static_secret = StaticSecret::from(stored.x25519_sk_bytes);
    let x25519_public_bytes = *XPublicKey::from(&x25519_static_secret).as_bytes();
    let mlkem_encaps_key_bytes = stored.mlkem_pk_bytes.clone();
    let device_id = stored.device_id;
    Ok(DeviceIdentity {
        device_id,
        ed25519_signing_key,
        mlkem_decaps_key,
        mlkem_encaps_key_bytes,
        x25519_static_secret,
        x25519_public_bytes,
    })
}

pub fn get_or_create_identity(data_dir: &Path) -> Result<DeviceIdentity, String> {
    if let Some(stored) = load_stored(data_dir)? {
        return identity_from_stored(stored);
    }

    let ed25519_signing_key = SigningKey::generate(&mut OsRng);
    let mut ed25519_sk_bytes = ed25519_signing_key.to_bytes();

    let (dk, ek): (MlKemDecapKey, MlKemEncapKey) = MlKem768::generate(&mut OsRng);
    let mut mlkem_sk_encoded = dk.as_bytes();
    let mlkem_sk_bytes = mlkem_sk_encoded.to_vec();
    mlkem_sk_encoded.zeroize();
    let mlkem_pk_bytes = ek.as_bytes().to_vec();

    let x25519_static_secret = StaticSecret::random_from_rng(OsRng);
    let mut x25519_sk_bytes: [u8; 32] = x25519_static_secret.to_bytes();
    let x25519_public_bytes = *XPublicKey::from(&x25519_static_secret).as_bytes();

    let stored = StoredIdentity {
        device_id: None,
        ed25519_sk_bytes,
        mlkem_sk_bytes,
        mlkem_pk_bytes: mlkem_pk_bytes.clone(),
        x25519_sk_bytes,
    };
    let save_result = save_stored(data_dir, &stored);

    ed25519_sk_bytes.zeroize();
    x25519_sk_bytes.zeroize();
    save_result?;

    Ok(DeviceIdentity {
        device_id: None,
        ed25519_signing_key,
        mlkem_decaps_key: dk,
        mlkem_encaps_key_bytes: mlkem_pk_bytes,
        x25519_static_secret,
        x25519_public_bytes,
    })
}

pub fn set_device_id(data_dir: &Path, device_id: Uuid) -> Result<(), String> {
    let mut stored = load_stored(data_dir)?.ok_or_else(|| "no device identity".to_string())?;
    stored.device_id = Some(device_id);
    save_stored(data_dir, &stored)
}

pub fn clear_device_id(data_dir: &Path) -> Result<(), String> {
    if let Some(mut stored) = load_stored(data_dir)? {
        stored.device_id = None;
        save_stored(data_dir, &stored)?;
    }
    Ok(())
}

pub fn sign_challenge(identity: &DeviceIdentity, nonce_b64: &str) -> Result<String, String> {
    sign_with_key(&identity.ed25519_signing_key, nonce_b64)
}

const DEVICE_CHALLENGE_LABEL: &[u8] = b"aster-device-challenge-v1";
const DEVICE_CHALLENGE_NONCE_LEN: usize = 32;

fn device_challenge_message(nonce: &[u8]) -> Result<Vec<u8>, String> {
    if nonce.len() != DEVICE_CHALLENGE_NONCE_LEN {
        return Err("invalid challenge length".to_string());
    }
    let mut message = Vec::with_capacity(DEVICE_CHALLENGE_LABEL.len() + nonce.len());
    message.extend_from_slice(DEVICE_CHALLENGE_LABEL);
    message.extend_from_slice(nonce);
    Ok(message)
}

pub fn sign_with_key(key: &SigningKey, nonce_b64: &str) -> Result<String, String> {
    let nonce = b64url_decode(nonce_b64)?;
    let message = device_challenge_message(&nonce)?;
    let sig = key.sign(&message);
    Ok(b64url(&sig.to_bytes()))
}

const FINGERPRINT_DOMAIN: &[u8] = b"aster-bridge-device-fingerprint-v1\0";
const FINGERPRINT_BYTES: usize = 10;

pub fn fingerprint_of_public_keys(ed25519_pk: &[u8], mlkem_pk: &[u8], x25519_pk: &[u8]) -> String {
    use sha2::Digest;

    let mut hasher = Sha256::new();
    hasher.update(FINGERPRINT_DOMAIN);
    for part in [ed25519_pk, mlkem_pk, x25519_pk] {
        hasher.update((part.len() as u32).to_be_bytes());
        hasher.update(part);
    }
    let digest = hasher.finalize();
    let hex: String = digest[..FINGERPRINT_BYTES]
        .iter()
        .map(|byte| format!("{:02X}", byte))
        .collect();
    hex.as_bytes()
        .chunks(4)
        .map(|group| std::str::from_utf8(group).unwrap_or_default())
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn device_fingerprint(identity: &DeviceIdentity) -> String {
    fingerprint_of_public_keys(
        identity.ed25519_signing_key.verifying_key().as_bytes(),
        &identity.mlkem_encaps_key_bytes,
        &identity.x25519_public_bytes,
    )
}

pub fn get_pubkeys(identity: &DeviceIdentity) -> (String, String, String) {
    let ed25519_pk = b64url(identity.ed25519_signing_key.verifying_key().as_bytes());
    let mlkem_pk = b64url(&identity.mlkem_encaps_key_bytes);
    let x25519_pk = b64url(&identity.x25519_public_bytes);
    (ed25519_pk, mlkem_pk, x25519_pk)
}

pub const ENVELOPE_VERSIONS: [u8; 2] = [1, 2];

const ENROLL_INFO_V1: &[u8] = b"astermail-device-enroll-v1";
const ENROLL_INFO_V2: &[u8] = b"astermail-device-enroll-v2";
const ENVELOPE_V2_MAGIC: &[u8; 4] = b"AEV2";
const ED25519_PK_LEN: usize = 32;
const MLKEM_PK_LEN: usize = 1184;
const MLKEM_CT_LEN: usize = 1088;
const X25519_PK_LEN: usize = 32;
const ENVELOPE_NONCE_LEN: usize = 24;
const ENVELOPE_HEADER_LEN: usize = X25519_PK_LEN + MLKEM_CT_LEN + ENVELOPE_NONCE_LEN;
const ENVELOPE_TAG_LEN: usize = 16;

pub struct EnvelopeRecipient<'a> {
    pub ed25519_pk: &'a [u8],
    pub mlkem_pk: &'a [u8],
    pub x25519_pk: &'a [u8],
}

fn envelope_v2_transcript(
    recipient: &EnvelopeRecipient<'_>,
    eph_pk: &[u8],
    mlkem_ct: &[u8],
) -> Result<[u8; 32], String> {
    use sha2::Digest;

    if recipient.ed25519_pk.len() != ED25519_PK_LEN
        || recipient.mlkem_pk.len() != MLKEM_PK_LEN
        || recipient.x25519_pk.len() != X25519_PK_LEN
    {
        return Err("envelope recipient key size".to_string());
    }
    let mut hasher = Sha256::new();
    hasher.update(ENROLL_INFO_V2);
    hasher.update(ENVELOPE_V2_MAGIC);
    hasher.update(recipient.ed25519_pk);
    hasher.update(recipient.mlkem_pk);
    hasher.update(recipient.x25519_pk);
    hasher.update(eph_pk);
    hasher.update(mlkem_ct);
    Ok(hasher.finalize().into())
}

fn envelope_key(
    ss_pq: &[u8],
    ss_cl: &[u8],
    nonce: &[u8],
    transcript: Option<&[u8; 32]>,
) -> Result<zeroize::Zeroizing<[u8; 32]>, String> {
    let mut ikm = zeroize::Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(ss_pq);
    ikm[32..].copy_from_slice(ss_cl);
    let mut info = Vec::with_capacity(ENROLL_INFO_V2.len() + 32);
    match transcript {
        Some(hash) => {
            info.extend_from_slice(ENROLL_INFO_V2);
            info.extend_from_slice(hash);
        }
        None => info.extend_from_slice(ENROLL_INFO_V1),
    }
    let mut key = zeroize::Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(nonce), ikm.as_slice())
        .expand(&info, key.as_mut_slice())
        .map_err(|e| e.to_string())?;
    Ok(key)
}

pub fn open_device_envelope(
    data: &[u8],
    recipient: &EnvelopeRecipient<'_>,
    mlkem_decaps_key: &MlKemDecapKey,
    x25519_secret: &StaticSecret,
) -> Result<Vec<u8>, String> {
    let (body, versioned) = match data.strip_prefix(ENVELOPE_V2_MAGIC.as_slice()) {
        Some(rest) => (rest, true),
        None => (data, false),
    };
    if body.len() < ENVELOPE_HEADER_LEN + ENVELOPE_TAG_LEN {
        return Err("envelope too short".to_string());
    }
    let eph_pk = &body[..X25519_PK_LEN];
    let mlkem_ct = &body[X25519_PK_LEN..X25519_PK_LEN + MLKEM_CT_LEN];
    let nonce = &body[X25519_PK_LEN + MLKEM_CT_LEN..ENVELOPE_HEADER_LEN];
    let ciphertext = &body[ENVELOPE_HEADER_LEN..];

    let transcript = if versioned {
        Some(envelope_v2_transcript(recipient, eph_pk, mlkem_ct)?)
    } else {
        None
    };

    let ct: Ciphertext<MlKem768> =
        Array::try_from(mlkem_ct).map_err(|e: _| format!("ct size: {:?}", e))?;
    let mut ss_pq = mlkem_decaps_key
        .decapsulate(&ct)
        .map_err(|e| format!("mlkem decaps: {:?}", e))?;
    let eph_bytes: [u8; 32] = eph_pk.try_into().map_err(|_| "slice")?;
    let ss_cl = x25519_secret.diffie_hellman(&XPublicKey::from(eph_bytes));
    let key = envelope_key(ss_pq.as_slice(), ss_cl.as_bytes(), nonce, transcript.as_ref());
    ss_pq.zeroize();
    drop(ss_cl);
    let key = key?;

    let cipher = XChaCha20Poly1305::new(key.as_slice().into());
    let xnonce = XNonce::from_slice(nonce);
    let opened = match transcript {
        Some(hash) => {
            let mut aad = Vec::with_capacity(ENVELOPE_V2_MAGIC.len() + hash.len());
            aad.extend_from_slice(ENVELOPE_V2_MAGIC);
            aad.extend_from_slice(&hash);
            cipher.decrypt(xnonce, Payload { msg: ciphertext, aad: &aad })
        }
        None => cipher.decrypt(xnonce, ciphertext),
    };
    opened.map_err(|e| format!("decrypt: {:?}", e))
}

pub fn unseal_vault_envelope(
    identity: &DeviceIdentity,
    envelope_b64: &str,
) -> Result<Vec<u8>, String> {
    let data = b64url_decode(envelope_b64)?;
    let ed25519_pk = identity.ed25519_signing_key.verifying_key().to_bytes();
    let recipient = EnvelopeRecipient {
        ed25519_pk: &ed25519_pk,
        mlkem_pk: &identity.mlkem_encaps_key_bytes,
        x25519_pk: &identity.x25519_public_bytes,
    };
    open_device_envelope(
        &data,
        &recipient,
        &identity.mlkem_decaps_key,
        &identity.x25519_static_secret,
    )
}

#[cfg(any(test, feature = "test-support"))]
pub fn seal_vault_envelope(
    ed25519_pk_b64: &str,
    mlkem_pk_b64: &str,
    x25519_pk_b64: &str,
    plaintext: &[u8],
    version: u8,
) -> Result<String, String> {
    if !ENVELOPE_VERSIONS.contains(&version) {
        return Err("unsupported envelope version".to_string());
    }
    let ed25519_pk = b64url_decode(ed25519_pk_b64)?;
    let mlkem_pk = b64url_decode(mlkem_pk_b64)?;
    let x25519_pk = b64url_decode(x25519_pk_b64)?;
    let recipient = EnvelopeRecipient {
        ed25519_pk: &ed25519_pk,
        mlkem_pk: &mlkem_pk,
        x25519_pk: &x25519_pk,
    };
    let ek = mlkem_encaps_key_from_bytes(&mlkem_pk)?;
    let (ct, mut ss_pq) = ek
        .encapsulate(&mut OsRng)
        .map_err(|e| format!("encapsulate: {:?}", e))?;

    let x25519_bytes: [u8; 32] = x25519_pk
        .as_slice()
        .try_into()
        .map_err(|_| "x25519 public size".to_string())?;
    let eph_secret = StaticSecret::random_from_rng(OsRng);
    let eph_public = XPublicKey::from(&eph_secret);
    let ss_cl = eph_secret.diffie_hellman(&XPublicKey::from(x25519_bytes));

    let nonce_bytes: [u8; ENVELOPE_NONCE_LEN] = OsRng.gen();

    let transcript = if version == 2 {
        Some(envelope_v2_transcript(&recipient, eph_public.as_bytes(), ct.as_slice())?)
    } else {
        None
    };
    let key = envelope_key(ss_pq.as_slice(), ss_cl.as_bytes(), &nonce_bytes, transcript.as_ref());
    ss_pq.zeroize();
    let key = key?;

    let cipher = XChaCha20Poly1305::new(key.as_slice().into());
    let xnonce = XNonce::from_slice(&nonce_bytes);
    let mut envelope = Vec::with_capacity(ENVELOPE_V2_MAGIC.len() + ENVELOPE_HEADER_LEN + plaintext.len() + ENVELOPE_TAG_LEN);
    let ciphertext = match transcript {
        Some(hash) => {
            envelope.extend_from_slice(ENVELOPE_V2_MAGIC);
            let mut aad = Vec::with_capacity(ENVELOPE_V2_MAGIC.len() + hash.len());
            aad.extend_from_slice(ENVELOPE_V2_MAGIC);
            aad.extend_from_slice(&hash);
            cipher.encrypt(xnonce, Payload { msg: plaintext, aad: &aad })
        }
        None => cipher.encrypt(xnonce, plaintext),
    }
    .map_err(|e| format!("encrypt: {:?}", e))?;

    envelope.extend_from_slice(eph_public.as_bytes());
    envelope.extend_from_slice(ct.as_slice());
    envelope.extend_from_slice(&nonce_bytes);
    envelope.extend_from_slice(&ciphertext);
    Ok(b64url(&envelope))
}

const KEYRING_USER: &str = "vault-passphrase";

fn keyring_store(passphrase: &[u8]) -> std::result::Result<(), String> {
    let mut encoded = b64url(passphrase);
    let result = crate::secrets::set(KEYRING_USER, &encoded);
    encoded.zeroize();
    result
}

fn keyring_load() -> std::result::Result<Option<Vec<u8>>, String> {
    match crate::secrets::get(KEYRING_USER)? {
        Some(mut encoded) => {
            let bytes = b64url_decode(&encoded);
            encoded.zeroize();
            bytes.map(Some)
        }
        None => Ok(None),
    }
}

fn keyring_holds(expected: &[u8]) -> bool {
    match keyring_load() {
        Ok(Some(mut stored)) => {
            let same = stored.as_slice() == expected;
            stored.zeroize();
            same
        }
        _ => false,
    }
}

fn keyring_delete() -> std::result::Result<(), String> {
    crate::secrets::delete(KEYRING_USER)
}

pub fn store_passphrase(data_dir: &Path, passphrase: &[u8]) -> Result<(), String> {
    if keyring_store(passphrase).is_ok() && keyring_holds(passphrase) {
        let path = passphrase_file_path(data_dir);
        if path.exists() {
            let _ = std::fs::remove_file(&path);
        }
        return Ok(());
    }

    let path = passphrase_file_path(data_dir);
    let wrap_key = wrap_key_load_or_create()?;
    let blob = aead_seal(&wrap_key, MAGIC_PP, passphrase)?;
    atomic_write(&path, &blob)
}

pub fn load_passphrase(data_dir: &Path) -> Result<Option<Vec<u8>>, String> {
    if let Ok(Some(bytes)) = keyring_load() {
        return Ok(Some(bytes));
    }

    let path = passphrase_file_path(data_dir);
    if !path.exists() {
        return Ok(None);
    }
    let data = std::fs::read(&path).map_err(|e| e.to_string())?;

    let was_sealed = data.len() >= 8 && &data[..8] == MAGIC_PP;
    let bytes = if was_sealed {
        let wrap_key = wrap_key_load()?
            .ok_or_else(|| "passphrase locked: wrap key missing from keystore".to_string())?;
        aead_open(&wrap_key, MAGIC_PP, &data)?
    } else {
        let s = std::str::from_utf8(&data).map_err(|e| e.to_string())?;
        b64url_decode(s)?
    };

    if keyring_store(&bytes).is_ok() && keyring_holds(&bytes) {
        let _ = std::fs::remove_file(&path);
    } else if !was_sealed {
        if let Err(e) = reseal_legacy_file(&path, MAGIC_PP, &bytes) {
            tracing::warn!(
                "could not re-seal legacy passphrase file; it remains in plaintext on disk: {}",
                e
            );
            restrict_legacy_file(&path);
        }
    }

    Ok(Some(bytes))
}

pub fn clear_passphrase(data_dir: &Path) {
    let _ = keyring_delete();
    let path = passphrase_file_path(data_dir);
    if path.exists() {
        let _ = std::fs::remove_file(&path);
    }
}

pub fn clear_identity(data_dir: &Path) {
    let path = identity_file_path(data_dir);
    if path.exists() {
        let _ = std::fs::remove_file(&path);
    }
    let _ = wrap_key_delete();
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Verifier, VerifyingKey};

    #[test]
    fn the_device_fingerprint_matches_the_published_vector() {
        let fingerprint = fingerprint_of_public_keys(&[1u8; 32], &[2u8; 1184], &[3u8; 32]);
        assert_eq!(fingerprint, "9B16 AF79 0A6A E2F2 55D3");
    }

    #[test]
    fn the_device_fingerprint_changes_with_any_public_key() {
        let base = fingerprint_of_public_keys(&[1u8; 32], &[2u8; 1184], &[3u8; 32]);
        assert_eq!(base.len(), 24);
        assert_ne!(base, fingerprint_of_public_keys(&[9u8; 32], &[2u8; 1184], &[3u8; 32]));
        assert_ne!(base, fingerprint_of_public_keys(&[1u8; 32], &[9u8; 1184], &[3u8; 32]));
        assert_ne!(base, fingerprint_of_public_keys(&[1u8; 32], &[2u8; 1184], &[9u8; 32]));
        assert_ne!(base, fingerprint_of_public_keys(&[1u8; 32], &[2u8; 1183], &[3u8; 33]));
    }

    #[test]
    fn b64url_round_trips_arbitrary_bytes() {
        let data = [0u8, 1, 2, 250, 255, 128, 64];
        let encoded = b64url(&data);
        assert!(!encoded.contains('='));
        let decoded = b64url_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn b64url_decode_rejects_invalid_input() {
        assert!(b64url_decode("####not base64####").is_err());
    }

    #[test]
    fn aead_seal_open_round_trips() {
        let key = [7u8; 32];
        let plaintext = b"device identity secret bytes";
        let sealed = aead_seal(&key, MAGIC_ID, plaintext).unwrap();
        assert_eq!(&sealed[..8], MAGIC_ID);
        let opened = aead_open(&key, MAGIC_ID, &sealed).unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn aead_open_wrong_key_fails_without_panic() {
        let sealed = aead_seal(&[1u8; 32], MAGIC_PP, b"secret").unwrap();
        assert!(aead_open(&[2u8; 32], MAGIC_PP, &sealed).is_err());
    }

    #[test]
    fn aead_open_wrong_magic_aad_fails() {
        let sealed = aead_seal(&[3u8; 32], MAGIC_ID, b"secret").unwrap();
        assert!(aead_open(&[3u8; 32], MAGIC_PP, &sealed).is_err());
    }

    #[test]
    fn aead_open_tampered_ciphertext_fails() {
        let key = [4u8; 32];
        let mut sealed = aead_seal(&key, MAGIC_ID, b"authentic payload").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0xff;
        assert!(aead_open(&key, MAGIC_ID, &sealed).is_err());
    }

    #[test]
    fn aead_open_short_input_is_rejected() {
        assert!(aead_open(&[0u8; 32], MAGIC_ID, b"tiny").is_err());
    }

    fn temp_leftovers(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect()
    }

    #[test]
    fn legacy_identity_file_is_resealed_after_it_reads_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = identity_file_path(dir.path());
        let json = br#"{"device_id":null}"#;
        std::fs::write(&path, b64url(json)).unwrap();

        let key = [21u8; 32];
        reseal_with_keys(&path, MAGIC_ID, json, &key, Some(key)).unwrap();

        let sealed = std::fs::read(&path).unwrap();
        assert_eq!(&sealed[..8], MAGIC_ID);
        assert_eq!(aead_open(&key, MAGIC_ID, &sealed).unwrap(), json);
        assert!(temp_leftovers(dir.path()).is_empty());
    }

    #[test]
    fn legacy_passphrase_file_is_resealed_after_it_reads_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = passphrase_file_path(dir.path());
        let passphrase = b"correct horse battery staple";
        std::fs::write(&path, b64url(passphrase)).unwrap();

        let key = [22u8; 32];
        reseal_with_keys(&path, MAGIC_PP, passphrase, &key, Some(key)).unwrap();

        let sealed = std::fs::read(&path).unwrap();
        assert_eq!(aead_open(&key, MAGIC_PP, &sealed).unwrap(), passphrase);
    }

    #[test]
    fn a_wrap_key_that_reads_back_differently_keeps_the_legacy_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = passphrase_file_path(dir.path());
        let passphrase = b"correct horse battery staple";
        let legacy = b64url(passphrase);
        std::fs::write(&path, &legacy).unwrap();

        assert!(reseal_with_keys(&path, MAGIC_PP, passphrase, &[23u8; 32], Some([24u8; 32])).is_err());
        assert!(reseal_with_keys(&path, MAGIC_PP, passphrase, &[23u8; 32], None).is_err());

        assert_eq!(std::fs::read(&path).unwrap(), legacy.as_bytes());
        assert!(temp_leftovers(dir.path()).is_empty());
    }

    #[test]
    fn a_failed_replace_keeps_the_original_and_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("occupied");
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("child"), b"legacy").unwrap();

        let key = [25u8; 32];
        assert!(reseal_with_keys(&path, MAGIC_ID, b"payload", &key, Some(key)).is_err());

        assert_eq!(std::fs::read(path.join("child")).unwrap(), b"legacy");
        assert!(temp_leftovers(dir.path()).is_empty());
    }

    fn test_identity() -> DeviceIdentity {
        let ed25519_signing_key = SigningKey::generate(&mut OsRng);
        let (dk, ek): (MlKemDecapKey, MlKemEncapKey) = MlKem768::generate(&mut OsRng);
        let x25519_static_secret = StaticSecret::random_from_rng(OsRng);
        let x25519_public_bytes = *XPublicKey::from(&x25519_static_secret).as_bytes();
        DeviceIdentity {
            device_id: None,
            ed25519_signing_key,
            mlkem_decaps_key: dk,
            mlkem_encaps_key_bytes: ek.as_bytes().to_vec(),
            x25519_static_secret,
            x25519_public_bytes,
        }
    }

    fn seal_for(identity: &DeviceIdentity, plaintext: &[u8], version: u8) -> String {
        let (ed25519_pk, mlkem_pk, x25519_pk) = get_pubkeys(identity);
        seal_vault_envelope(&ed25519_pk, &mlkem_pk, &x25519_pk, plaintext, version).unwrap()
    }

    fn reencode(envelope: &str, edit: impl FnOnce(&mut Vec<u8>)) -> String {
        let mut bytes = b64url_decode(envelope).unwrap();
        edit(&mut bytes);
        b64url(&bytes)
    }

    fn vector() -> std::collections::HashMap<String, String> {
        include_str!("../../tests/fixtures/device_envelope_vector.txt")
            .lines()
            .filter(|line| !line.trim().is_empty())
            .filter_map(|line| line.split_once('='))
            .map(|(key, value)| (key.to_string(), value.trim().to_string()))
            .collect()
    }

    fn vector_bytes(vector: &std::collections::HashMap<String, String>, key: &str) -> Vec<u8> {
        b64url_decode(&vector[key]).unwrap()
    }

    fn vector_keys(
        vector: &std::collections::HashMap<String, String>,
    ) -> (MlKemDecapKey, StaticSecret) {
        let decaps = mlkem_decaps_key_from_bytes(
            &vector_bytes(vector, "mlkem_decaps"),
            &vector_bytes(vector, "mlkem_pk"),
        )
        .unwrap();
        let scalar: [u8; 32] = vector_bytes(vector, "x25519_scalar").try_into().unwrap();
        (decaps, StaticSecret::from(scalar))
    }

    fn open_vector(
        vector: &std::collections::HashMap<String, String>,
        envelope: &[u8],
        ed25519_pk: &[u8],
    ) -> Result<Vec<u8>, String> {
        let (decaps, scalar) = vector_keys(vector);
        let mlkem_pk = vector_bytes(vector, "mlkem_pk");
        let x25519_pk = vector_bytes(vector, "x25519_pk");
        let recipient = EnvelopeRecipient {
            ed25519_pk,
            mlkem_pk: &mlkem_pk,
            x25519_pk: &x25519_pk,
        };
        open_device_envelope(envelope, &recipient, &decaps, &scalar)
    }

    #[test]
    fn sealed_envelope_opens_with_the_device_keys() {
        let identity = test_identity();
        for version in ENVELOPE_VERSIONS {
            let envelope = seal_for(&identity, b"vault-passphrase", version);
            assert_eq!(unseal_vault_envelope(&identity, &envelope).unwrap(), b"vault-passphrase");
            let other = test_identity();
            assert!(unseal_vault_envelope(&other, &envelope).is_err());
        }
    }

    #[test]
    fn a_v2_envelope_carries_the_version_magic() {
        let identity = test_identity();
        let envelope = b64url_decode(&seal_for(&identity, b"vault-passphrase", 2)).unwrap();
        assert_eq!(&envelope[..4], b"AEV2");
        assert_eq!(envelope.len(), 4 + ENVELOPE_HEADER_LEN + b"vault-passphrase".len() + ENVELOPE_TAG_LEN);
    }

    #[test]
    fn a_v2_envelope_sealed_to_other_signing_key_is_refused() {
        let identity = test_identity();
        let (_, mlkem_pk, x25519_pk) = get_pubkeys(&identity);
        let stranger = b64url(SigningKey::generate(&mut OsRng).verifying_key().as_bytes());
        let envelope =
            seal_vault_envelope(&stranger, &mlkem_pk, &x25519_pk, b"vault-passphrase", 2).unwrap();
        assert!(unseal_vault_envelope(&identity, &envelope).is_err());
    }

    #[test]
    fn a_v2_envelope_with_a_swapped_ephemeral_key_is_refused() {
        let identity = test_identity();
        let envelope = seal_for(&identity, b"vault-passphrase", 2);
        let other = seal_for(&identity, b"vault-passphrase", 2);
        let other_bytes = b64url_decode(&other).unwrap();
        let spliced = reencode(&envelope, |bytes| {
            bytes[4..4 + X25519_PK_LEN].copy_from_slice(&other_bytes[4..4 + X25519_PK_LEN]);
        });
        assert!(unseal_vault_envelope(&identity, &spliced).is_err());
    }

    #[test]
    fn a_v2_envelope_with_any_flipped_byte_is_refused() {
        let identity = test_identity();
        let envelope = seal_for(&identity, b"vault-passphrase", 2);
        let length = b64url_decode(&envelope).unwrap().len();
        for index in [0, 3, 4, 4 + X25519_PK_LEN, 4 + X25519_PK_LEN + MLKEM_CT_LEN, length - 1] {
            let tampered = reencode(&envelope, |bytes| bytes[index] ^= 0x01);
            assert!(unseal_vault_envelope(&identity, &tampered).is_err(), "byte {index}");
        }
    }

    #[test]
    fn a_v2_envelope_stripped_of_its_magic_does_not_open_as_v1() {
        let identity = test_identity();
        let envelope = seal_for(&identity, b"vault-passphrase", 2);
        let stripped = reencode(&envelope, |bytes| {
            bytes.drain(..4);
        });
        assert!(unseal_vault_envelope(&identity, &stripped).is_err());
    }

    #[test]
    fn a_v1_envelope_given_the_v2_magic_is_refused() {
        let identity = test_identity();
        let envelope = seal_for(&identity, b"vault-passphrase", 1);
        let relabeled = reencode(&envelope, |bytes| {
            bytes.splice(0..0, b"AEV2".iter().copied());
        });
        assert!(unseal_vault_envelope(&identity, &relabeled).is_err());
    }

    #[test]
    fn a_short_v2_envelope_is_refused() {
        let identity = test_identity();
        let mut short = b"AEV2".to_vec();
        short.extend_from_slice(&[0u8; ENVELOPE_HEADER_LEN + ENVELOPE_TAG_LEN - 1]);
        assert!(unseal_vault_envelope(&identity, &b64url(&short)).is_err());
    }

    #[test]
    fn an_unknown_envelope_version_is_not_sealed() {
        let identity = test_identity();
        let (ed25519_pk, mlkem_pk, x25519_pk) = get_pubkeys(&identity);
        assert!(seal_vault_envelope(&ed25519_pk, &mlkem_pk, &x25519_pk, b"x", 3).is_err());
    }

    #[test]
    fn the_shared_vector_keys_pass_validation() {
        let vector = vector();
        assert!(mlkem_decaps_key_from_bytes(
            &vector_bytes(&vector, "mlkem_decaps"),
            &vector_bytes(&vector, "mlkem_pk"),
        )
        .is_ok());
    }

    #[test]
    fn a_decaps_key_must_match_its_public_key() {
        let (dk, ek): (MlKemDecapKey, MlKemEncapKey) = MlKem768::generate(&mut OsRng);
        let (_, other_ek): (MlKemDecapKey, MlKemEncapKey) = MlKem768::generate(&mut OsRng);
        let sk = dk.as_bytes().to_vec();
        assert!(mlkem_decaps_key_from_bytes(&sk, ek.as_bytes().as_slice()).is_ok());
        assert!(mlkem_decaps_key_from_bytes(&sk, other_ek.as_bytes().as_slice()).is_err());
    }

    #[test]
    fn a_damaged_decaps_key_is_refused() {
        let (dk, ek): (MlKemDecapKey, MlKemEncapKey) = MlKem768::generate(&mut OsRng);
        let sk = dk.as_bytes().to_vec();
        let pk = ek.as_bytes().to_vec();
        let hash_offset = MLKEM_SK_PKE_LEN + MLKEM_PK_LEN;
        for offset in [0, MLKEM_SK_PKE_LEN, hash_offset] {
            let mut damaged = sk.clone();
            damaged[offset] ^= 0xff;
            assert!(
                mlkem_decaps_key_from_bytes(&damaged, &pk).is_err(),
                "offset {offset}"
            );
        }
        assert!(mlkem_decaps_key_from_bytes(&sk[..MLKEM_SK_LEN - 1], &pk).is_err());
        assert!(mlkem_decaps_key_from_bytes(&[], &pk).is_err());
        assert!(mlkem_decaps_key_from_bytes(&sk, &pk[..MLKEM_PK_LEN - 1]).is_err());
    }

    #[test]
    fn a_public_key_with_an_out_of_range_coefficient_is_refused() {
        let identity = test_identity();
        let (ed25519_pk, _, x25519_pk) = get_pubkeys(&identity);
        let mut pk = identity.mlkem_encaps_key_bytes.clone();
        assert!(mlkem_encaps_key_from_bytes(&pk).is_ok());
        pk[0] = 0xff;
        pk[1] |= 0x0f;
        assert!(mlkem_encaps_key_from_bytes(&pk).is_err());
        assert!(seal_vault_envelope(&ed25519_pk, &b64url(&pk), &x25519_pk, b"x", 2).is_err());
    }

    #[test]
    fn a_stored_identity_with_mismatched_keys_does_not_load() {
        let (dk, _): (MlKemDecapKey, MlKemEncapKey) = MlKem768::generate(&mut OsRng);
        let (_, other_ek): (MlKemDecapKey, MlKemEncapKey) = MlKem768::generate(&mut OsRng);
        let stored = StoredIdentity {
            device_id: None,
            ed25519_sk_bytes: [1u8; 32],
            mlkem_sk_bytes: dk.as_bytes().to_vec(),
            mlkem_pk_bytes: other_ek.as_bytes().to_vec(),
            x25519_sk_bytes: [2u8; 32],
        };
        assert!(identity_from_stored(stored).is_err());
    }

    #[test]
    fn the_shared_vectors_do_not_open_once_altered() {
        let vector = vector();
        let ed25519_pk = vector_bytes(&vector, "ed25519_pk");
        for (name, prefix) in [("envelope", 0), ("envelope_v2", ENVELOPE_V2_MAGIC.len())] {
            let envelope = vector_bytes(&vector, name);
            let offsets = [
                prefix,
                prefix + X25519_PK_LEN,
                prefix + X25519_PK_LEN + MLKEM_CT_LEN - 1,
                prefix + X25519_PK_LEN + MLKEM_CT_LEN,
                prefix + ENVELOPE_HEADER_LEN,
                envelope.len() - 1,
            ];
            for offset in offsets {
                let mut altered = envelope.clone();
                altered[offset] ^= 0x01;
                assert!(
                    open_vector(&vector, &altered, &ed25519_pk).is_err(),
                    "{name} offset {offset}"
                );
            }
            assert!(open_vector(&vector, &envelope[..envelope.len() - 1], &ed25519_pk).is_err());
            assert!(open_vector(&vector, &envelope[..prefix + ENVELOPE_HEADER_LEN], &ed25519_pk).is_err());
        }
    }

    #[test]
    fn the_shared_v1_vector_opens() {
        let vector = vector();
        let opened = open_vector(&vector, &vector_bytes(&vector, "envelope"), &[0u8; 32]).unwrap();
        assert_eq!(opened, vector["plaintext"].as_bytes());
    }

    #[test]
    fn the_shared_v2_vector_opens_only_for_its_recipient() {
        let vector = vector();
        let envelope = vector_bytes(&vector, "envelope_v2");
        let ed25519_pk = vector_bytes(&vector, "ed25519_pk");
        let opened = open_vector(&vector, &envelope, &ed25519_pk).unwrap();
        assert_eq!(opened, vector["plaintext"].as_bytes());
        let mut other_pk = ed25519_pk.clone();
        other_pk[0] ^= 0x01;
        assert!(open_vector(&vector, &envelope, &other_pk).is_err());
    }

    #[test]
    fn sign_challenge_produces_verifiable_signature() {
        let identity = test_identity();
        let nonce_raw = [9u8; 32];
        let nonce_b64 = b64url(&nonce_raw);
        let sig_b64 = sign_challenge(&identity, &nonce_b64).unwrap();

        let sig_bytes = b64url_decode(&sig_b64).unwrap();
        let sig = ed25519_dalek::Signature::from_slice(&sig_bytes).unwrap();
        let verifying: VerifyingKey = identity.ed25519_signing_key.verifying_key();
        let mut labeled = b"aster-device-challenge-v1".to_vec();
        labeled.extend_from_slice(&nonce_raw);
        assert!(verifying.verify_strict(&labeled, &sig).is_ok());
        assert!(verifying.verify_strict(&nonce_raw, &sig).is_err());
    }

    #[test]
    fn sign_challenge_rejects_wrong_nonce_length() {
        let identity = test_identity();
        for len in [0usize, 1, 16, 31, 33, 64, 4096] {
            let nonce_b64 = b64url(&vec![3u8; len]);
            assert!(sign_challenge(&identity, &nonce_b64).is_err());
        }
    }

    #[test]
    fn signature_fails_verification_for_wrong_message() {
        let identity = test_identity();
        let nonce_b64 = b64url(&[1u8; 32]);
        let sig_b64 = sign_challenge(&identity, &nonce_b64).unwrap();
        let sig_bytes = b64url_decode(&sig_b64).unwrap();
        let sig = ed25519_dalek::Signature::from_slice(&sig_bytes).unwrap();
        let verifying = identity.ed25519_signing_key.verifying_key();
        assert!(verifying.verify(&[2u8; 32], &sig).is_err());
    }

    #[test]
    fn sign_challenge_rejects_invalid_nonce_encoding() {
        let identity = test_identity();
        assert!(sign_challenge(&identity, "###not base64###").is_err());
    }

    #[test]
    fn get_pubkeys_returns_well_formed_keys() {
        let identity = test_identity();
        let (ed_pk, mlkem_pk, x25519_pk) = get_pubkeys(&identity);

        assert_eq!(b64url_decode(&ed_pk).unwrap().len(), 32);
        assert_eq!(b64url_decode(&x25519_pk).unwrap().len(), 32);
        assert!(!b64url_decode(&mlkem_pk).unwrap().is_empty());
    }

    #[test]
    fn unseal_vault_envelope_rejects_short_envelope() {
        let identity = test_identity();
        let short = b64url(&[0u8; 16]);
        assert!(unseal_vault_envelope(&identity, &short).is_err());
    }
}
