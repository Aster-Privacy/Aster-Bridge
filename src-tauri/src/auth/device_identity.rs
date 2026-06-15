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
use ml_kem::kem::Decapsulate;
use ml_kem::{Ciphertext, EncodedSizeUser, KemCore, MlKem768};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::path::Path;
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
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, perms).map_err(|e| e.to_string())?;
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let user = whoami::fallible::username()
            .unwrap_or_else(|_| std::env::var("USERNAME").unwrap_or_default());
        if !user.is_empty() {
            match std::process::Command::new("icacls")
                .args([
                    &path.to_string_lossy().to_string(),
                    "/inheritance:r",
                    "/grant:r",
                    &format!("{}:(F)", user),
                ])
                .creation_flags(0x0800_0000)
                .output()
            {
                Ok(out) if !out.status.success() => {
                    tracing::warn!(
                        "icacls failed to restrict {}: {}",
                        path.display(),
                        String::from_utf8_lossy(&out.stderr).trim()
                    );
                }
                Err(e) => tracing::warn!("icacls invocation failed for {}: {}", path.display(), e),
                _ => {}
            }
        }
    }
    let _ = path;
    Ok(())
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
    let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_WRAP_USER)
        .map_err(|e| format!("keyring init: {}", e))?;
    match entry.get_password() {
        Ok(encoded) => {
            let bytes = b64url_decode(&encoded)?;
            let key: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| "wrap key wrong size".to_string())?;
            Ok(Some(key))
        }
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(format!("keyring get: {}", e)),
    }
}

fn wrap_key_load_or_create() -> Result<[u8; 32], String> {
    if let Some(key) = wrap_key_load()? {
        return Ok(key);
    }
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_WRAP_USER)
        .map_err(|e| format!("keyring init: {}", e))?;
    entry
        .set_password(&b64url(&key))
        .map_err(|e| format!("keyring set wrap: {}", e))?;
    Ok(key)
}

fn wrap_key_delete() -> Result<(), String> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_WRAP_USER)
        .map_err(|e| format!("keyring init: {}", e))?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(format!("keyring delete wrap: {}", e)),
    }
}

fn atomic_write(path: &Path, data: &[u8]) -> Result<(), String> {
    use std::io::Write as _;
    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::File::create(&tmp).map_err(|e| e.to_string())?;
        f.write_all(data).map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
    }
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())?;
    Ok(())
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

    let bytes = URL_SAFE_NO_PAD.decode(&data).map_err(|e| e.to_string())?;
    let stored: StoredIdentity = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if let Err(e) = save_stored(data_dir, &stored) {
        tracing::warn!("identity legacy-to-v2 migration deferred: {}", e);
    }
    Ok(Some(stored))
}

fn save_stored(data_dir: &Path, stored: &StoredIdentity) -> Result<(), String> {
    let path = identity_file_path(data_dir);
    let json = serde_json::to_vec(stored).map_err(|e| e.to_string())?;
    let wrap_key = wrap_key_load_or_create()?;
    let blob = aead_seal(&wrap_key, MAGIC_ID, &json)?;
    atomic_write(&path, &blob)?;
    set_file_permissions_restrictive(&path)?;
    Ok(())
}

fn identity_from_stored(stored: StoredIdentity) -> Result<DeviceIdentity, String> {
    let ed25519_signing_key = SigningKey::from_bytes(&stored.ed25519_sk_bytes);
    let mlkem_decaps_key = MlKemDecapKey::from_bytes(
        &ml_kem::Encoded::<MlKemDecapKey>::try_from(stored.mlkem_sk_bytes.as_slice())
            .map_err(|e| e.to_string())?,
    );
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
    let mut mlkem_sk_bytes = dk.as_bytes().to_vec();
    let mlkem_pk_bytes = ek.as_bytes().to_vec();

    let x25519_static_secret = StaticSecret::random_from_rng(OsRng);
    let mut x25519_sk_bytes: [u8; 32] = x25519_static_secret.to_bytes();
    let x25519_public_bytes = *XPublicKey::from(&x25519_static_secret).as_bytes();

    let stored = StoredIdentity {
        device_id: None,
        ed25519_sk_bytes,
        mlkem_sk_bytes: mlkem_sk_bytes.clone(),
        mlkem_pk_bytes: mlkem_pk_bytes.clone(),
        x25519_sk_bytes,
    };
    let save_result = save_stored(data_dir, &stored);

    ed25519_sk_bytes.zeroize();
    mlkem_sk_bytes.zeroize();
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

pub fn sign_with_key(key: &SigningKey, nonce_b64: &str) -> Result<String, String> {
    let nonce = b64url_decode(nonce_b64)?;
    let sig = key.sign(&nonce);
    Ok(b64url(&sig.to_bytes()))
}

pub fn get_pubkeys(identity: &DeviceIdentity) -> (String, String, String) {
    let ed25519_pk = b64url(identity.ed25519_signing_key.verifying_key().as_bytes());
    let mlkem_pk = b64url(&identity.mlkem_encaps_key_bytes);
    let x25519_pk = b64url(&identity.x25519_public_bytes);
    (ed25519_pk, mlkem_pk, x25519_pk)
}

pub fn unseal_vault_envelope(
    identity: &DeviceIdentity,
    envelope_b64: &str,
) -> Result<Vec<u8>, String> {
    let data = b64url_decode(envelope_b64)?;
    if data.len() < 32 + 1088 + 24 + 16 {
        return Err("envelope too short".to_string());
    }

    let x25519_eph_pk_bytes: [u8; 32] = data[0..32].try_into().map_err(|_| "slice")?;
    let mlkem_ct_bytes = &data[32..32 + 1088];
    let nonce_bytes: [u8; 24] = data[32 + 1088..32 + 1088 + 24]
        .try_into()
        .map_err(|_| "slice")?;
    let ciphertext = &data[32 + 1088 + 24..];

    let ct: Ciphertext<MlKem768> =
        Array::try_from(mlkem_ct_bytes).map_err(|e: _| format!("ct size: {:?}", e))?;
    let mut ss_pq = identity
        .mlkem_decaps_key
        .decapsulate(&ct)
        .map_err(|e| format!("mlkem decaps: {:?}", e))?;

    let eph_pub = XPublicKey::from(x25519_eph_pk_bytes);
    let ss_cl = identity.x25519_static_secret.diffie_hellman(&eph_pub);

    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(ss_pq.as_slice());
    ikm[32..].copy_from_slice(ss_cl.as_bytes());

    let hk = Hkdf::<Sha256>::new(Some(&nonce_bytes), &ikm);
    let mut shared_key = [0u8; 32];
    hk.expand(b"astermail-device-enroll-v1", &mut shared_key)
        .map_err(|e| e.to_string())?;

    ikm.zeroize();
    ss_pq.zeroize();
    drop(ss_cl);

    let cipher = XChaCha20Poly1305::new((&shared_key).into());
    let xnonce = XNonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(xnonce, ciphertext)
        .map_err(|e| format!("decrypt: {:?}", e))?;

    shared_key.zeroize();

    Ok(plaintext)
}

const KEYRING_SERVICE: &str = "com.astermail.bridge";
const KEYRING_USER: &str = "vault-passphrase";

fn keyring_store(passphrase: &[u8]) -> std::result::Result<(), String> {
    let encoded = b64url(passphrase);
    let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
        .map_err(|e| format!("keyring init: {}", e))?;
    entry
        .set_password(&encoded)
        .map_err(|e| format!("keyring set: {}", e))
}

fn keyring_load() -> std::result::Result<Option<Vec<u8>>, String> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
        .map_err(|e| format!("keyring init: {}", e))?;
    match entry.get_password() {
        Ok(encoded) => {
            let bytes = b64url_decode(&encoded)?;
            Ok(Some(bytes))
        }
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(format!("keyring get: {}", e)),
    }
}

fn keyring_delete() -> std::result::Result<(), String> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
        .map_err(|e| format!("keyring init: {}", e))?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(format!("keyring delete: {}", e)),
    }
}

pub fn store_passphrase(data_dir: &Path, passphrase: &[u8]) -> Result<(), String> {
    if keyring_store(passphrase).is_ok() {
        let path = passphrase_file_path(data_dir);
        if path.exists() {
            let _ = std::fs::remove_file(&path);
        }
        return Ok(());
    }

    let path = passphrase_file_path(data_dir);
    let wrap_key = wrap_key_load_or_create()?;
    let blob = aead_seal(&wrap_key, MAGIC_PP, passphrase)?;
    atomic_write(&path, &blob)?;
    set_file_permissions_restrictive(&path)?;
    Ok(())
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

    if keyring_store(&bytes).is_ok() {
        let _ = std::fs::remove_file(&path);
    } else if !was_sealed {
        let resealed = wrap_key_load_or_create().ok().and_then(|wrap_key| {
            let blob = aead_seal(&wrap_key, MAGIC_PP, &bytes).ok()?;
            atomic_write(&path, &blob).ok()?;
            let _ = set_file_permissions_restrictive(&path);
            Some(())
        });
        if resealed.is_none() {
            tracing::warn!("could not re-seal legacy passphrase file; it remains in plaintext on disk");
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

    #[test]
    fn sign_challenge_produces_verifiable_signature() {
        let identity = test_identity();
        let nonce_raw = [9u8; 32];
        let nonce_b64 = b64url(&nonce_raw);
        let sig_b64 = sign_challenge(&identity, &nonce_b64).unwrap();

        let sig_bytes = b64url_decode(&sig_b64).unwrap();
        let sig = ed25519_dalek::Signature::from_slice(&sig_bytes).unwrap();
        let verifying: VerifyingKey = identity.ed25519_signing_key.verifying_key();
        assert!(verifying.verify(&nonce_raw, &sig).is_ok());
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
