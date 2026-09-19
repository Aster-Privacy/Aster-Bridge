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
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::api_client::ApiClient;

pub const ACCOUNT_KEY_LEN: usize = 32;
pub const PREFERENCES_CONTEXT: &str = "astermail-preferences-v1";
pub const DRAFT_CONTEXT: &str = "astermail-draft-v2";

const TOKEN_TYPE: &str = "aster-account-key";
const TOKEN_VERSION: u64 = 2;
const LEGACY_TOKEN_VERSION: u64 = 1;
const MAX_SERIAL: u64 = 9_007_199_254_740_991;
const DATA_SALT: &[u8] = b"aster-account-data-salt-v1";
const DATA_INFO_PREFIX: &str = "aster-account-data-v1:";

pub type AccountKey = Zeroizing<[u8; ACCOUNT_KEY_LEN]>;

pub fn derive_context_key(account_key: &[u8; ACCOUNT_KEY_LEN], context: &str) -> AccountKey {
    let hk = Hkdf::<Sha256>::new(Some(DATA_SALT), account_key);
    let info = format!("{}{}", DATA_INFO_PREFIX, context);
    let mut out = Zeroizing::new([0u8; ACCOUNT_KEY_LEN]);
    hk.expand(info.as_bytes(), out.as_mut())
        .expect("hkdf output of 32 bytes is always valid");
    out
}

fn is_fingerprint(value: &str) -> bool {
    (value.len() == 40 || value.len() == 64)
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn parse_token_payload(plaintext: &[u8], owner_fingerprints: &[String]) -> Option<AccountKey> {
    let value: serde_json::Value = serde_json::from_slice(plaintext).ok()?;
    let payload = value.as_object()?;
    if payload.get("type")?.as_str()? != TOKEN_TYPE {
        return None;
    }
    let version = payload.get("version")?;
    if !version.is_u64() {
        return None;
    }
    match version.as_u64()? {
        TOKEN_VERSION => {
            let owner = payload.get("owner")?.as_str()?;
            if !is_fingerprint(owner)
                || !owner_fingerprints
                    .iter()
                    .any(|f| f.trim().eq_ignore_ascii_case(owner))
            {
                return None;
            }
            let serial = payload.get("serial")?;
            if !serial.is_u64() || !(1..=MAX_SERIAL).contains(&serial.as_u64()?) {
                return None;
            }
        }
        LEGACY_TOKEN_VERSION => {}
        _ => return None,
    }
    let decoded = Zeroizing::new(STANDARD.decode(payload.get("key")?.as_str()?).ok()?);
    if decoded.len() != ACCOUNT_KEY_LEN {
        return None;
    }
    let mut key = Zeroizing::new([0u8; ACCOUNT_KEY_LEN]);
    key.copy_from_slice(&decoded);
    Some(key)
}

pub fn open_token(
    token: &str,
    own_keys: &[aster_crypto::KeyPair],
    passphrase: &str,
) -> Option<AccountKey> {
    if own_keys.is_empty() {
        return None;
    }
    let public_keys: Vec<aster_crypto::PublicKey> =
        own_keys.iter().map(|k| k.public_key()).collect();
    let public_refs: Vec<&aster_crypto::PublicKey> = public_keys.iter().collect();
    let secret_refs: Vec<&aster_crypto::KeyPair> = own_keys.iter().collect();
    let plaintext = Zeroizing::new(
        aster_crypto::decrypt_and_verify_with_passphrase(
            token.as_bytes(),
            &secret_refs,
            &public_refs,
            passphrase,
        )
        .ok()?,
    );
    let owners: Vec<String> = own_keys.iter().map(|k| k.fingerprint()).collect();
    parse_token_payload(&plaintext, &owners)
}

pub fn open_tokens(
    tokens: &[String],
    identity_key: &str,
    previous_keys: &[String],
    passphrase: &[u8],
) -> Vec<AccountKey> {
    let passphrase = match std::str::from_utf8(passphrase) {
        Ok(p) => Zeroizing::new(p.to_string()),
        Err(_) => return Vec::new(),
    };
    let own_keys: Vec<aster_crypto::KeyPair> = std::iter::once(identity_key)
        .chain(previous_keys.iter().map(String::as_str))
        .filter_map(|armored| aster_crypto::import_secret_key(armored).ok())
        .collect();
    let mut opened: Vec<AccountKey> = Vec::new();
    for token in tokens {
        if let Some(key) = open_token(token, &own_keys, &passphrase) {
            if !opened.iter().any(|k| k[..] == key[..]) {
                opened.push(key);
            }
        }
    }
    opened
}

pub async fn load_account_keys(
    client: &ApiClient,
    access_token: &str,
    identity_key: &str,
    previous_keys: &[String],
    passphrase: &[u8],
) -> Vec<AccountKey> {
    let current = match client.get_account_key_token(access_token).await {
        Ok(Some(c)) => c,
        Ok(None) => return Vec::new(),
        Err(e) => {
            tracing::warn!("account key fetch failed: {}", e);
            return Vec::new();
        }
    };
    let history = client
        .get_account_key_token_history(access_token)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("account key history fetch failed: {}", e);
            Vec::new()
        });
    let tokens: Vec<String> = std::iter::once(current.token)
        .chain(history.into_iter().map(|h| h.token))
        .collect();
    open_tokens(&tokens, identity_key, previous_keys, passphrase)
}

pub fn merge_account_keys(existing: &mut Vec<AccountKey>, loaded: Vec<AccountKey>) {
    for key in loaded {
        if !existing.iter().any(|k| k[..] == key[..]) {
            existing.push(key);
        }
    }
}

pub fn context_keys(account_keys: &[AccountKey], context: &str) -> Vec<AccountKey> {
    account_keys
        .iter()
        .map(|k| derive_context_key(k, context))
        .collect()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

    const PASSPHRASE: &str = "correct horse battery staple";

    fn test_account_key() -> AccountKey {
        let mut key = Zeroizing::new([0u8; ACCOUNT_KEY_LEN]);
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        key
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn payload(key: &[u8]) -> String {
        format!(
            r#"{{"type":"aster-account-key","version":1,"key":"{}"}}"#,
            STANDARD.encode(key)
        )
    }

    fn keypair(name: &str) -> aster_crypto::KeyPair {
        aster_crypto::generate_keypair(name, &format!("{}@astermail.org", name)).unwrap()
    }

    pub(crate) fn protected_keypair(passphrase: &str) -> aster_crypto::KeyPair {
        use pgp::composed::{KeyType, SecretKeyParamsBuilder, SubkeyParamsBuilder};
        use pgp::crypto::ecc_curve::ECCCurve;

        let rng = rand::rngs::OsRng;
        let pw = passphrase.to_string();
        let params = SecretKeyParamsBuilder::default()
            .key_type(KeyType::EdDSALegacy)
            .can_certify(true)
            .can_sign(true)
            .primary_user_id("Owner <owner@astermail.org>".into())
            .passphrase(Some(pw.clone()))
            .subkey(
                SubkeyParamsBuilder::default()
                    .key_type(KeyType::ECDH(ECCCurve::Curve25519))
                    .can_encrypt(true)
                    .passphrase(Some(pw.clone()))
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        let signed = params.generate(rng).unwrap().sign(rng, || pw).unwrap();
        let armored = signed.to_armored_string(None.into()).unwrap();
        aster_crypto::import_secret_key(&armored).unwrap()
    }

    fn seal(
        plaintext: &str,
        signer: &aster_crypto::KeyPair,
        recipient: &aster_crypto::KeyPair,
        passphrase: &str,
    ) -> String {
        let recipient_pub = recipient.public_key();
        let armored = aster_crypto::encrypt_and_sign_with_passphrase(
            plaintext.as_bytes(),
            &[&recipient_pub],
            signer,
            passphrase,
        )
        .unwrap();
        String::from_utf8(armored).unwrap()
    }

    fn aes_encrypt(key: &[u8; 32], plaintext: &[u8]) -> (String, String) {
        let nonce_bytes = [7u8; 12];
        let cipher = Aes256Gcm::new_from_slice(key).unwrap();
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
            .unwrap();
        (STANDARD.encode(ciphertext), STANDARD.encode(nonce_bytes))
    }

    #[test]
    fn context_keys_match_web_vectors() {
        let key = test_account_key();
        assert_eq!(
            hex(&derive_context_key(&key, PREFERENCES_CONTEXT)[..]),
            "689560f8c35dae5940ef30ae2f047099b93e4c6c846ac1075fe7e50c7b085aa5"
        );
        assert_eq!(
            hex(&derive_context_key(&key, DRAFT_CONTEXT)[..]),
            "adb0a69ec8c6548233dd706fa786375d72820aa2c66574bcd478183a0f705a63"
        );
    }

    #[test]
    fn parses_valid_payload() {
        let key = test_account_key();
        let parsed = parse_token_payload(payload(&key[..]).as_bytes(), &[]).unwrap();
        assert_eq!(parsed[..], key[..]);
    }

    #[test]
    fn rejects_malformed_payloads() {
        let key_b64 = STANDARD.encode([1u8; 32]);
        let short_b64 = STANDARD.encode([1u8; 31]);
        let bad = [
            String::new(),
            "not json".to_string(),
            "[]".to_string(),
            r#"{"type":"aster-account-key","version":1}"#.to_string(),
            format!(r#"{{"type":"other","version":1,"key":"{}"}}"#, key_b64),
            format!(
                r#"{{"type":"aster-account-key","version":"1","key":"{}"}}"#,
                key_b64
            ),
            format!(
                r#"{{"type":"aster-account-key","version":1.5,"key":"{}"}}"#,
                key_b64
            ),
            format!(
                r#"{{"type":"aster-account-key","version":2,"key":"{}"}}"#,
                key_b64
            ),
            format!(
                r#"{{"type":"aster-account-key","version":1,"key":"{}"}}"#,
                short_b64
            ),
            r#"{"type":"aster-account-key","version":1,"key":"***"}"#.to_string(),
            r#"{"type":"aster-account-key","version":1,"key":32}"#.to_string(),
            payload_v2(&[1u8; 32], None, Some("1")),
            payload_v2(&[1u8; 32], Some(OWNER), None),
            payload_v2(&[1u8; 32], Some(OWNER), Some("0")),
            payload_v2(&[1u8; 32], Some(OWNER), Some("1.5")),
            payload_v2(&[1u8; 32], Some(OWNER), Some(r#""1""#)),
            payload_v2(&[1u8; 32], Some(OWNER), Some("-1")),
            payload_v2(&[1u8; 32], Some(OWNER), Some("9007199254740992")),
            payload_v2(&[1u8; 32], Some(&OWNER.to_uppercase()), Some("1")),
            payload_v2(&[1u8; 32], Some(&"cd".repeat(20)), Some("1")),
            payload_v2(&[1u8; 32], Some("xyz"), Some("1")),
            format!(
                r#"{{"type":"aster-account-key","version":3,"key":"{}","owner":"{}","serial":1}}"#,
                key_b64, OWNER
            ),
        ];
        for p in bad.iter() {
            assert!(
                parse_token_payload(p.as_bytes(), &[OWNER.to_string()]).is_none(),
                "accepted {}",
                p
            );
        }
    }

    const OWNER: &str = "abababababababababababababababababababab";

    fn payload_v2(key: &[u8], owner: Option<&str>, serial: Option<&str>) -> String {
        let mut fields = vec![
            r#""type":"aster-account-key""#.to_string(),
            r#""version":2"#.to_string(),
            format!(r#""key":"{}""#, STANDARD.encode(key)),
        ];
        if let Some(o) = owner {
            fields.push(format!(r#""owner":"{}""#, o));
        }
        if let Some(n) = serial {
            fields.push(format!(r#""serial":{}"#, n));
        }
        format!("{{{}}}", fields.join(","))
    }

    #[test]
    fn parses_version_two_for_known_owner() {
        let key = test_account_key();
        let text = payload_v2(&key[..], Some(OWNER), Some("7"));
        assert_eq!(
            parse_token_payload(text.as_bytes(), &[OWNER.to_uppercase()]).unwrap()[..],
            key[..]
        );
        assert!(parse_token_payload(text.as_bytes(), &[]).is_none());
    }

    #[test]
    fn opens_version_two_token_only_for_its_owner() {
        let owner = keypair("owner");
        let other = keypair("other");
        let key = test_account_key();
        let own = seal(
            &payload_v2(&key[..], Some(&owner.fingerprint()), Some("1")),
            &owner,
            &owner,
            "",
        );
        let named_other = seal(
            &payload_v2(&key[..], Some(&other.fingerprint()), Some("1")),
            &owner,
            &owner,
            "",
        );
        assert_eq!(
            open_token(&own, std::slice::from_ref(&owner), PASSPHRASE).unwrap()[..],
            key[..]
        );
        assert!(open_token(&named_other, &[owner], PASSPHRASE).is_none());
    }

    #[test]
    fn opens_token_signed_and_encrypted_by_own_key() {
        let owner = keypair("owner");
        let key = test_account_key();
        let token = seal(&payload(&key[..]), &owner, &owner, "");
        let opened = open_token(&token, &[owner], PASSPHRASE).unwrap();
        assert_eq!(opened[..], key[..]);
    }

    #[test]
    fn opens_token_from_protected_key_only_with_right_passphrase() {
        let owner = protected_keypair(PASSPHRASE);
        let key = test_account_key();
        let token = seal(&payload(&key[..]), &owner, &owner, PASSPHRASE);
        let owners = [owner];
        assert_eq!(
            open_token(&token, &owners, PASSPHRASE).unwrap()[..],
            key[..]
        );
        assert!(open_token(&token, &owners, "wrong passphrase").is_none());
        assert!(open_token(&token, &owners, "").is_none());
    }

    #[test]
    fn rejects_token_signed_by_foreign_key() {
        let owner = keypair("owner");
        let attacker = keypair("attacker");
        let token = seal(&payload(&test_account_key()[..]), &attacker, &owner, "");
        assert!(open_token(&token, &[owner], PASSPHRASE).is_none());
    }

    #[test]
    fn rejects_unsigned_token() {
        let owner = keypair("owner");
        let owner_pub = owner.public_key();
        let token = String::from_utf8(
            aster_crypto::encrypt_message(
                payload(&test_account_key()[..]).as_bytes(),
                &[&owner_pub],
            )
            .unwrap(),
        )
        .unwrap();
        assert!(open_token(&token, &[owner], PASSPHRASE).is_none());
    }

    #[test]
    fn rejects_token_from_another_account() {
        let owner = keypair("owner");
        let other = keypair("other");
        let token = seal(&payload(&test_account_key()[..]), &other, &other, "");
        assert!(open_token(&token, &[owner], PASSPHRASE).is_none());
    }

    #[test]
    fn rejects_signed_token_with_bad_payload() {
        let owner = keypair("owner");
        let token = seal(
            r#"{"type":"aster-account-key","version":1,"key":"AAAA"}"#,
            &owner,
            &owner,
            "",
        );
        assert!(open_token(&token, &[owner], PASSPHRASE).is_none());
    }

    #[test]
    fn rejects_when_no_own_keys() {
        let owner = keypair("owner");
        let token = seal(&payload(&test_account_key()[..]), &owner, &owner, "");
        assert!(open_token(&token, &[], PASSPHRASE).is_none());
    }

    #[test]
    fn open_tokens_reads_previous_keys_and_dedupes() {
        let current = keypair("current");
        let previous = keypair("previous");
        let attacker = keypair("attacker");
        let current_key = test_account_key();
        let old_key = [9u8; 32];
        let tokens = vec![
            seal(&payload(&current_key[..]), &current, &current, ""),
            seal(&payload(&old_key), &previous, &previous, ""),
            seal(&payload(&current_key[..]), &current, &current, ""),
            seal(&payload(&[5u8; 32]), &attacker, &current, ""),
            "garbage".to_string(),
        ];
        let opened = open_tokens(
            &tokens,
            &current.to_armored().unwrap(),
            &[previous.to_armored().unwrap()],
            PASSPHRASE.as_bytes(),
        );
        assert_eq!(opened.len(), 2);
        assert_eq!(opened[0][..], current_key[..]);
        assert_eq!(opened[1][..], old_key[..]);
    }

    #[test]
    fn open_tokens_skips_invalid_passphrase_bytes_and_bad_identity() {
        let owner = keypair("owner");
        let tokens = vec![seal(&payload(&test_account_key()[..]), &owner, &owner, "")];
        let armored = owner.to_armored().unwrap();
        assert!(open_tokens(&tokens, &armored, &[], &[0xff, 0xfe]).is_empty());
        assert!(open_tokens(&tokens, "not a key", &[], PASSPHRASE.as_bytes()).is_empty());
    }

    #[test]
    fn merge_keeps_existing_and_dedupes() {
        let mut existing = vec![test_account_key()];
        merge_account_keys(&mut existing, Vec::new());
        assert_eq!(existing.len(), 1);
        merge_account_keys(
            &mut existing,
            vec![test_account_key(), Zeroizing::new([3u8; 32])],
        );
        assert_eq!(existing.len(), 2);
        assert_eq!(existing[1][..], [3u8; 32]);
    }

    #[test]
    fn preferences_fall_back_to_account_key() {
        use crate::crypto::preferences::{
            decrypt_preferences, decrypt_preferences_with_account_keys,
        };

        let account_keys = vec![Zeroizing::new([4u8; 32]), test_account_key()];
        let data_key = derive_context_key(&test_account_key(), PREFERENCES_CONTEXT);
        let (enc, nonce) = aes_encrypt(&data_key, br#"{"theme":"dark"}"#);

        assert!(decrypt_preferences("ik", &enc, &nonce).is_err());
        assert!(decrypt_preferences_with_account_keys("ik", &[], &enc, &nonce).is_err());
        let prefs =
            decrypt_preferences_with_account_keys("ik", &account_keys, &enc, &nonce).unwrap();
        assert_eq!(prefs.theme.as_deref(), Some("dark"));
    }

    #[test]
    fn drafts_fall_back_to_account_key_and_keep_identity_key_first() {
        use crate::crypto::draft::{
            decrypt_draft_content, decrypt_draft_content_with_keys, encrypt_draft_content,
            DraftContent, DraftKeys,
        };

        let account_keys = vec![test_account_key()];
        let keys = DraftKeys {
            identity_key: "ik",
            previous_keys: &[],
            account_keys: &account_keys,
            passphrase: b"pass",
        };
        let data_key = derive_context_key(&test_account_key(), DRAFT_CONTEXT);
        let (enc, nonce) = aes_encrypt(&data_key, br#"{"subject":"from account key"}"#);

        assert!(decrypt_draft_content(&enc, &nonce, "ik").is_err());
        let content = decrypt_draft_content_with_keys(&enc, &nonce, &keys).unwrap();
        assert_eq!(content.subject, "from account key");

        let legacy = DraftContent {
            subject: "from identity key".to_string(),
            ..Default::default()
        };
        let (enc, nonce) = encrypt_draft_content(&legacy, "ik").unwrap();
        let content = decrypt_draft_content_with_keys(&enc, &nonce, &keys).unwrap();
        assert_eq!(content.subject, "from identity key");
    }
}
