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
use base64::{engine::general_purpose::STANDARD, Engine};

const RSA_VECTORS: &str = include_str!("testdata/rsa_interop_vectors.json");

fn vectors() -> serde_json::Value {
    serde_json::from_str(RSA_VECTORS).unwrap()
}

fn field(vector: &serde_json::Value, name: &str) -> String {
    vector[name].as_str().unwrap().to_string()
}

fn stored_rsa_key() -> aster_crypto::KeyPair {
    let bytes = STANDARD.decode(field(&vectors(), "secret_key_b64")).unwrap();
    aster_crypto::import_secret_key_bytes(&bytes).unwrap()
}

fn fresh_rsa_key() -> aster_crypto::KeyPair {
    aster_crypto::import_secret_key_bytes(&crate::crypto::external_pgp_key::test_keys::rsa_3072_secret_key())
        .unwrap()
}

#[test]
fn a_stored_rsa_key_from_another_client_still_loads() {
    let pair = stored_rsa_key();

    assert_eq!(pair.fingerprint().to_ascii_lowercase(), field(&vectors(), "fingerprint"));
}

#[test]
fn mail_encrypted_and_signed_by_another_client_decrypts_and_verifies() {
    let vector = vectors();
    let pair = stored_rsa_key();
    let public = pair.public_key();

    let plain = aster_crypto::decrypt_and_verify_with_passphrase(
        field(&vector, "encrypted_and_signed").as_bytes(),
        &[&pair],
        &[&public],
        "",
    )
    .unwrap();

    assert_eq!(plain, field(&vector, "plaintext").into_bytes());
}

#[test]
fn a_cleartext_signature_from_another_client_verifies() {
    let vector = vectors();
    let pair = stored_rsa_key();
    let armored_public = pair.public_key_armored().unwrap();

    let signed = aster_crypto::verify_cleartext_signature(&armored_public, &field(&vector, "cleartext_signed")).unwrap();

    assert_eq!(signed.as_deref().map(str::trim_end), Some(field(&vector, "plaintext").as_str()));
}

#[test]
fn a_changed_cleartext_message_does_not_verify() {
    let vector = vectors();
    let pair = stored_rsa_key();
    let armored_public = pair.public_key_armored().unwrap();
    let changed = field(&vector, "cleartext_signed").replace("another client", "someone else");

    let signed = aster_crypto::verify_cleartext_signature(&armored_public, &changed);

    assert!(!matches!(signed, Ok(Some(_))));
}

#[test]
fn rsa_keys_sign_and_decrypt_their_own_messages() {
    for pair in [stored_rsa_key(), fresh_rsa_key()] {
        let public = pair.public_key();
        let armored_public = pair.public_key_armored().unwrap();

        let sealed = aster_crypto::encrypt_and_sign_with_passphrase(b"round trip", &[&public], &pair, "").unwrap();
        let plain = aster_crypto::decrypt_and_verify_with_passphrase(&sealed, &[&pair], &[&public], "").unwrap();
        assert_eq!(plain.as_slice(), b"round trip");

        let signed = aster_crypto::sign_cleartext_message("signed text", &pair).unwrap();
        let verified = aster_crypto::verify_cleartext_signature(&armored_public, &signed).unwrap();
        assert_eq!(verified.as_deref(), Some("signed text"));
    }
}

#[test]
fn a_different_rsa_key_cannot_open_the_message() {
    let stored = stored_rsa_key();
    let fresh = fresh_rsa_key();
    let sealed = aster_crypto::encrypt_message(b"for the fresh key", &[&fresh.public_key()]).unwrap();

    assert!(aster_crypto::decrypt_message(&sealed, &[&stored]).is_err());
    assert_eq!(aster_crypto::decrypt_message(&sealed, &[&fresh]).unwrap().as_slice(), b"for the fresh key");
}

#[test]
fn a_signature_from_a_different_rsa_key_does_not_verify() {
    let stored = stored_rsa_key();
    let fresh = fresh_rsa_key();
    let signed = aster_crypto::sign_cleartext_message("signed text", &fresh).unwrap();

    let verified = aster_crypto::verify_cleartext_signature(&stored.public_key_armored().unwrap(), &signed);

    assert!(!matches!(verified, Ok(Some(_))));
}
