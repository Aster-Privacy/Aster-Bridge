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

const ECC_VECTORS: &str = include_str!("testdata/ecc_interop_vectors.json");

fn vectors() -> serde_json::Value {
    serde_json::from_str(ECC_VECTORS).unwrap()
}

fn field(vector: &serde_json::Value, name: &str) -> String {
    vector[name].as_str().unwrap().to_string()
}

fn keys() -> Vec<serde_json::Value> {
    vectors()["keys"].as_array().unwrap().clone()
}

fn plaintext() -> String {
    field(&vectors(), "plaintext")
}

fn stored_key(vector: &serde_json::Value) -> aster_crypto::KeyPair {
    let bytes = STANDARD.decode(field(vector, "secret_key_b64")).unwrap();
    aster_crypto::import_secret_key_bytes(&bytes).unwrap()
}

#[test]
fn the_vectors_cover_every_curve() {
    let labels: Vec<String> = keys().iter().map(|k| field(k, "label")).collect();

    assert_eq!(labels, ["ed25519", "nistp256", "nistp384", "nistp521"]);
}

#[test]
fn stored_ecc_keys_from_another_client_still_load() {
    for vector in keys() {
        let pair = stored_key(&vector);

        assert_eq!(pair.fingerprint().to_ascii_lowercase(), field(&vector, "fingerprint"), "{}", field(&vector, "label"));
    }
}

#[test]
fn ecc_mail_encrypted_and_signed_by_another_client_decrypts_and_verifies() {
    for vector in keys() {
        let pair = stored_key(&vector);
        let public = pair.public_key();

        let plain = aster_crypto::decrypt_and_verify_with_passphrase(
            field(&vector, "encrypted_and_signed").as_bytes(),
            &[&pair],
            &[&public],
            "",
        )
        .unwrap_or_else(|e| panic!("{}: {:?}", field(&vector, "label"), e));

        assert_eq!(plain, plaintext().into_bytes(), "{}", field(&vector, "label"));
    }
}

#[test]
fn ecc_cleartext_signatures_from_another_client_verify() {
    for vector in keys() {
        let armored_public = stored_key(&vector).public_key_armored().unwrap();

        let signed = aster_crypto::verify_cleartext_signature(&armored_public, &field(&vector, "cleartext_signed")).unwrap();

        assert_eq!(signed.as_deref().map(str::trim_end), Some(plaintext().as_str()), "{}", field(&vector, "label"));
    }
}

#[test]
fn a_changed_ecc_cleartext_message_does_not_verify() {
    for vector in keys() {
        let armored_public = stored_key(&vector).public_key_armored().unwrap();
        let changed = field(&vector, "cleartext_signed").replace("another client", "someone else");

        let signed = aster_crypto::verify_cleartext_signature(&armored_public, &changed);

        assert!(!matches!(signed, Ok(Some(_))), "{}", field(&vector, "label"));
    }
}

#[test]
fn ecc_keys_sign_and_decrypt_their_own_messages() {
    for vector in keys() {
        let pair = stored_key(&vector);
        let public = pair.public_key();
        let armored_public = pair.public_key_armored().unwrap();

        let sealed = aster_crypto::encrypt_and_sign_with_passphrase(b"round trip", &[&public], &pair, "").unwrap();
        let plain = aster_crypto::decrypt_and_verify_with_passphrase(&sealed, &[&pair], &[&public], "").unwrap();
        assert_eq!(plain.as_slice(), b"round trip", "{}", field(&vector, "label"));

        let signed = aster_crypto::sign_cleartext_message("signed text", &pair).unwrap();
        let verified = aster_crypto::verify_cleartext_signature(&armored_public, &signed).unwrap();
        assert_eq!(verified.as_deref(), Some("signed text"), "{}", field(&vector, "label"));
    }
}

#[test]
fn an_ecc_key_cannot_open_mail_for_another_curve() {
    let all = keys();
    for (i, sender) in all.iter().enumerate() {
        let recipient = stored_key(sender);
        let sealed = aster_crypto::encrypt_message(b"for one key", &[&recipient.public_key()]).unwrap();
        for (j, other) in all.iter().enumerate() {
            let opened = aster_crypto::decrypt_message(&sealed, &[&stored_key(other)]);
            if i == j {
                assert_eq!(opened.unwrap().as_slice(), b"for one key");
            } else {
                assert!(opened.is_err(), "{} opened mail for {}", field(other, "label"), field(sender, "label"));
            }
        }
    }
}

#[test]
fn an_ecc_signature_from_another_key_does_not_verify() {
    let all = keys();
    for (i, signer) in all.iter().enumerate() {
        let signed = aster_crypto::sign_cleartext_message("signed text", &stored_key(signer)).unwrap();
        for (j, other) in all.iter().enumerate() {
            if i == j {
                continue;
            }
            let verified =
                aster_crypto::verify_cleartext_signature(&stored_key(other).public_key_armored().unwrap(), &signed);
            assert!(!matches!(verified, Ok(Some(_))), "{} verified {}", field(other, "label"), field(signer, "label"));
        }
    }
}
