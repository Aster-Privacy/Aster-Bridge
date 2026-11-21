// SPDX-License-Identifier: AGPL-3.0-or-later
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
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const KEYS_DOMAIN: &[u8] = b"aster-guard-keys-v1";
pub const APPROVE_DOMAIN: &[u8] = b"aster-guard-approve-v1";
pub const ACTION_PK_LEN: usize = 33;

pub fn new_device_keys_digest(
    ed25519_pk: &[u8],
    mlkem_pk: &[u8],
    x25519_pk: &[u8],
    action_pk: Option<&[u8]>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(KEYS_DOMAIN);
    hasher.update(ed25519_pk);
    hasher.update(mlkem_pk);
    hasher.update(x25519_pk);
    match action_pk {
        Some(key) => hasher.update(key),
        None => hasher.update([0u8; ACTION_PK_LEN]),
    }
    hasher.finalize().into()
}

pub fn approve_subject(request_id: Uuid, keys_digest: &[u8; 32], number: u8) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(APPROVE_DOMAIN);
    hasher.update(request_id.as_bytes());
    hasher.update(keys_digest);
    hasher.update([number]);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn keys() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut action = vec![0x02u8];
        action.extend(std::iter::repeat(0x44u8).take(32));
        (vec![0x11; 32], vec![0x22; 1184], vec![0x33; 32], action)
    }

    fn request_id() -> Uuid {
        Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap()
    }

    #[test]
    fn keys_digest_with_action_pk_matches_vector() {
        let (ed, mlkem, x25519, action) = keys();
        let digest = new_device_keys_digest(&ed, &mlkem, &x25519, Some(&action));
        assert_eq!(
            to_hex(&digest),
            "c8b92c7e16a9bb2edf93c93983240c55a375fc29d50746cf6cdf6d439d41110b"
        );
    }

    #[test]
    fn keys_digest_without_action_pk_uses_zeros() {
        let (ed, mlkem, x25519, _) = keys();
        let digest = new_device_keys_digest(&ed, &mlkem, &x25519, None);
        assert_eq!(
            to_hex(&digest),
            "834f8d3bc8320d7e2a92e33f00f200de037ce2806695c27d38902e9cfb8269e3"
        );
        let zeros = [0u8; ACTION_PK_LEN];
        assert_eq!(digest, new_device_keys_digest(&ed, &mlkem, &x25519, Some(&zeros)));
    }

    #[test]
    fn approve_subject_matches_vectors() {
        let (ed, mlkem, x25519, action) = keys();
        let with_action = new_device_keys_digest(&ed, &mlkem, &x25519, Some(&action));
        let absent = new_device_keys_digest(&ed, &mlkem, &x25519, None);
        assert_eq!(
            to_hex(&approve_subject(request_id(), &with_action, 42)),
            "ac8e5a52e5e4d55ac8fc07619a5c7cc6be147d749a4dc5f93f943f3a1d9026bc"
        );
        assert_eq!(
            to_hex(&approve_subject(Uuid::nil(), &absent, 0)),
            "3e5170b45bb76f27bdc4fb9d9ca6c5110b000fc15558d1f75c2df11e0a7ecd3b"
        );
        assert_eq!(
            to_hex(&approve_subject(Uuid::nil(), &with_action, 0)),
            "374d2364cb371fda52fdf948e42c21153c3cfd338217f63f713265c3964a8151"
        );
    }
}
