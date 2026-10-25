//! Optional REALITY hybrid exchange. Cryptographic operations stay in BoringSSL.
//! Authentication and both offered shares use the same ephemeral X25519 key.
use boring::mlkem::{Algorithm, MlKemPrivateKey, MlKemPublicKey};

use super::{x25519, Result, TransportError, GROUP_X25519};

pub(super) const GROUP_X25519_MLKEM768: u16 = 0x11ec;
const MLKEM_CIPHERTEXT_LEN: usize = 1088;

pub(super) struct HybridExchange {
    keys: Option<(MlKemPublicKey, MlKemPrivateKey)>,
}

impl HybridExchange {
    pub(super) fn new(enabled: bool) -> Result<Self> {
        let keys =
            if enabled {
                Some(MlKemPrivateKey::generate(Algorithm::MlKem768).map_err(|_| {
                    TransportError::Tls("REALITY ML-KEM key generation failed".into())
                })?)
            } else {
                None
            };
        Ok(Self { keys })
    }

    pub(super) fn public_key(&self) -> Option<&[u8]> {
        self.keys.as_ref().map(|(public, _)| public.as_bytes())
    }

    pub(super) fn complete(&self, group: u16, share: &[u8], private: &[u8; 32]) -> Result<Vec<u8>> {
        match group {
            GROUP_X25519 if share.len() == 32 => {
                let public = share.try_into().map_err(|_| invalid_share())?;
                Ok(x25519(private, public)?.to_vec())
            }
            GROUP_X25519_MLKEM768 if share.len() == MLKEM_CIPHERTEXT_LEN + 32 => {
                let (_, mlkem) = self.keys.as_ref().ok_or_else(invalid_share)?;
                let (ciphertext, public) = share.split_at(MLKEM_CIPHERTEXT_LEN);
                let classical = x25519(private, public.try_into().map_err(|_| invalid_share())?)?;
                let post_quantum = mlkem.decapsulate(ciphertext).map_err(|_| invalid_share())?;
                // TLS X25519MLKEM768 orders the ML-KEM secret before X25519.
                let mut secret = Vec::with_capacity(64);
                secret.extend_from_slice(post_quantum.as_ref());
                secret.extend_from_slice(&classical);
                Ok(secret)
            }
            _ => Err(invalid_share()),
        }
    }
}

fn invalid_share() -> TransportError {
    TransportError::Tls("REALITY peer selected an unsupported or malformed key share".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reality_tls::x25519_public_from_private;

    #[test]
    fn negotiated_hybrid_secret_matches_the_offered_keys_and_tls_order() {
        let client = HybridExchange::new(true).unwrap();
        let public =
            MlKemPublicKey::from_slice(Algorithm::MlKem768, client.public_key().unwrap()).unwrap();
        let (mut share, secret) = public.encapsulate().unwrap();
        let client_private = [7; 32];
        let server_private = [9; 32];
        share.extend_from_slice(&x25519_public_from_private(&server_private));
        let derived = client
            .complete(GROUP_X25519_MLKEM768, &share, &client_private)
            .unwrap();
        let classical = x25519(
            &server_private,
            &x25519_public_from_private(&client_private),
        )
        .unwrap();
        assert_eq!(&derived[..32], secret.as_ref());
        assert_eq!(&derived[32..], &classical);
    }

    #[test]
    fn unoffered_malformed_and_low_order_shares_fail_without_changing_keys() {
        let disabled = HybridExchange::new(false).unwrap();
        assert!(disabled.public_key().is_none());
        assert!(disabled
            .complete(GROUP_X25519_MLKEM768, &[1; 1120], &[7; 32])
            .is_err());
        let client = HybridExchange::new(true).unwrap();
        let before = client.public_key().unwrap().to_vec();
        for (group, share) in [
            (GROUP_X25519_MLKEM768, vec![1; 1119]),
            (GROUP_X25519_MLKEM768, vec![1; 1121]),
            (GROUP_X25519, vec![1; 31]),
            (GROUP_X25519, vec![0; 32]),
            (0x0017, vec![1; 65]),
        ] {
            assert!(client.complete(group, &share, &[7; 32]).is_err());
            assert_eq!(client.public_key().unwrap(), &before);
        }
    }

    #[test]
    fn hybrid_offer_allows_a_server_to_select_the_classical_share() {
        let private = [7; 32];
        let public = x25519_public_from_private(&[9; 32]);
        let expected = x25519(&private, &public).unwrap();
        for enabled in [false, true] {
            let client = HybridExchange::new(enabled).unwrap();
            assert_eq!(
                client.complete(GROUP_X25519, &public, &private).unwrap(),
                expected
            );
        }
    }
}
