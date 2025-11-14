use crate::errors::PolicyError;
use crate::musig2::{MuSig2Error, MuSig2HashFunction, MuSig2Session, MuSig2Signature};
use crate::policy::PolicyTree;
use ark_ec::{AffineRepr, CurveGroup};
use itertools::Itertools;
use rand::RngCore;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Policy Signer
pub struct Signer<G: AffineRepr, H: MuSig2HashFunction<G::ScalarField>> {
    secret_key: G::ScalarField,
    pub public_key: G,
    clauses_keys: Vec<(G::ScalarField, G)>, // resolvable keys by this signer
    musig2_sessions: Vec<MuSig2Session<G, H>>,
}

impl<G: AffineRepr, H: MuSig2HashFunction<G::ScalarField> + Clone> Signer<G, H> {
    pub fn new(
        label: String,
        secret_key: G::ScalarField,
        policy: PolicyTree<G>,
        message: Vec<u8>,
        hash_function: H,
    ) -> Result<Self, PolicyError> {
        let clauses_keys = policy.resolve_clauses_private_keys(secret_key)?;
        let co_signers = policy.get_clauses_public_keys()?;
        Ok(Self {
            secret_key,
            public_key: (G::generator() * secret_key).into_affine(),
            clauses_keys: clauses_keys.clone(),
            musig2_sessions: clauses_keys
                .into_iter()
                .map(|(_, public_key)| {
                    MuSig2Session::new(
                        {
                            let pk_debug = format!("{:?}", public_key);
                            let mut hasher = DefaultHasher::new();
                            pk_debug.hash(&mut hasher);
                            format!(
                                "{}/{:08x}",
                                label.clone(),
                                (hasher.finish() & 0xffff_ffff) as u32
                            )
                        },
                        message.clone(),
                        public_key,
                        co_signers.clone(),
                        hash_function.clone(),
                    )
                })
                .collect::<Result<Vec<_>, _>>()?,
        })
    }

    /// perform the first round of MuSig2: nonce generation
    pub fn generate_nonces(
        &mut self,
        rng: &mut impl RngCore,
    ) -> Result<Vec<(G, (G, G))>, PolicyError> {
        self.musig2_sessions
            .iter_mut()
            .map(|s| {
                Ok((
                    s.cosigner_public_keys[s.local_signer_idx.unwrap()],
                    s.generate_nonces(rng)?,
                ))
            })
            .collect::<Result<Vec<_>, _>>()
    }

    /// process the nonces received from other signers
    pub fn process_nonces(
        &mut self,
        signer_public_key: G,
        nonces: (G, G),
    ) -> Result<(), PolicyError> {
        self.musig2_sessions
            .iter_mut()
            .map(|s| s.add_public_nonces(signer_public_key, nonces))
            .collect::<Result<(), _>>()
            .map_err(|e| e.into())
    }

    /// perform the second round of MuSig2: nonce aggregation
    pub fn aggregate_nonces(&mut self) -> Result<G, PolicyError> {
        let mut nonces = self
            .musig2_sessions
            .iter_mut()
            .map(|s| s.compute_aggregated_nonce())
            .collect::<Result<Vec<G>, _>>()?;
        nonces.dedup();
        if nonces.len() != 1 {
            return Err(MuSig2Error::InvalidNonce.into());
        }
        Ok(nonces[0])
    }

    /// get aggregated public key
    pub fn aggregate_public_keys(&mut self) -> Result<G, PolicyError> {
        let mut public_keys = self
            .musig2_sessions
            .iter_mut()
            .map(|s| s.compute_aggregated_key())
            .collect::<Result<Vec<G>, _>>()?;
        public_keys.dedup();
        if public_keys.len() != 1 {
            return Err(MuSig2Error::InvalidPublicKey.into());
        }
        Ok(public_keys[0])
    }

    /// compute partial signatures
    pub fn sign(&mut self) -> Result<Vec<G::ScalarField>, PolicyError> {
        self.musig2_sessions
            .iter_mut()
            .map(|s| {
                s.sign(
                    self.clauses_keys
                        .iter()
                        .find(|(_, Q)| Q == &s.cosigner_public_keys[s.local_signer_idx.unwrap()]) // find clause private key
                        .unwrap()
                        .0,
                )
            })
            .collect::<Result<Vec<G::ScalarField>, _>>()
            .map_err(|e| e.into())
    }

    pub fn resolve_policy(&self, policy_tree: PolicyTree<G>) -> Result<PolicyTree<G>, PolicyError> {
        policy_tree.resolve(self.secret_key)
    }
}
