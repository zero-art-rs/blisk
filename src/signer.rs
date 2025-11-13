use crate::errors::PolicyError;
use crate::policy::PolicyTree;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;

pub struct Signer<G: AffineRepr> {
    secret_key: G::ScalarField,
    public_key: G,
}

impl<G: AffineRepr> Signer<G> {
    pub fn new(secret_key: G::ScalarField) -> Self {
        Self {
            secret_key,
            public_key: (G::generator() * secret_key).into_affine(),
        }
    }

    pub fn resolve_policy(&self, policy_tree: PolicyTree<G>) -> Result<PolicyTree<G>, PolicyError> {
        policy_tree.resolve(self.secret_key)
    }
    
    
}
