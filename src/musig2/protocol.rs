use crate::musig2::error::MuSig2Error;
use crate::musig2::types::{
    MuSig2HashFunction, MuSig2Session, MuSig2SessionState, MuSig2Signature, SignerId,
};

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{PrimeField, UniformRand, Zero};
use ark_serialize::CanonicalSerialize;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::marker::PhantomData;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DefaultMuSig2Hash<S: PrimeField> {
    _phantom: PhantomData<S>,
}

impl<S: PrimeField> DefaultMuSig2Hash<S> {
    /// Create a new instance of the default hash function
    pub fn new() -> Self {
        DefaultMuSig2Hash {
            _phantom: PhantomData,
        }
    }
}

impl<S: PrimeField> MuSig2HashFunction<S> for DefaultMuSig2Hash<S> {
    /// Generic hash function for the MuSig2 protocol with domain separation
    fn hash(&self, domain: &str, data: &[&[u8]]) -> Result<S, MuSig2Error> {
        let mut hasher = Sha256::new();

        // Add domain separation
        hasher.update(domain.as_bytes());

        // Add a separator between domain and data
        hasher.update(&[0]);

        // Add all data pieces with separators
        for piece in data {
            hasher.update(piece);
            hasher.update(&[0]);
        }

        let result = hasher.finalize();

        let bytes_needed = (S::MODULUS_BIT_SIZE as usize + 7) / 8;
        let mut truncated = result.to_vec();
        truncated.truncate(bytes_needed);

        Ok(S::from_le_bytes_mod_order(&truncated))
    }
}

/// Initialize a new MuSig2 signing session
pub fn create_session<G, H>(
    session_id: String,
    message: Vec<u8>,
    local_public_key: G,
    cosigner_public_keys: Vec<G>,
    hash_function: H,
) -> Result<MuSig2Session<G, H>, MuSig2Error>
where
    G: AffineRepr,
    H: MuSig2HashFunction<G::ScalarField>,
{
    // Verify that the local signer is in the cosigner list
    if !cosigner_public_keys.contains(&local_public_key) {
        return Err(MuSig2Error::SignerNotInCosigners);
    }

    // Sort the public keys lexicographically
    let mut sorted_keys = cosigner_public_keys.clone();
    sorted_keys.sort_by(|a, b| {
        let mut a_bytes = Vec::new();
        let mut b_bytes = Vec::new();
        a.serialize_compressed(&mut a_bytes).unwrap();
        b.serialize_compressed(&mut b_bytes).unwrap();
        a_bytes.cmp(&b_bytes)
    });

    // Find the local signer's index
    let mut local_idx = None;
    for (idx, key) in sorted_keys.iter().enumerate() {
        if *key == local_public_key {
            local_idx = Some(idx);
            break;
        }
    }

    if local_idx.is_none() {
        return Err(MuSig2Error::SignerNotInCosigners);
    }

    // Create a new session with initial state
    Ok(MuSig2Session {
        session_id,
        state: MuSig2SessionState::Initialized,
        message,
        cosigner_public_keys: sorted_keys,
        key_aggregation_coeffs: HashMap::new(),
        aggregated_public_key: None,
        local_signer_idx: local_idx,
        secret_nonces: None,
        public_nonces: HashMap::new(),
        nonce_aggregation_coeff: None,
        aggregated_nonce: None,
        challenge: None,
        partial_signatures: HashMap::new(),
        final_signature: None,
        hash_function,
    })
}

/// Aggregate multiple public keys into a single MuSig2 public key
///
/// This function computes an aggregated public key from multiple individual public keys
/// using the MuSig2 key aggregation algorithm.
pub fn aggregate_public_keys<G, H>(public_keys: &[G], hash_function: &H) -> Result<G, MuSig2Error>
where
    G: AffineRepr,
    H: MuSig2HashFunction<G::ScalarField>,
{
    // Use the with_coeffs function and return just the key
    let (agg_key, _) = aggregate_public_keys_with_coeffs(public_keys, hash_function)?;
    Ok(agg_key)
}

/// Version of aggregate_public_keys that also returns the computed coefficients
pub fn aggregate_public_keys_with_coeffs<G, H>(
    public_keys: &[G],
    hash_function: &H,
) -> Result<(G, HashMap<SignerId, G::ScalarField>), MuSig2Error>
where
    G: AffineRepr,
    H: MuSig2HashFunction<G::ScalarField>,
{
    if public_keys.is_empty() {
        return Err(MuSig2Error::InvalidPublicKey);
    }

    // Sort the public keys to ensure consistent behavior
    let mut sorted_keys = public_keys.to_vec();
    sorted_keys.sort_by(|a, b| {
        let mut a_bytes = Vec::new();
        let mut b_bytes = Vec::new();
        a.serialize_compressed(&mut a_bytes).unwrap();
        b.serialize_compressed(&mut b_bytes).unwrap();
        a_bytes.cmp(&b_bytes)
    });

    // Serialize all public keys for hashing
    let mut key_bytes_list = Vec::new();
    let mut all_keys_bytes = Vec::new();

    for key in &sorted_keys {
        let mut key_bytes = Vec::new();
        key.serialize_compressed(&mut key_bytes)?;
        key_bytes_list.push(key_bytes.clone());
        all_keys_bytes.extend_from_slice(&key_bytes);
    }

    // Create temporary aggregated key (simple sum) for coefficient calculation
    let mut temp_agg_key = <<G as AffineRepr>::Group as Zero>::zero();
    for key in &sorted_keys {
        temp_agg_key += key.into_group();
    }
    let temp_agg_key = temp_agg_key.into_affine();

    // Serialize temporary aggregated key
    let mut temp_agg_key_bytes = Vec::new();
    temp_agg_key.serialize_compressed(&mut temp_agg_key_bytes)?;

    // Compute key aggregation coefficients for each signer
    let mut coeffs = HashMap::new();

    for (idx, key) in sorted_keys.iter().enumerate() {
        // Use hash function with domain separation for key aggregation
        let data_slice1 = all_keys_bytes.as_slice();
        let data_slice2 = temp_agg_key_bytes.as_slice();
        let idx_bytes = (idx as u32).to_be_bytes();
        let data_slice3 = &idx_bytes[..];
        let data = &[data_slice1, data_slice2, data_slice3];

        let a_i = hash_function.hash("aggregate", data)?;

        let signer_id = SignerId::from_public_key(key)?;
        coeffs.insert(signer_id.clone(), a_i);
    }

    // Compute the true aggregated public key: X = ∑ a_i * X_i
    let mut agg_key = <<G as AffineRepr>::Group as Zero>::zero();
    for key in &sorted_keys {
        let signer_id = SignerId::from_public_key(key)?;
        let a_i = coeffs
            .get(&signer_id)
            .ok_or(MuSig2Error::InvalidPublicKey)?;
        agg_key += key.into_group() * a_i;
    }

    Ok((agg_key.into_affine(), coeffs))
}

/// Aggregate partial signatures into a final MuSig2 signature
pub fn aggregate_partial_signatures<G: AffineRepr>(
    partial_signatures: &[G::ScalarField],
    aggregated_nonce: G,
) -> Result<MuSig2Signature<G>, MuSig2Error> {
    if partial_signatures.is_empty() {
        return Err(MuSig2Error::InvalidPartialSignature);
    }

    // Sum all partial signatures
    let mut s = G::ScalarField::zero();
    for partial_sig in partial_signatures {
        s += *partial_sig;
    }

    Ok(MuSig2Signature {
        r: aggregated_nonce,
        s,
    })
}

/// Verify a MuSig2 signature against a public key and message
/// Verify a MuSig2 signature against a message and aggregated public key
pub fn verify_signature<G, H>(
    aggregated_public_key: G,
    message: &[u8],
    signature: &MuSig2Signature<G>,
    hash_function: &H,
) -> Result<bool, MuSig2Error>
where
    G: AffineRepr,
    H: MuSig2HashFunction<G::ScalarField>,
{
    // Serialize keys for challenge computation
    let mut agg_pk_bytes = Vec::new();
    let mut r_bytes = Vec::new();

    aggregated_public_key.serialize_compressed(&mut agg_pk_bytes)?;
    signature.r.serialize_compressed(&mut r_bytes)?;

    // Compute challenge c = H("signature", X || R || m)
    let data_slice1 = agg_pk_bytes.as_slice();
    let data_slice2 = r_bytes.as_slice();
    let data_slice3 = message;
    let data = &[data_slice1, data_slice2, data_slice3];
    let c = hash_function.hash("signature", data)?;

    // Verify the signature equation: R + c·X = s·G
    let lhs = signature.r.into_group() + (aggregated_public_key.into_group() * c);
    let rhs = G::generator() * signature.s;

    // Check if the equation holds
    Ok(lhs.into_affine() == rhs.into_affine())
}

impl<G, H> MuSig2Session<G, H>
where
    G: AffineRepr,
    H: MuSig2HashFunction<G::ScalarField>,
{
    /// Compute the aggregated public key for the session
    pub fn compute_aggregated_key(&mut self) -> Result<G, MuSig2Error> {
        if self.aggregated_public_key.is_some() {
            // Return cached result if already computed
            return Ok(self.aggregated_public_key.unwrap());
        }

        // Use the standalone function to get both the aggregated key and coefficients
        let (agg_key, coeffs) =
            aggregate_public_keys_with_coeffs(&self.cosigner_public_keys, &self.hash_function)?;

        // Store the results in the session
        self.key_aggregation_coeffs = coeffs;
        self.aggregated_public_key = Some(agg_key);
        self.state = MuSig2SessionState::KeyAggregated;

        Ok(agg_key)
    }

    /// Generate the nonces for the local signer
    pub fn generate_nonces(&mut self, rng: &mut impl RngCore) -> Result<(G, G), MuSig2Error> {
        // Ensure session is in the correct state
        if self.state != MuSig2SessionState::Initialized
            && self.state != MuSig2SessionState::KeyAggregated
            && self.state != MuSig2SessionState::NoncesCollected
        {
            return Err(MuSig2Error::InvalidSessionState(
                "Session must be initialized, have aggregated keys, or have collected nonces"
                    .into(),
            ));
        }

        // Compute aggregated key if not already done
        if self.aggregated_public_key.is_none() {
            let _ = self.compute_aggregated_key()?;
        }

        // Generate two random scalar values
        let r1 = G::ScalarField::rand(rng);
        let r2 = G::ScalarField::rand(rng);

        // Compute the corresponding nonce points: R_i = r_i * G
        let r1_point = (G::generator() * r1).into_affine();
        let r2_point = (G::generator() * r2).into_affine();

        // Store secret nonces securely
        self.secret_nonces = Some((r1, r2));

        // Get local signer ID
        let local_idx = self
            .local_signer_idx
            .ok_or(MuSig2Error::SignerNotInCosigners)?;
        let local_public_key = self.cosigner_public_keys[local_idx];
        let signer_id = SignerId::from_public_key(&local_public_key)?;

        // Store public nonces
        self.public_nonces.insert(signer_id, (r1_point, r2_point));
        self.state = MuSig2SessionState::NoncesGenerated;

        // Return public nonces
        Ok((r1_point, r2_point))
    }

    /// Add another signer's public nonces to the session
    pub fn add_public_nonces(
        &mut self,
        signer_pubkey: G,
        nonces: (G, G),
    ) -> Result<(), MuSig2Error> {
        // Validate the signer's public key
        if !self.cosigner_public_keys.contains(&signer_pubkey) {
            return Err(MuSig2Error::InvalidPublicKey);
        }

        // Check nonce validity (a basic check, could be more elaborate)
        if nonces.0 == G::zero() || nonces.1 == G::zero() {
            return Err(MuSig2Error::InvalidNonce);
        }

        // Store in public_nonces map
        let signer_id = SignerId::from_public_key(&signer_pubkey)?;
        self.public_nonces.insert(signer_id, nonces);

        self.state = MuSig2SessionState::NoncesCollected;

        Ok(())
    }

    /// Compute the aggregated nonce once all nonces are collected
    pub fn compute_aggregated_nonce(&mut self) -> Result<G, MuSig2Error> {
        // Check if we have nonces from all cosigners
        let mut missing_signers = Vec::new();

        for pk in &self.cosigner_public_keys {
            let signer_id = SignerId::from_public_key(pk)?;

            if !self.public_nonces.contains_key(&signer_id) {
                missing_signers.push(signer_id.0.clone());
            }
        }

        if !missing_signers.is_empty() {
            return Err(MuSig2Error::MissingNonces(missing_signers));
        }

        // Compute aggregated nonce
        // First, serialize all public keys and nonces for computing coefficient b
        let mut all_pk_bytes = Vec::new();
        let mut all_nonce_bytes = Vec::new();

        // Get aggregated public key
        let agg_key = self.compute_aggregated_key()?;
        let mut agg_key_bytes = Vec::new();
        agg_key.serialize_compressed(&mut agg_key_bytes)?;

        // Serialize public keys
        for pk in &self.cosigner_public_keys {
            let mut pk_bytes = Vec::new();
            pk.serialize_compressed(&mut pk_bytes)?;
            all_pk_bytes.extend_from_slice(&pk_bytes);
        }

        // Serialize nonces
        for pk in &self.cosigner_public_keys {
            let signer_id = SignerId::from_public_key(pk)?;
            let (r1, r2) = self
                .public_nonces
                .get(&signer_id)
                .ok_or(MuSig2Error::InvalidNonce)?;

            // Serialize both nonces
            let mut r1_bytes = Vec::new();
            let mut r2_bytes = Vec::new();
            r1.serialize_compressed(&mut r1_bytes)?;
            r2.serialize_compressed(&mut r2_bytes)?;

            all_nonce_bytes.extend_from_slice(&r1_bytes);
            all_nonce_bytes.extend_from_slice(&r2_bytes);
        }

        // Compute the aggregation coefficient b = H("nonce", L || X || R_1,1 || R_2,1 || ... || R_1,n || R_2,n || m)
        let data_slice1 = all_pk_bytes.as_slice();
        let data_slice2 = agg_key_bytes.as_slice();
        let data_slice3 = all_nonce_bytes.as_slice();
        let data_slice4 = self.message.as_slice();
        let data = &[data_slice1, data_slice2, data_slice3, data_slice4];
        let b = self.hash_function.hash("nonce", data)?;

        // Store the coefficient
        self.nonce_aggregation_coeff = Some(b);

        // Compute the aggregated nonce R = ∑(R_1,i + b·R_2,i)
        let mut r_agg = <<G as AffineRepr>::Group as Zero>::zero();
        for pk in &self.cosigner_public_keys {
            let signer_id = SignerId::from_public_key(pk)?;
            let (r1, r2) = self
                .public_nonces
                .get(&signer_id)
                .ok_or(MuSig2Error::InvalidNonce)?;

            r_agg += r1.into_group() + (r2.into_group() * b);
        }
        let r_agg = r_agg.into_affine();

        // Serialize aggregated nonce for challenge
        let mut r_agg_bytes = Vec::new();
        r_agg.serialize_compressed(&mut r_agg_bytes)?;

        // Compute challenge c = H("signature", X || R || m)
        let data_slice1 = agg_key_bytes.as_slice();
        let data_slice2 = r_agg_bytes.as_slice();
        let data_slice3 = self.message.as_slice();
        let data = &[data_slice1, data_slice2, data_slice3];
        let c = self.hash_function.hash("signature", data)?;

        // Store in session
        self.aggregated_nonce = Some(r_agg);
        self.challenge = Some(c);
        self.state = MuSig2SessionState::NonceAggregated;

        Ok(r_agg)
    }

    /// Creates a partial signature using the local signer's secret key
    pub fn sign(&mut self, secret_key: G::ScalarField) -> Result<G::ScalarField, MuSig2Error> {
        // Ensure aggregated key is computed
        if self.aggregated_public_key.is_none() {
            self.compute_aggregated_key()?;
        }

        // Ensure nonces are generated
        if self.secret_nonces.is_none() {
            return Err(MuSig2Error::InvalidSessionState(
                "Nonces must be generated before signing".into(),
            ));
        }

        // Ensure aggregated nonce is computed
        if self.aggregated_nonce.is_none() {
            self.compute_aggregated_nonce()?;
        }

        // Get the nonces and coefficients
        let (r1, r2) = self.secret_nonces.ok_or(MuSig2Error::InvalidNonce)?;

        let b = self
            .nonce_aggregation_coeff
            .ok_or(MuSig2Error::InvalidSessionState(
                "Nonce aggregation coefficient not computed".into(),
            ))?;

        let c = self.challenge.ok_or(MuSig2Error::InvalidSessionState(
            "Challenge not computed".into(),
        ))?;

        // Get local signer's key and coefficient
        let local_idx = self
            .local_signer_idx
            .ok_or(MuSig2Error::SignerNotInCosigners)?;
        let local_public_key = self.cosigner_public_keys[local_idx];
        let signer_id = SignerId::from_public_key(&local_public_key)?;

        let a_i = self
            .key_aggregation_coeffs
            .get(&signer_id)
            .ok_or(MuSig2Error::InvalidPublicKey)?;

        // Compute partial signature s_i = r_1 + b*r_2 + c*a_i*x_i
        let s_i = r1 + (b * r2) + (c * a_i * secret_key);

        // Add partial signature to session
        self.partial_signatures.insert(signer_id, s_i);
        self.state = MuSig2SessionState::PartiallySignedLocal;

        // Return partial signature
        Ok(s_i)
    }

    /// Adds another signer's partial signature to the session
    pub fn add_partial_signature(
        &mut self,
        signer_public_key: G,
        partial_sig: G::ScalarField,
    ) -> Result<(), MuSig2Error> {
        // Verify the public key corresponds to a cosigner
        if !self.cosigner_public_keys.contains(&signer_public_key) {
            return Err(MuSig2Error::InvalidPublicKey);
        }

        // Add to session's partial_signatures map
        let signer_id = SignerId::from_public_key(&signer_public_key)?;
        self.partial_signatures.insert(signer_id, partial_sig);

        // Check if we have all signatures
        if self.partial_signatures.len() == self.cosigner_public_keys.len() {
            self.state = MuSig2SessionState::SignaturesCollected;
        }

        Ok(())
    }

    /// Aggregates all partial signatures to create the final signature
    pub fn aggregate_signatures(&mut self) -> Result<MuSig2Signature<G>, MuSig2Error> {
        // Check if we have partial signatures from all cosigners
        let mut missing_signers = Vec::new();

        for pk in &self.cosigner_public_keys {
            let signer_id = SignerId::from_public_key(pk)?;

            if !self.partial_signatures.contains_key(&signer_id) {
                missing_signers.push(signer_id.0.clone());
            }
        }

        if !missing_signers.is_empty() {
            return Err(MuSig2Error::MissingPartialSignatures(missing_signers));
        }

        // Ensure we have an aggregated nonce
        let r_agg = self.aggregated_nonce.ok_or(MuSig2Error::InvalidNonce)?;

        // Sum all partial signatures
        let mut s = G::ScalarField::zero();
        for (_, partial_sig) in &self.partial_signatures {
            s += *partial_sig;
        }

        // Create the final signature
        let signature = MuSig2Signature { r: r_agg, s };

        // Store in session
        self.final_signature = Some(signature.clone());
        self.state = MuSig2SessionState::Completed;

        // Return final signature
        Ok(signature)
    }

    /// Verifies the aggregated signature against the aggregated public key
    pub fn verify(&self) -> Result<bool, MuSig2Error> {
        // Ensure we have a final signature
        let signature = self
            .final_signature
            .as_ref()
            .ok_or(MuSig2Error::InvalidAggregatedSignature)?;

        // Ensure we have an aggregated public key
        let agg_key = self
            .aggregated_public_key
            .ok_or(MuSig2Error::InvalidPublicKey)?;

        // Use the standalone function for verification
        verify_signature(agg_key, &self.message, signature, &self.hash_function)
    }
}
