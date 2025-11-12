use crate::errors::PolicyError;
use ark_ec::AffineRepr;
use ark_ec::CurveGroup;
use ark_ff::{BigInt, BigInteger, Field, PrimeField, UniformRand};
use ark_serialize::CanonicalSerializeHashExt;
use itertools::Itertools;
use std::cmp::Ordering;
use std::fmt::{self, Display};
use std::hash::{Hash, Hasher};
use std::ops::Add;
use tree_ds::prelude::{Node, Tree};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum PolicyNode<G: AffineRepr> {
    #[default]
    Empty,
    UserKey((String, G)),
    AndGate(Option<G>),
    OrGate(Option<G>),
}

impl<G: AffineRepr + PartialEq> Hash for PolicyNode<G> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        std::mem::discriminant(self).hash(state);
    }
}

impl<G: AffineRepr> fmt::Display for PolicyNode<G> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyNode::Empty => write!(f, "Empty"),
            PolicyNode::UserKey((label, _)) => write!(f, "UserKey({:?})", label),
            PolicyNode::AndGate(and_gate) => write!(f, "AndGate({:?})", and_gate),
            PolicyNode::OrGate(o) => write!(f, "OrGate({:?})", o),
        }
    }
}

#[derive(Debug)]
pub struct PolicyTree<G: AffineRepr> {
    pub(crate) tree: Tree<u64, PolicyNode<G>>,
    pub(crate) iota: fn(G) -> G::ScalarField,
}

impl<G: AffineRepr> PolicyTree<G> {
    pub fn new(tree: Tree<u64, PolicyNode<G>>, iota: fn(G) -> G::ScalarField) -> Self {
        Self { tree, iota }.resolve_and_gates()
    }

    /// get a list of needed users labels to resolve the policy (build the tree completely)
    /// typyially, resolved by OR-gates' inputs
    pub fn get_resolution_list(&self) -> Vec<String> {
        self.tree
            .get_nodes()
            .iter()
            .filter_map(|node| match node.get_value().unwrap().unwrap() {
                PolicyNode::OrGate(None) => Some(
                    node.get_children_ids()
                        .unwrap()
                        .iter()
                        .filter_map(|node_id| {
                            match self
                                .tree
                                .get_node_by_id(node_id)
                                .unwrap()
                                .get_value()
                                .unwrap()
                                .unwrap()
                            {
                                PolicyNode::UserKey(u) => Some(u.0),
                                _ => None,
                            }
                        })
                        .collect::<Vec<_>>(),
                ),
                _ => None,
            })
            .flatten()
            .sorted()
            .dedup()
            .collect()
    }

    /// Checks if the policy tree is resolved (i.e. all nodes have values)
    pub fn is_resolved(&self) -> bool {
        self.tree
            .get_root_node()
            .unwrap()
            .get_value()
            .unwrap()
            .is_some()
    }

    fn resolve_and_gate(&self, root: &Node<u64, PolicyNode<G>>) -> Option<G> {
        match root.get_value().unwrap().unwrap() {
            PolicyNode::UserKey((_, u)) => Some(u),
            PolicyNode::OrGate(Some(u)) => Some(u),
            PolicyNode::OrGate(None) => {
                root.get_children_ids()
                    .unwrap()
                    .iter()
                    .for_each(|child_id| {
                        self.resolve_and_gate(&self.tree.get_node_by_id(&child_id).unwrap());
                    });
                None
            }

            PolicyNode::AndGate(Some(u)) => Some(u),
            PolicyNode::AndGate(None) => {
                let res = root
                    .get_children_ids()
                    .unwrap()
                    .iter()
                    .map(|x| self.resolve_and_gate(&self.tree.get_node_by_id(x).unwrap()))
                    .fold_options(G::ZERO, |acc, x| (acc + x).into());
                root.update_value(|v| *v = Some(PolicyNode::AndGate(res)))
                    .unwrap();
                res
            }
            _ => None,
        }
    }

    fn resolve_or_gate(
        &self,
        root: &Node<u64, PolicyNode<G>>,
        secret_key: G::ScalarField,
    ) -> Result<(Option<G::ScalarField>, Option<G>), PolicyError> {
        match root.get_value().unwrap().unwrap() {
            PolicyNode::UserKey((_, u)) => {
                match u == (G::generator() * secret_key).into_affine() {
                    true => Ok((Some(secret_key), Some(u))), // our leaf node
                    false => Ok((None, Some(u))),
                }
            }
            PolicyNode::OrGate(Some(u)) => Ok((None, Some(u))),
            PolicyNode::OrGate(None) => {
                if root.get_children_ids().unwrap().len() != 2 {
                    return Err(PolicyError::ResolutionError(
                        "OR gate must have exactly 2 childs".into(),
                    ));
                }
                let (s_a, Q_a) = self.resolve_or_gate(
                    &self
                        .tree
                        .get_node_by_id(&root.get_children_ids().unwrap()[0])
                        .unwrap(),
                    secret_key,
                )?;
                let (s_b, Q_b) = self.resolve_or_gate(
                    &self
                        .tree
                        .get_node_by_id(&root.get_children_ids().unwrap()[1])
                        .unwrap(),
                    secret_key,
                )?;
                if let Some(s_a) = s_a
                    && let Some(Q_b) = Q_b
                {
                    let s = (self.iota)((Q_b * s_a).into_affine());
                    let Q = (G::generator() * s).into_affine();
                    root.update_value(|x| *x = Some(PolicyNode::OrGate(Some(Q))))
                        .unwrap();
                    Ok((Some(s), Some(Q)))
                } else if let Some(s_b) = s_b
                    && let Some(Q_a) = Q_a
                {
                    let s = (self.iota)((Q_a * s_b).into_affine());
                    let Q = (G::generator() * s).into_affine();
                    root.update_value(|x| *x = Some(PolicyNode::OrGate(Some(Q))))
                        .unwrap();
                    Ok((Some(s), Some(Q)))
                } else {
                    Ok((None, None))
                }
            }
            PolicyNode::AndGate(Some(u)) => Ok((None, Some(u))),
            PolicyNode::AndGate(None) => {
                for child_id in root.get_children_ids().unwrap() {
                    self.resolve_or_gate(
                        &self.tree.get_node_by_id(&child_id).unwrap(),
                        secret_key,
                    )?;
                }
                Ok((None, None))
            }
            _ => Ok((None, None)),
        }
    }

    fn resolve_and_gates(self) -> Self {
        self.resolve_and_gate(&mut self.tree.get_root_node().unwrap());
        self
    }

    /// Resolve the user's keys in the policy tree
    pub fn resolve(self, key: G::ScalarField) -> Result<Self, PolicyError> {
        self.resolve_or_gate(&mut self.tree.get_root_node().unwrap(), key)?;
        self.resolve_and_gate(&mut self.tree.get_root_node().unwrap());
        Ok(self)
    }
}

impl<G: AffineRepr> Display for PolicyTree<G> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.tree)
    }
}

pub struct Signer<G: AffineRepr> {
    secret_key: G::ScalarField,
    public_key: G,
}

impl<G: AffineRepr> Signer<G> {
    pub fn new(secret_key: G::ScalarField, public_key: G) -> Self {
        Self {
            secret_key,
            public_key,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::CompilationOptions;
    use crate::compiler::Compiler;
    use crate::parser::PolicyExpr;
    use crate::parser::parse;
    use ark_ec::CurveGroup;
    use ark_ed25519::{EdwardsAffine as G1Affine, Fr};
    use std::collections::HashMap;
    use std::ops::Mul;

    fn iota(P: G1Affine) -> Fr {
        Fr::from_le_bytes_mod_order(&P.x().unwrap().into_bigint().to_bytes_le())
    }

    fn setup_test_keys(k: usize) -> (HashMap<String, G1Affine>, HashMap<String, Fr>) {
        let mut public_keys = HashMap::new();
        let mut private_keys = HashMap::new();
        // Generate some test public keys using random scalars
        for i in 1..=k {
            let scalar = Fr::from(i as u64);
            let point = G1Affine::generator().mul(scalar).into_affine();
            public_keys.insert(format!("Key {}", i), point);
            private_keys.insert(format!("Key {}", i), scalar);
        }
        (public_keys, private_keys)
    }

    #[test]
    fn test_resolve_cnf() {
        let circuits = [
            "(and A B)",
            "(and (or A B) (or A C))",
            "(and (or A B) C)",
            "(and (or A (or B C)) (or B (or D C)))",
        ];
        let compiler = Compiler::new();
        for c in circuits {
            let (_, expr) = parse(c).unwrap();
            let test_keys = expr.generate_random_keys().unwrap();
            let public_keys = test_keys
                .iter()
                .map(|(k, (_, pk))| (k.clone(), *pk))
                .collect();
            let options = CompilationOptions {
                public_keys,
                iota,
                name: "Test Policy".to_string(),
            };
            let policy = compiler.compile(&expr, options).unwrap();
            let resolved_policy = policy.resolve(test_keys["A"].0).unwrap();
            println!("{:}", resolved_policy);
        }
    }
}
