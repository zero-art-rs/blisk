use crate::errors::PolicyError;
use crate::parser::PolicyExpr;
use ark_ec::AffineRepr;
use ark_ec::CurveGroup;
use ark_ff::{BigInt, BigInteger, Field, PrimeField, UniformRand};
use ark_serialize::CanonicalSerializeHashExt;
use itertools::Itertools;
use std::cmp::Ordering;
use std::collections::HashSet;
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
    pub(crate) occupied_or_gates: HashSet<u64>,
    pub(crate) is_cnf: bool,
    pub(crate) iota: fn(G) -> G::ScalarField,
    pub(crate) aggregate: fn(Vec<G>) -> G,
}

impl<G: AffineRepr> PolicyTree<G> {
    pub(crate) fn new(
        tree: Tree<u64, PolicyNode<G>>,
        is_cnf: bool,
        iota: fn(G) -> G::ScalarField,
        aggregate: fn(Vec<G>) -> G,
    ) -> Self {
        Self {
            tree,
            occupied_or_gates: HashSet::new(),
            is_cnf,
            iota,
            aggregate,
        }
        .resolve_and_gates()
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

    /// Returns the total number of children of the root AND gate (total number of clauses)
    pub fn get_clauses_count(&self) -> Result<usize, PolicyError> {
        if !self.is_cnf {
            return Err(PolicyError::NotCNF);
        }
        Ok(self
            .tree
            .get_root_node()
            .unwrap()
            .get_children_ids()
            .unwrap()
            .len())
    }

    /// Returns the maximum total number of nodes among all clauses (children of the top-level AND gate)
    pub fn get_maximal_clause_depth(&self) -> Result<usize, PolicyError> {
        if !self.is_cnf {
            return Err(PolicyError::NotCNF);
        }

        fn count_nodes<G: AffineRepr>(
            tree: &Tree<u64, PolicyNode<G>>,
            node: &Node<u64, PolicyNode<G>>,
        ) -> usize {
            let children_ids = node.get_children_ids().unwrap();
            1 + children_ids
                .iter()
                .map(|child_id| count_nodes(tree, &tree.get_node_by_id(child_id).unwrap()))
                .sum::<usize>()
        }

        let max_nodes = self
            .tree
            .get_root_node()
            .unwrap()
            .get_children_ids()
            .unwrap()
            .iter()
            .map(|child_id| count_nodes(&self.tree, &self.tree.get_node_by_id(child_id).unwrap()))
            .max()
            .unwrap_or(0);

        Ok(max_nodes)
    }

    /// Converts the PolicyTree back to a PolicyExpr
    pub fn to_expr(&self) -> PolicyExpr {
        fn node_to_expr<G: AffineRepr>(
            tree: &Tree<u64, PolicyNode<G>>,
            node: &Node<u64, PolicyNode<G>>,
        ) -> PolicyExpr {
            match node.get_value().unwrap().unwrap() {
                PolicyNode::UserKey((label, _)) => PolicyExpr::Key(label),
                PolicyNode::AndGate(_) => {
                    let children: Vec<PolicyExpr> = node
                        .get_children_ids()
                        .unwrap()
                        .iter()
                        .map(|child_id| node_to_expr(tree, &tree.get_node_by_id(child_id).unwrap()))
                        .collect();
                    PolicyExpr::And(children)
                }
                PolicyNode::OrGate(_) => {
                    let children: Vec<PolicyExpr> = node
                        .get_children_ids()
                        .unwrap()
                        .iter()
                        .map(|child_id| node_to_expr(tree, &tree.get_node_by_id(child_id).unwrap()))
                        .collect();
                    PolicyExpr::Or(children)
                }
                PolicyNode::Empty => PolicyExpr::Key("__empty__".to_string()),
            }
        }

        node_to_expr(&self.tree, &self.tree.get_root_node().unwrap())
    }

    pub fn get_clauses_public_keys(&self) -> Result<Vec<G>, PolicyError> {
        if !self.is_cnf {
            return Err(PolicyError::NotCNF);
        }
        self.tree
            .get_root_node()
            .unwrap()
            .get_children_ids()
            .unwrap()
            .iter()
            .map(|child_id| {
                match self
                    .tree
                    .get_node_by_id(child_id)
                    .unwrap()
                    .get_value()
                    .unwrap()
                    .unwrap()
                {
                    PolicyNode::OrGate(clause_pk) => {
                        clause_pk.ok_or(PolicyError::MissingClausePublicKey)
                    }
                    PolicyNode::UserKey((_, pk)) => Ok(pk),
                    _ => Err(PolicyError::InvalidGate),
                }
            })
            .collect()
    }

    pub fn resolve_clauses_private_keys(
        &mut self,
        secret_key: G::ScalarField,
    ) -> Result<Vec<(G::ScalarField, G)>, PolicyError> {
        if !self.is_cnf {
            return Err(PolicyError::NotCNF);
        }
        Ok(self
            .tree
            .get_root_node()
            .unwrap()
            .get_children_ids()
            .unwrap()
            .iter()
            .filter_map(|child_id| {
                self.resolve_or_gate(&self.tree.get_node_by_id(child_id).unwrap(), secret_key)
                    .map(|(sk, pk)| match (sk, pk) {
                        (Some(s), Some(p)) => match self.occupied_or_gates.contains(child_id) {
                            true => None, // if this clause is already resolved, skip it
                            false => {
                                self.occupied_or_gates.insert(*child_id);
                                Some((s, p))
                            }
                        },
                        _ => None,
                    })
                    .ok()
                    .flatten()
            })
            .collect())
    }

    pub fn get_public_key(&self) -> Option<G> {
        match self
            .tree
            .get_root_node()
            .unwrap()
            .get_value()
            .unwrap()
            .unwrap()
        {
            PolicyNode::AndGate(root) => root,
            _ => None,
        }
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
                    .collect::<Option<Vec<_>>>()
                    .map(self.aggregate);
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
            PolicyNode::OrGate(existing_key) => {
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
                    // Left child has secret, right child has public key
                    // Compute derived key using DH
                    let s = (self.iota)((Q_b * s_a).into_affine());
                    let Q = (G::generator() * s).into_affine();
                    root.update_value(|x| *x = Some(PolicyNode::OrGate(Some(Q))))
                        .unwrap();
                    Ok((Some(s), Some(Q)))
                } else if let Some(s_b) = s_b
                    && let Some(Q_a) = Q_a
                {
                    // Right child has secret, left child has public key
                    // Compute derived key using DH
                    let s = (self.iota)((Q_a * s_b).into_affine());
                    let Q = (G::generator() * s).into_affine();
                    root.update_value(|x| *x = Some(PolicyNode::OrGate(Some(Q))))
                        .unwrap();
                    Ok((Some(s), Some(Q)))
                } else if let Some(Q) = existing_key {
                    // Gate already has a key from previous resolution
                    Ok((None, Some(Q)))
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

    fn aggregate(points: Vec<G1Affine>) -> G1Affine {
        points
            .iter()
            .fold(G1Affine::zero(), |acc, p| (acc + p).into())
    }

    #[test]
    fn test_resolve_cnf() {
        let circuits = [
            "(policy policy_A_and_B
                (and A B))",
            "(policy policy_A_or_BC
                (and
                    (or A B)
                    (or A C)))",
            "(policy policy_C_and_A_or_B
                (and
                    (or A B)
                    C))",
            "(policy policy_complex
                (or
                    (and A (or B C))
                    (or B (or D C))))",
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
                transform_to_cnf: true,
                aggregate,
                iota,
            };
            let policy = compiler.compile(&expr, options).unwrap();
            let expr_compiled = policy.to_expr();
            println!("Compiled Expression: {}", expr_compiled);
            let resolved_policy = policy.resolve(test_keys["A"].0).unwrap();
            println!("{:}", resolved_policy);
        }
    }
}
