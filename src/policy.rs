use ark_ec::AffineRepr;
use itertools::Itertools;
use std::cmp::Ordering;
use std::fmt::{self, Display};
use std::hash::{Hash, Hasher};
use std::ops::Add;
use tree_ds::prelude::{Node, Tree};
use ark_ec::CurveGroup;

use crate::errors::PolicyError;

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
pub struct PolicyTree<G: AffineRepr>(pub(crate) Tree<u64, PolicyNode<G>>);

impl<G: AffineRepr> PolicyTree<G> {
    pub fn new(tree: Tree<u64, PolicyNode<G>>) -> Self {
        Self(tree).resolve_and_gates()
    }

    /// get a list of needed users labels to resolve the policy (build the tree completely)
    /// typyially, resolved by OR-gates' inputs
    pub fn get_resolution_list(&self) -> Vec<String> {
        self.0
            .get_nodes()
            .iter()
            .filter_map(|node| match node.get_value().unwrap().unwrap() {
                PolicyNode::OrGate(None) => Some(
                    node.get_children_ids()
                        .unwrap()
                        .iter()
                        .filter_map(|node_id| {
                            match self
                                .0
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
        self.0
            .get_root_node()
            .unwrap()
            .get_value()
            .unwrap()
            .is_some()
    }

    fn resolve_and_gate(&self, root: &mut Node<u64, PolicyNode<G>>) -> Option<G> {
        match root.get_value().unwrap().unwrap() {
            PolicyNode::UserKey((_, u)) => Some(u),
            PolicyNode::OrGate(Some(u)) => Some(u),
            PolicyNode::OrGate(None) => {
                root.get_children_ids()
                    .unwrap()
                    .iter()
                    .for_each(|child_id| {
                        self.resolve_and_gate(&mut self.0.get_node_by_id(&child_id).unwrap());
                    });
                None
            }

            PolicyNode::AndGate(Some(u)) => Some(u),
            PolicyNode::AndGate(None) => {
                let res = root
                    .get_children_ids()
                    .unwrap()
                    .iter()
                    .map(|x| self.resolve_and_gate(&mut self.0.get_node_by_id(x).unwrap()))
                    .fold_options(G::ZERO, |acc, x| (acc + x).into());
                root.update_value(|v| *v = Some(PolicyNode::AndGate(res)))
                    .unwrap();
                res
            }
            _ => None,
        }
    }

    fn resolve_or_gate(&self, root: &mut Node<u64, PolicyNode<G>>, secret_key: G::ScalarField) -> Result<(Option<G::ScalarField>, Option<G>), PolicyError> {
        match root.get_value().unwrap().unwrap() {
            PolicyNode::UserKey((_, u)) => {
                match u == (G::generator() * secret_key).into_affine() {
                    true => Ok((Some(secret_key), Some(u))),
                    false => Ok((None, Some(u))),
                }
            },
            PolicyNode::OrGate(Some(u)) => Ok((None, Some(u))),
            PolicyNode::OrGate(None) => {
                if root.get_children_ids()
                    .unwrap().len() != 2 {
                    return Err(PolicyError::ResolutionError("OR gate must have exactly 2 childs".into()));
                }
                let left_child = self.0.get_node_by_id(&root.get_children_ids().unwrap()[0]).unwrap();
                let right_child = self.0.get_node_by_id(&root.get_children_ids().unwrap()[1]).unwrap();

                Ok((None, None))
            }

            PolicyNode::AndGate(Some(u)) => Ok((None, Some(u))),
            PolicyNode::AndGate(None) => {
                root.get_children_ids()
                    .unwrap()
                    .iter()
                    .for_each(|child_id| {
                        self.resolve_or_gate(&mut self.0.get_node_by_id(&child_id).unwrap(), secret_key);
                    });
                Ok((None, None))
            }
            _ => Ok((None, None)),
        }
    }

    fn resolve_and_gates(self) -> Self {
        self.resolve_and_gate(&mut self.0.get_root_node().unwrap());
        self
    }

    /// Resolve the user's keys in the policy tree
    //pub fn resolve(self, key: G::ScalarField) -> Self {}
}

impl<G: AffineRepr> Display for PolicyTree<G> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
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
