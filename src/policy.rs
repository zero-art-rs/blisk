use ark_ec::AffineRepr;
use std::cmp::Ordering;
use std::fmt::{self, Display};
use std::hash::{Hash, Hasher};
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
pub struct PolicyTree<G: AffineRepr>(pub(crate) Tree<u64, PolicyNode<G>>);

impl<G: AffineRepr> PolicyTree<G> {
    pub fn new(tree: Tree<u64, PolicyNode<G>>) -> Self {
        Self(tree)
    }

    /// get a list of needed users labels to resolve the policy (build the tree completely)
    /// typyially, resolved by OR-gates' inputs
    pub fn get_resolution_list(&self) -> Vec<String> {
        self.0
            .get_nodes()
            .iter()
            .filter_map(|node| match node {
                PolicyNode::OrGate(None) => node
                    .get_children_ids()
                    .map(|node_id| self.0.get_node_by_id(node_id).unwrap().get_label())
                    .collect(),
                _ => None,
            })
            .flatten()
            .collect()
    }
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
