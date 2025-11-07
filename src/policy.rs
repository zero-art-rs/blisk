use ark_ec::AffineRepr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyNode<G: AffineRepr> {
    UserKey(G),
    AndGate(Option<G>),
    OrGate(Option<G>),
}

pub struct PolicyTree<G: AffineRepr>(tree_ds::prelude::Tree<u64, PolicyNode<G>>);
