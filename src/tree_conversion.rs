use crate::Expr;
use std::rc::Rc;
use tree_ds::prelude::Node;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeKind {
    Key(String),
    And,
    Or,
    Not,
    Threshold(u32),
    WeightedThreshold(u32),
    Weight(u32),
}

impl std::fmt::Display for NodeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeKind::Key(key) => write!(f, "Key({})", key),
            NodeKind::And => write!(f, "AND"),
            NodeKind::Or => write!(f, "OR"),
            NodeKind::Not => write!(f, "NOT"),
            NodeKind::Threshold(k) => write!(f, "Threshold({})", k),
            NodeKind::WeightedThreshold(k) => write!(f, "WeightedThreshold({})", k),
            NodeKind::Weight(w) => write!(f, "Weight({})", w),
        }
    }
}

pub type TreeNode = Node<NodeKind, NodeKind>;

impl Expr {
    pub fn to_tree(&self) -> Rc<TreeNode> {
        match self {
            Expr::Key(key) => TreeNode::new(NodeKind::Key(key.clone())),
            Expr::And(exprs) => {
                let node = TreeNode::new(NodeKind::And);
                for expr in exprs {
                    node.add_child(expr.to_tree());
                }
                node
            }
            Expr::Or(exprs) => {
                let node = TreeNode::new(NodeKind::Or);
                for expr in exprs {
                    node.add_child(expr.to_tree());
                }
                node
            }
            Expr::Not(expr) => {
                let node = TreeNode::new(NodeKind::Not);
                node.add_child(expr.to_tree());
                node
            }
            Expr::Threshold { k, subs } => {
                let node = TreeNode::new(NodeKind::Threshold(*k));
                for expr in subs {
                    node.add_child(expr.to_tree());
                }
                node
            }
            Expr::WeightedThreshold { k, subs } => {
                let node = TreeNode::new(NodeKind::WeightedThreshold(*k));
                for (expr, weight) in subs {
                    let weight_node = TreeNode::new(NodeKind::Weight(*weight));
                    weight_node.add_child(expr.to_tree());
                    node.add_child(weight_node);
                }
                node
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_key() {
        let expr = Expr::Key("A".to_string());
        let tree = expr.to_tree();
        assert_eq!(tree.data(), &NodeKind::Key("A".to_string()));
        assert_eq!(tree.children().len(), 0);
    }

    #[test]
    fn test_and_expression() {
        let expr = Expr::And(vec![Expr::Key("A".to_string()), Expr::Key("B".to_string())]);
        let tree = expr.to_tree();
        assert_eq!(tree.data(), &NodeKind::And);
        assert_eq!(tree.children().len(), 2);
        assert_eq!(tree.children()[0].data(), &NodeKind::Key("A".to_string()));
        assert_eq!(tree.children()[1].data(), &NodeKind::Key("B".to_string()));
    }

    #[test]
    fn test_weighted_threshold() {
        let expr = Expr::WeightedThreshold {
            k: 3,
            subs: vec![
                (Expr::Key("A".to_string()), 2),
                (Expr::Key("B".to_string()), 1),
            ],
        };
        let tree = expr.to_tree();
        assert_eq!(tree.data(), &NodeKind::WeightedThreshold(3));
        assert_eq!(tree.children().len(), 2);

        let first_weight = &tree.children()[0];
        assert_eq!(first_weight.data(), &NodeKind::Weight(2));
        assert_eq!(
            first_weight.children()[0].data(),
            &NodeKind::Key("A".to_string())
        );

        let second_weight = &tree.children()[1];
        assert_eq!(second_weight.data(), &NodeKind::Weight(1));
        assert_eq!(
            second_weight.children()[0].data(),
            &NodeKind::Key("B".to_string())
        );
    }

    #[test]
    fn test_complex_expression() {
        let expr = Expr::And(vec![
            Expr::Or(vec![Expr::Key("A".to_string()), Expr::Key("B".to_string())]),
            Expr::Not(Box::new(Expr::Threshold {
                k: 2,
                subs: vec![
                    Expr::Key("C".to_string()),
                    Expr::Key("D".to_string()),
                    Expr::Key("E".to_string()),
                ],
            })),
        ]);

        let tree = expr.to_tree();
        assert_eq!(tree.data(), &NodeKind::And);
        assert_eq!(tree.children().len(), 2);

        let or_node = &tree.children()[0];
        assert_eq!(or_node.data(), &NodeKind::Or);
        assert_eq!(or_node.children().len(), 2);
        assert_eq!(
            or_node.children()[0].data(),
            &NodeKind::Key("A".to_string())
        );
        assert_eq!(
            or_node.children()[1].data(),
            &NodeKind::Key("B".to_string())
        );

        let not_node = &tree.children()[1];
        assert_eq!(not_node.data(), &NodeKind::Not);
        assert_eq!(not_node.children().len(), 1);

        let threshold_node = &not_node.children()[0];
        assert_eq!(threshold_node.data(), &NodeKind::Threshold(2));
        assert_eq!(threshold_node.children().len(), 3);
        assert_eq!(
            threshold_node.children()[0].data(),
            &NodeKind::Key("C".to_string())
        );
        assert_eq!(
            threshold_node.children()[1].data(),
            &NodeKind::Key("D".to_string())
        );
        assert_eq!(
            threshold_node.children()[2].data(),
            &NodeKind::Key("E".to_string())
        );
    }
}
