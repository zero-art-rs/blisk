use nom::{
    IResult, Parser,
    branch::alt,
    bytes::complete::{tag, take_while1},
    character::complete::{char, multispace0, multispace1, u32 as parse_u32},
    multi::separated_list0,
    sequence::{delimited, preceded},
};

#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub enum PolicyExpr {
    Key(String),
    And(Vec<PolicyExpr>),
    Or(Vec<PolicyExpr>),
    Not(Box<PolicyExpr>),
    Threshold {
        k: u32,
        subs: Vec<PolicyExpr>,
    },
    WeightedThreshold {
        k: u32,
        subs: Vec<(PolicyExpr, u32)>,
    },
    Policy {
        name: String,
        expr: Box<PolicyExpr>,
    },
}

/// ======= Parser =======

fn identifier(input: &str) -> IResult<&str, String> {
    take_while1(|c: char| c.is_alphanumeric() || c == '_' || c == '-')
        .map(|s: &str| s.to_string())
        .parse(input)
}

fn key_expr(input: &str) -> IResult<&str, PolicyExpr> {
    identifier.map(PolicyExpr::Key).parse(input)
}

pub fn parse(input: &str) -> IResult<&str, PolicyExpr> {
    preceded(multispace0, alt((list_expr, key_expr))).parse(input)
}

fn list_expr(input: &str) -> IResult<&str, PolicyExpr> {
    delimited(
        preceded(multispace0, char('(')),
        preceded(
            multispace0,
            alt((
                parse_and,
                parse_or,
                parse_not,
                parse_threshold,
                parse_weighted_threshold,
                parse_policy,
            )),
        ),
        preceded(multispace0, char(')')),
    )
    .parse(input)
}

fn parse_and(input: &str) -> IResult<&str, PolicyExpr> {
    tag("and")
        .and(multispace1)
        .and(separated_list0(multispace1, parse))
        .map(|(_, exprs)| PolicyExpr::And(exprs))
        .parse(input)
}

fn parse_or(input: &str) -> IResult<&str, PolicyExpr> {
    tag("or")
        .and(multispace1)
        .and(separated_list0(multispace1, parse))
        .map(|(_, exprs)| PolicyExpr::Or(exprs))
        .parse(input)
}

fn parse_not(input: &str) -> IResult<&str, PolicyExpr> {
    tag("not")
        .and(multispace1)
        .and(parse)
        .map(|(_, e)| PolicyExpr::Not(Box::new(e)))
        .parse(input)
}

fn parse_threshold(input: &str) -> IResult<&str, PolicyExpr> {
    tag("threshold")
        .and(multispace1)
        .and(parse_u32)
        .and(multispace1)
        .and(separated_list0(multispace1, parse))
        .map(|(((_, k), _), subs)| PolicyExpr::Threshold { k, subs })
        .parse(input)
}

fn parse_weighted_threshold(input: &str) -> IResult<&str, PolicyExpr> {
    tag("weighted-threshold")
        .and(multispace1)
        .and(parse_u32)
        .and(multispace1)
        .and(separated_list0(multispace1, weighted_sub))
        .map(|(((_, k), _), subs)| PolicyExpr::WeightedThreshold { k, subs })
        .parse(input)
}

fn parse_policy(input: &str) -> IResult<&str, PolicyExpr> {
    tag("policy")
        .and(multispace1)
        .and(identifier)
        .and(multispace1)
        .and(parse)
        .map(|(((_, name), _), expr)| PolicyExpr::Policy {
            name,
            expr: Box::new(expr),
        })
        .parse(input)
}

fn weighted_sub(input: &str) -> IResult<&str, (PolicyExpr, u32)> {
    delimited(
        preceded(multispace0, char('(')),
        key_expr
            .and(multispace1)
            .and(parse_u32)
            .map(|((expr, _), weight)| (expr, weight)),
        preceded(multispace0, char(')')),
    )
    .parse(input)
}
