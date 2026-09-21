//! Lookup callbacks used by the SHA-3 extraction harnesses.

use std::borrow::Cow;

use ff::Field;
use haloumi::{
    core::info_traits::CreateQuery as _,
    ir::{expr::IRBexpr, meta::HasMeta, stmt::{EmitIf as _, IRStmt}},
    ir_gen::{lookups::{callbacks::{LookupCallbacks, LookupResult}, table::LookupTableGenerator}, temps::{ExprOrTemp, Temps}},
    synthesis::lookups::Lookup,
};
use midnight_curves::Fq;
use midnight_proofs::plonk::{AdviceQuery, Expression};

#[derive(Debug, Default)]
pub(crate) struct Sha3LookupCallbacks;

pub(crate) fn sha3_lookup_callbacks() -> Sha3LookupCallbacks { Sha3LookupCallbacks }

#[derive(Clone, Copy)]
enum Mode { Byte, Any, Tag12, Tagged }

impl Sha3LookupCallbacks {
    fn mode(name: &str) -> Option<Mode> {
        if name.starts_with("spread byte lookup") { Some(Mode::Byte) }
        else if name.starts_with("decomposition lookup") && (name.ends_with("limb 0") || name.ends_with("limb 1") || name.ends_with("limb 2")) { Some(Mode::Any) }
        else if name == "decomposition lookup: limb 3" { Some(Mode::Tag12) }
        else if name.starts_with("decomposition lookup") && (name.ends_with("limb 4") || name.ends_with("limb 5")) { Some(Mode::Tagged) }
        else { None }
    }

    fn parts<'a>(mode: Mode, l: &'a Lookup<Expression<Fq>>, temps: &mut Temps) -> (ExprOrTemp<Cow<'a, Expression<Fq>>>, ExprOrTemp<Cow<'a, Expression<Fq>>>, ExprOrTemp<Cow<'a, Expression<Fq>>>) {
        match mode {
            Mode::Byte => (expr(&l.inputs()[0]), expr(&l.inputs()[1]), expr(&l.inputs()[2])),
            Mode::Any => (owned(13), temp(temps), expr(&l.inputs()[0])),
            Mode::Tag12 | Mode::Tagged => (expr(&l.inputs()[0]), temp(temps), expr(&l.inputs()[1])),
        }
    }

    fn check(mode: Mode, l: &Lookup<Expression<Fq>>) -> Result<(), Error> {
        let size = match mode { Mode::Byte => 3, Mode::Any => 1, Mode::Tag12 | Mode::Tagged => 2 };
        if l.inputs().len() != size { return Err(Error::Inputs); }
        match mode { Mode::Byte => tag(&l.inputs()[0], 8), Mode::Tag12 => tag(&l.inputs()[0], 12), _ => Ok(()) }
    }

    fn call<'a>(name: &str, input: ExprOrTemp<Cow<'a, Expression<Fq>>>, output: ExprOrTemp<Cow<'a, Expression<Fq>>>, temps: &mut Temps) -> IRStmt<ExprOrTemp<Cow<'a, Expression<Fq>>>> {
        let (out, reused) = match &output { ExprOrTemp::Temp(t) => (*t, true), ExprOrTemp::Expr(_) => (temps.next().unwrap(), false) };
        let call = IRStmt::call(name, [input], [out.into()]);
        if reused { call } else { call.then(IRStmt::eq(output, ExprOrTemp::Temp(out))) }
    }

    fn bounds<'a>(tag: ExprOrTemp<Cow<'a, Expression<Fq>>>, dense: ExprOrTemp<Cow<'a, Expression<Fq>>>, spread: ExprOrTemp<Cow<'a, Expression<Fq>>>) -> IRStmt<ExprOrTemp<Cow<'a, Expression<Fq>>>> {
        let zero = IRBexpr::and_many([IRBexpr::eq(tag.clone(), owned(0)), IRBexpr::eq(dense.clone(), owned(0)), IRBexpr::eq(spread.clone(), owned(0))]);
        let checks = (1_u32..14).map(|bits| IRBexpr::and_many([IRBexpr::eq(tag.clone(), owned(bits.into())), IRBexpr::lt(dense.clone(), owned(2_u64.pow(bits))), IRBexpr::le(spread.clone(), owned((8_u64.pow(bits) - 1) / 7))]));
        IRStmt::assert(IRBexpr::or_many(std::iter::once(zero).chain(checks)))
    }

    fn determinism<'a>(spread: &ExprOrTemp<Cow<'a, Expression<Fq>>>) -> IRStmt<ExprOrTemp<Cow<'a, Expression<Fq>>>> {
        let ExprOrTemp::Expr(value) = spread else { return IRStmt::comment("no determinism axiom for temporary spread"); };
        let Some(query) = advice(value) else { return IRStmt::comment("determinism axiom unavailable"); };
        let values = [Expression::Advice(query.clone()), AdviceQuery::query_expr(query.column_index(), query.rotation().0 + 1), AdviceQuery::query_expr(query.column_index(), query.rotation().0 + 2)];
        (0..3).flat_map(|x| (0..3).flat_map(move |y| (0..3).map(move |z| (x, y, z)))).map(|(x, y, z)| {
            let linear = values[x].clone() + Expression::Constant(Fq::from(2)) * values[y].clone() + Expression::Constant(Fq::from(4)) * values[z].clone();
            IRStmt::assert(IRBexpr::det(linear).implies(IRBexpr::det(values[x].clone()) & IRBexpr::det(values[y].clone()) & IRBexpr::det(values[z].clone()))).map(&mut Cow::Owned).map(&mut ExprOrTemp::Expr)
        }).collect()
    }
}

impl LookupCallbacks<Fq, Expression<Fq>> for Sha3LookupCallbacks {
    fn on_lookup<'a>(&self, l: &'a Lookup<Expression<Fq>>, _: &dyn LookupTableGenerator<Fq>, temps: &mut Temps) -> LookupResult<'a, Expression<Fq>> {
        let mode = Self::mode(l.name()).ok_or_else(|| Error::Name(l.name().to_owned()))?;
        Self::check(mode, l)?;
        let (tag_value, dense, spread) = Self::parts(mode, l, temps);
        let disable = match dense { ExprOrTemp::Temp(_) => !IRBexpr::eq(spread.clone(), owned(0)), ExprOrTemp::Expr(_) => !IRBexpr::eq(spread.clone(), owned(0)).and(IRBexpr::eq(dense.clone(), owned(0))) };
        let mut result = [Self::bounds(tag_value, dense.clone(), spread.clone()), Self::call("Spread", dense.clone(), spread.clone(), temps), Self::call("Unspread", spread.clone(), dense, temps), Self::determinism(&spread)].emit_unless_false(disable);
        result.meta_mut().at_lookup(l.name(), l.idx(), None);
        result.propagate_meta();
        Ok(result)
    }
}

fn expr<'a>(value: &'a Expression<Fq>) -> ExprOrTemp<Cow<'a, Expression<Fq>>> { ExprOrTemp::Expr(Cow::Borrowed(value)) }
fn owned(value: u64) -> ExprOrTemp<Cow<'static, Expression<Fq>>> { ExprOrTemp::Expr(Cow::Owned(Expression::from(value))) }
fn temp<'a>(temps: &mut Temps) -> ExprOrTemp<Cow<'a, Expression<Fq>>> { ExprOrTemp::Temp(temps.next().unwrap()) }
fn advice(value: &Expression<Fq>) -> Option<AdviceQuery> { match value { Expression::Advice(q) => Some(q.clone()), Expression::Product(a, b) if matches!(a.as_ref(), Expression::Selector(_)) => advice(b), _ => None } }
fn tag(value: &Expression<Fq>, expected: u64) -> Result<(), Error> {
    let actual = value.evaluate(&|x| Some(x), &|_| Some(Fq::ONE), &|_| None, &|_| None, &|_| None, &|_| None, &|x| x.map(|y| -y), &|a, b| a.zip(b).map(|(x, y)| x + y), &|a, b| a.zip(b).map(|(x, y)| x * y), &|a, b| a.map(|x| x * b)).ok_or(Error::Tag)?;
    if actual == Fq::from(expected) { Ok(()) } else { Err(Error::Tag) }
}

#[derive(Debug)]
enum Error { Inputs, Tag, Name(String) }

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self { Self::Inputs => write!(f, "unexpected lookup inputs"), Self::Tag => write!(f, "unexpected lookup tag"), Self::Name(name) => write!(f, "no callback for lookup {name}") }
    }
}

impl std::error::Error for Error {}
