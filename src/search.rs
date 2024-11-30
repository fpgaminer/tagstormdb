//! Search query parser and executor
//!
//! The search query parser is implemented using the pest crate, which is a PEG parser generator.
//!
//! The parser generates an abstract syntax tree (AST) that can then be executed to search through the images in the database.
use std::collections::HashSet;

use futures::{future::BoxFuture, FutureExt};
use ordered_float::NotNan;
use pest::{Parser, RuleType, Span};
use pest_derive::Parser;

use crate::{database::Database, ImageHash, ImageId};


const MAX_DEPTH: usize = 32;


#[derive(Parser)]
#[grammar = "search-grammar.pest"]
pub struct SearchParser;


pub fn parse_search(input: &str) -> Result<TreeQuery, pest::error::Error<Rule>> {
	// Parse the input
	let mut pairs = SearchParser::parse(Rule::query, input)?;

	// Construct the AST
	// The first pair is the query rule
	let first_pair = pairs.next().unwrap();
	assert_eq!(first_pair.as_rule(), Rule::query);

	let query = TreeQuery::from_pair(first_pair, 0)?;

	//format_parse_tree(pairs.clone(), 0);

	Ok(query)
}


#[allow(dead_code)]
fn format_parse_tree(pairs: pest::iterators::Pairs<Rule>, indent: usize) {
	for pair in pairs {
		let indent_str = "|    ".repeat(indent.saturating_sub(1)) + if indent > 0 { "|----" } else { "" };
		let span = pair.as_span();
		let rule = pair.as_rule();
		let inner = pair.into_inner();

		print!("{}{:?}", indent_str, rule);

		if inner.clone().count() > 0 {
			println!();
			format_parse_tree(inner, indent + 1);
		} else {
			println!(": {}", span.as_str());
		}
	}
}


trait TreeFromPair<'a>: Sized {
	fn from_pair(pair: pest::iterators::Pair<'a, Rule>, depth: usize) -> FromPairResult<'a, Self> {
		if depth > MAX_DEPTH {
			return Err(pest::error::Error::new_from_span(
				pest::error::ErrorVariant::CustomError {
					message: "Max depth exceeded".to_string(),
				},
				pair.as_span(),
			));
		}

		Self::from_pair_inner(pair, depth)
	}

	fn from_pair_inner(pair: pest::iterators::Pair<'a, Rule>, depth: usize) -> FromPairResult<'a, Self>;
}

type FromPairResult<'a, T> = Result<T, pest::error::Error<Rule>>;


#[derive(Debug)]
pub struct TreeQuery<'a> {
	pub expression: Option<TreeExpression<'a>>,
	pub sort: Option<TreeSort>,
}

impl<'a> TreeFromPair<'a> for TreeQuery<'a> {
	fn from_pair_inner(pair: pest::iterators::Pair<'a, Rule>, depth: usize) -> FromPairResult<'a, Self> {
		assert_eq!(pair.as_rule(), Rule::query);

		let mut expression = Option::None;
		let mut sort = Option::None;
		let span = pair.as_span();

		for inner_pair in pair.into_inner() {
			match inner_pair.as_rule() {
				Rule::expression if expression.is_none() => expression = Some(TreeExpression::from_pair(inner_pair, depth + 1)?),
				Rule::sort_clause if sort.is_none() => sort = Some(TreeSort::from_pair(inner_pair, depth + 1)?),
				Rule::EOI => (),
				rule => {
					return Err(pest::error::Error::new_from_span(
						pest::error::ErrorVariant::CustomError {
							message: format!("Unexpected rule: {:?}", rule),
						},
						span,
					))
				},
			}
		}

		Ok(Self { expression, sort })
	}
}

impl<'a> TreeQuery<'a> {
	pub fn execute(&'a self, db: &'a Database) -> BoxFuture<'a, Result<ExecutionResult, ExecutionError>> {
		match self.expression {
			Some(ref expression) => expression.execute(db),
			// If there's no expression, return all images
			None => async { Ok(HashSet::from_iter((0..db.images.read().await.len() as u64).map(ImageId))) }.boxed(),
		}
	}
}


#[derive(Debug)]
pub struct TreeExpression<'a> {
	// OR'd
	expressions: Vec<TreeAndExpression<'a>>,
}

impl<'a> TreeFromPair<'a> for TreeExpression<'a> {
	fn from_pair_inner(pair: pest::iterators::Pair<'a, Rule>, depth: usize) -> FromPairResult<'a, Self> {
		assert_eq!(pair.as_rule(), Rule::expression);

		let mut expressions = Vec::new();

		for inner_pair in pair.into_inner() {
			assert_eq!(inner_pair.as_rule(), Rule::and_expression);

			expressions.push(TreeAndExpression::from_pair(inner_pair, depth + 1)?);
		}

		Ok(Self { expressions })
	}
}

impl<'a> TreeExpression<'a> {
	pub fn execute(&'a self, db: &'a Database) -> BoxFuture<'a, Result<ExecutionResult, ExecutionError>> {
		async move {
			let mut set = HashSet::new();

			for expression in &self.expressions {
				let result = expression.execute(db).await?;

				if self.expressions.len() == 1 {
					return Ok(result);
				}

				// Union (OR)
				set.extend(result);
			}

			Ok(set)
		}
		.boxed()
	}
}


#[derive(Debug)]
struct TreeAndExpression<'a> {
	expressions: Vec<TreeNotExpression<'a>>,
}

impl<'a> TreeFromPair<'a> for TreeAndExpression<'a> {
	fn from_pair_inner(pair: pest::iterators::Pair<'a, Rule>, depth: usize) -> FromPairResult<'a, Self> {
		assert_eq!(pair.as_rule(), Rule::and_expression);

		let mut expressions = Vec::new();

		for inner_pair in pair.into_inner() {
			assert_eq!(inner_pair.as_rule(), Rule::not_expression);

			expressions.push(TreeNotExpression::from_pair(inner_pair, depth + 1)?);
		}

		Ok(Self { expressions })
	}
}

impl<'a> TreeAndExpression<'a> {
	async fn execute(&self, db: &Database) -> Result<ExecutionResult, ExecutionError> {
		let mut expressions = self.expressions.iter();
		let mut set = match expressions.next() {
			Some(expression) => expression.execute(db).await?,
			None => return Ok(HashSet::new()),
		};

		for expression in expressions {
			let result = expression.execute(db).await?;

			// Intersection (AND)
			set.retain(|id| result.contains(id));
		}

		Ok(set)
	}
}


#[derive(Debug)]
enum TreeNotExpression<'a> {
	Expression(TreePrimary<'a>),
	NotExpression(TreePrimary<'a>),
}

impl<'a> TreeFromPair<'a> for TreeNotExpression<'a> {
	fn from_pair_inner(pair: pest::iterators::Pair<'a, Rule>, depth: usize) -> FromPairResult<'a, Self> {
		assert_eq!(pair.as_rule(), Rule::not_expression);

		for (i, pair) in pair.into_inner().enumerate() {
			if pair.as_rule() == Rule::primary {
				let primary = TreePrimary::from_pair(pair, depth + 1)?;
				return match i {
					0 => Ok(Self::Expression(primary)),
					1 => Ok(Self::NotExpression(primary)),
					_ => unreachable!(),
				};
			}
		}

		panic!("Expected primary");
	}
}

impl<'a> TreeNotExpression<'a> {
	async fn execute(&self, db: &Database) -> Result<ExecutionResult, ExecutionError> {
		match self {
			Self::Expression(expression) => expression.execute(db).await,
			Self::NotExpression(expression) => {
				let result = expression.execute(db).await?;

				// Invert the set
				let n_images = db.images.read().await.len() as u64;

				Ok(
					tokio::task::spawn_blocking(move || HashSet::from_iter((0..n_images).map(ImageId).filter(|id| !result.contains(id))))
						.await
						.unwrap(),
				)
			},
		}
	}
}


#[derive(Debug)]
enum TreePrimary<'a> {
	Predicate(TreePredicate<'a>),
	Expression(TreeExpression<'a>),
}

impl<'a> TreeFromPair<'a> for TreePrimary<'a> {
	fn from_pair_inner(pair: pest::iterators::Pair<'a, Rule>, depth: usize) -> FromPairResult<'a, Self> {
		assert_eq!(pair.as_rule(), Rule::primary);

		let mut pairs = pair.into_inner();
		let pair = pairs.next().unwrap();

		match pair.as_rule() {
			Rule::predicate => Ok(Self::Predicate(TreePredicate::from_pair(pair, depth + 1)?)),
			Rule::expression => Ok(Self::Expression(TreeExpression::from_pair(pair, depth + 1)?)),
			_ => unreachable!(),
		}
	}
}

impl<'a> TreePrimary<'a> {
	fn execute(&'a self, db: &'a Database) -> BoxFuture<'a, Result<ExecutionResult, ExecutionError>> {
		match self {
			Self::Predicate(predicate) => predicate.execute(db),
			Self::Expression(expression) => expression.execute(db),
		}
	}
}


#[derive(Debug)]
enum TreePredicate<'a> {
	Comparison(TreeComparison<'a>),
	FunctionCall(TreeFunctionCall),
}

impl<'a> TreeFromPair<'a> for TreePredicate<'a> {
	fn from_pair_inner(pair: pest::iterators::Pair<'a, Rule>, depth: usize) -> FromPairResult<'a, Self> {
		assert_eq!(pair.as_rule(), Rule::predicate);

		let mut pairs = pair.into_inner();
		let pair = pairs.next().unwrap();

		match pair.as_rule() {
			Rule::comparison => Ok(Self::Comparison(TreeComparison::from_pair(pair, depth + 1)?)),
			Rule::function_call => Ok(Self::FunctionCall(TreeFunctionCall::from_pair(pair, depth + 1)?)),
			_ => unreachable!(),
		}
	}
}

impl<'a> TreePredicate<'a> {
	fn execute(&'a self, db: &'a Database) -> BoxFuture<'a, Result<ExecutionResult, ExecutionError>> {
		match self {
			Self::Comparison(comparison) => comparison.execute(db),
			Self::FunctionCall(function_call) => function_call.execute(db),
		}
	}
}


#[derive(Debug)]
enum TreeOperand {
	Identifier(TreeIdentifier),
	FunctionCall(TreeFunctionCall),
}

impl<'a> TreeFromPair<'a> for TreeOperand {
	fn from_pair_inner(pair: pest::iterators::Pair<'a, Rule>, depth: usize) -> FromPairResult<'a, Self> {
		assert_eq!(pair.as_rule(), Rule::operand);

		let mut pairs = pair.into_inner();
		let pair = pairs.next().unwrap();

		match pair.as_rule() {
			Rule::identifier => Ok(Self::Identifier(TreeIdentifier::from_pair(pair, depth + 1)?)),
			Rule::function_call => Ok(Self::FunctionCall(TreeFunctionCall::from_pair(pair, depth + 1)?)),
			_ => unreachable!(),
		}
	}
}


#[derive(Debug)]
struct TreeComparison<'a> {
	lhs: TreeOperand,
	operator: TreeOperator,
	rhs: TreeValue,
	span: Span<'a>,
}

impl<'a> TreeFromPair<'a> for TreeComparison<'a> {
	fn from_pair_inner(pair: pest::iterators::Pair<'a, Rule>, depth: usize) -> FromPairResult<'a, Self> {
		assert_eq!(pair.as_rule(), Rule::comparison);

		let span = pair.as_span();
		let mut pairs = pair.into_inner();
		let lhs = pairs.next().unwrap();
		let operator = pairs.next().unwrap();
		let rhs = pairs.next().unwrap();

		Ok(Self {
			lhs: TreeOperand::from_pair(lhs, depth + 1)?,
			operator: TreeOperator::from_pair(operator, depth + 1)?,
			rhs: TreeValue::from_pair(rhs, depth + 1)?,
			span,
		})
	}
}

impl<'a> TreeComparison<'a> {
	fn execute(&'a self, db: &'a Database) -> BoxFuture<'a, Result<ExecutionResult, ExecutionError>> {
		async move {
			match (&self.lhs, self.operator, &self.rhs) {
				// id op Number
				(TreeOperand::Identifier(identifier), operator, TreeValue::Number(value)) if identifier.value == "id" => {
					let value = *value;
					let id = value.into_inner().round() as i64;
					let n_images = db.images.read().await.len() as u64;

					let set = match operator {
						TreeOperator::Equal => {
							if id >= 0 && (id as u64) < n_images {
								HashSet::from([ImageId(id as u64)])
							} else {
								HashSet::new()
							}
						},
						TreeOperator::GreaterThan => {
							let min = (id + 1).max(0) as u64;
							if min >= n_images {
								HashSet::new()
							} else {
								HashSet::from_iter((min..n_images).map(ImageId))
							}
						},
						TreeOperator::GreaterThanOrEqual => {
							let min = id.max(0) as u64;
							if min >= n_images {
								HashSet::new()
							} else {
								HashSet::from_iter((min..n_images).map(ImageId))
							}
						},
						TreeOperator::LessThan => {
							if id <= 0 {
								HashSet::new()
							} else {
								let max = (id as u64).min(n_images);
								HashSet::from_iter((0..max).map(ImageId))
							}
						},
						TreeOperator::LessThanOrEqual => {
							if id < 0 {
								HashSet::new()
							} else {
								let max = (id as u64 + 1).min(n_images);
								HashSet::from_iter((0..max).map(ImageId))
							}
						},
					};

					Ok(set)
				},
				// hash = String
				(TreeOperand::Identifier(identifier), TreeOperator::Equal, TreeValue::String(value)) if identifier.value == "hash" => {
					let mut image_hash = ImageHash([0u8; 32]);

					if hex::decode_to_slice(value, &mut image_hash.0).is_ok() {
						if let Some(image_id) = db.images.read().await.get_id_of(&image_hash) {
							Ok(HashSet::from([image_id]))
						} else {
							Ok(HashSet::new())
						}
					} else {
						Ok(HashSet::new())
					}
				},
				// tag = String
				(TreeOperand::Identifier(identifier), TreeOperator::Equal, TreeValue::String(value)) if identifier.value == "tag" => {
					let tag_id = match db.get_tag_id(value).await {
						Some(id) => id,
						None => {
							log::info!("tag_id not found for {}", value);
							return Ok(HashSet::new());
						},
					};

					let index_by_tag = db.index_by_tag.read().await;
					let set = match index_by_tag.get(tag_id) {
						Some(set) => set.clone(),
						None => HashSet::new(),
					};

					Ok(set)
				},
				// Identifier = String
				(TreeOperand::Identifier(identifier), TreeOperator::Equal, TreeValue::String(value)) => {
					// If there's no entry for the attribute key, no images can match
					let attribute_key_id = match db.get_string_id(&identifier.value).await {
						Some(id) => id.into(),
						None => {
							log::info!("attribute_key_id not found for {}", identifier.value);
							return Ok(HashSet::new());
						},
					};

					// If there's no entry for the attribute value, no images can match
					let attribute_value_id = match db.get_string_id(value).await {
						Some(id) => id.into(),
						None => {
							return {
								log::info!("attribute_value_id not found for {}", value);
								Ok(HashSet::new())
							}
						},
					};

					let index_by_attribute = db.index_by_attribute.read().await;
					let set = match index_by_attribute.get_by_key_value(attribute_key_id, attribute_value_id) {
						Some(set) => set,
						None => {
							log::info!("no value matches for {} = {}", attribute_key_id, attribute_value_id);
							return Ok(HashSet::new());
						},
					};

					Ok(set.clone())
				},
				// Identifier op Number
				(TreeOperand::Identifier(identifier), operator, TreeValue::Number(value)) => {
					let value = *value;

					// If there's no entry for the attribute key, no images can match
					let attribute_key_id = match db.get_string_id(&identifier.value).await {
						Some(id) => id.into(),
						None => return Ok(HashSet::new()),
					};

					let index_by_attribute_numeric = db.index_by_attribute_numeric.read().await;
					let btree = match index_by_attribute_numeric.get_by_key(attribute_key_id) {
						Some(btree) => btree,
						None => return Ok(HashSet::new()),
					};

					use std::ops::Bound::{Excluded, Included, Unbounded};

					let set: HashSet<ImageId> = match operator {
						TreeOperator::Equal => btree.get(&value).cloned().unwrap_or_default(),
						TreeOperator::GreaterThan => btree
							.range((Excluded(value), Unbounded))
							.flat_map(|(_, image_ids)| image_ids)
							.cloned()
							.collect(),
						TreeOperator::GreaterThanOrEqual => btree
							.range((Included(value), Unbounded))
							.flat_map(|(_, image_ids)| image_ids)
							.cloned()
							.collect(),
						TreeOperator::LessThan => btree
							.range((Unbounded, Excluded(value)))
							.flat_map(|(_, image_ids)| image_ids)
							.cloned()
							.collect(),
						TreeOperator::LessThanOrEqual => btree
							.range((Unbounded, Included(value)))
							.flat_map(|(_, image_ids)| image_ids)
							.cloned()
							.collect(),
					};

					Ok(set)
				},
				// Identifier op String -> Error
				(TreeOperand::Identifier(_), _, TreeValue::String(_)) => {
					Err(ExecutionError::new::<Rule>(ExecutionErrorVariant::AttributeKeyNotFound, self.span))
				},
				// EXISTS(_) * * -> Error
				(
					TreeOperand::FunctionCall(TreeFunctionCall {
						func: TreeFunction::Exists, ..
					}),
					_,
					_,
				) => Err(ExecutionError::new::<Rule>(ExecutionErrorVariant::CannotCompareExists, self.span)),
				// BLAME(_) * * -> Error
				(TreeOperand::FunctionCall(TreeFunctionCall { func: TreeFunction::Blame, .. }), _, _) => {
					Err(ExecutionError::new::<Rule>(ExecutionErrorVariant::CannotCompareExists, self.span))
				},
			}
		}
		.boxed()
	}
}


#[derive(Debug)]
struct TreeIdentifier {
	value: String,
}

impl<'a> TreeFromPair<'a> for TreeIdentifier {
	fn from_pair_inner(pair: pest::iterators::Pair<'a, Rule>, _depth: usize) -> FromPairResult<'a, Self> {
		Ok(Self {
			value: pair.as_str().to_string(),
		})
	}
}


#[derive(Debug, Clone, Copy)]
enum TreeOperator {
	Equal,
	GreaterThan,
	GreaterThanOrEqual,
	LessThan,
	LessThanOrEqual,
}

impl<'a> TreeFromPair<'a> for TreeOperator {
	fn from_pair_inner(pair: pest::iterators::Pair<'a, Rule>, _depth: usize) -> FromPairResult<'a, Self> {
		match pair.as_rule() {
			Rule::op_equal => Ok(Self::Equal),
			Rule::op_gt => Ok(Self::GreaterThan),
			Rule::op_gte => Ok(Self::GreaterThanOrEqual),
			Rule::op_lt => Ok(Self::LessThan),
			Rule::op_lte => Ok(Self::LessThanOrEqual),
			_ => unreachable!(),
		}
	}
}

#[derive(Debug)]
enum TreeValue {
	String(String),
	Number(NotNan<f32>),
}

impl TreeFromPair<'_> for TreeValue {
	fn from_pair_inner(pair: pest::iterators::Pair<'_, Rule>, _depth: usize) -> FromPairResult<'_, Self> {
		let mut pairs = pair.into_inner();
		let pair = pairs.next().unwrap();

		match pair.as_rule() {
			Rule::string => {
				let mut pairs = pair.into_inner();
				let pair = pairs.next().unwrap();
				assert!(pair.as_rule() == Rule::double_string || pair.as_rule() == Rule::single_string);

				let value = pair
					.as_str()
					.replace("\\\"", "\"")
					.replace("\\'", "'")
					.replace("\\n", "\n")
					.replace("\\r", "\r")
					.replace("\\t", "\t")
					.replace("\\\\", "\\");

				Ok(Self::String(value))
			},
			Rule::number => Ok(Self::Number(NotNan::new(pair.as_str().parse().unwrap()).unwrap())),
			_ => unreachable!(),
		}
	}
}


#[derive(Debug)]
struct TreeFunctionCall {
	func: TreeFunction,
	argument: TreeIdentifier,
	value: Option<i64>,
}

impl TreeFromPair<'_> for TreeFunctionCall {
	fn from_pair_inner(pair: pest::iterators::Pair<'_, Rule>, depth: usize) -> FromPairResult<'_, Self> {
		assert_eq!(pair.as_rule(), Rule::function_call);

		let span = pair.as_span();
		let mut pairs = pair.into_inner();
		let function_name = pairs.next().unwrap();
		let argument = pairs.next().unwrap();
		let value = match pairs.next().map(|pair| TreeValue::from_pair(pair, depth + 1)).transpose()? {
			Some(TreeValue::Number(value)) => Some(value.into_inner().round() as i64),
			None => None,
			Some(TreeValue::String(_)) => {
				return Err(pest::error::Error::new_from_span(
					pest::error::ErrorVariant::CustomError {
						message: "Expected number".to_string(),
					},
					span,
				))
			},
		};

		assert_eq!(argument.as_rule(), Rule::identifier);

		let func = TreeFunction::from_pair(function_name, depth + 1)?;
		let argument = TreeIdentifier::from_pair(argument, depth + 1)?;

		if func == TreeFunction::Blame && value.is_none() {
			return Err(pest::error::Error::new_from_span(
				pest::error::ErrorVariant::CustomError {
					message: "Expected blame value".to_string(),
				},
				span,
			));
		}

		Ok(Self { func, argument, value })
	}
}

impl TreeFunctionCall {
	fn execute<'a>(&'a self, db: &'a Database) -> BoxFuture<'a, Result<ExecutionResult, ExecutionError>> {
		async move {
			match self.func {
				TreeFunction::Exists => {
					let attribute_key_id = match db.get_string_id(&self.argument.value).await {
						Some(id) => id.into(),
						None => {
							log::info!("attribute_key_id not found for {}", self.argument.value);
							return Ok(HashSet::new());
						},
					};

					let index_by_attribute = db.index_by_attribute.read().await;
					let set = match index_by_attribute.get_by_key(attribute_key_id) {
						Some(set) => set.values().flatten().cloned().collect(),
						None => return Ok(HashSet::new()),
					};

					Ok(set)
				},
				TreeFunction::Blame => {
					// Same as EXISTS, but checks blame id
					let attribute_key_id = match db.get_string_id(&self.argument.value).await {
						Some(id) => id.into(),
						None => {
							log::info!("attribute_key_id not found for {}", self.argument.value);
							return Ok(HashSet::new());
						},
					};

					let value = if self.value.unwrap() < 0 {
						return Ok(HashSet::new());
					} else {
						(self.value.unwrap() as u64).into()
					};

					// Find all images that have the attribute
					let index_by_attribute = db.index_by_attribute.read().await;
					let images = db.images.read().await;
					let set = match index_by_attribute.get_by_key(attribute_key_id) {
						Some(set) => set.values().flatten().filter_map(|id| images.get_by_id(*id)),
						None => return Ok(HashSet::new()),
					};

					// Filter images by blame
					let set = set
						.filter_map(|image| {
							let mut blames = image.attributes.get(&attribute_key_id)?.values();
							if blames.any(|&blame| blame == value) {
								Some(image.id)
							} else {
								None
							}
						})
						.collect();

					Ok(set)
				},
			}
		}
		.boxed()
	}
}


#[derive(Debug, PartialEq)]
enum TreeFunction {
	Exists,
	Blame,
}

impl<'a> TreeFromPair<'a> for TreeFunction {
	fn from_pair_inner(pair: pest::iterators::Pair<'a, Rule>, _depth: usize) -> FromPairResult<'a, Self> {
		match pair.as_str().to_lowercase().as_str() {
			"exists" => Ok(TreeFunction::Exists),
			"has" => Ok(TreeFunction::Exists),
			"blame" => Ok(TreeFunction::Blame),
			_ => unreachable!(),
		}
	}
}


#[derive(Debug)]
pub enum TreeSort {
	Id,
	Hash,
}

impl<'a> TreeFromPair<'a> for TreeSort {
	fn from_pair_inner(pair: pest::iterators::Pair<'a, Rule>, _depth: usize) -> FromPairResult<'a, Self> {
		assert_eq!(pair.as_rule(), Rule::sort_clause);

		match pair.as_str().to_lowercase().as_str() {
			"sort:id" => Ok(Self::Id),
			"sort:hash" => Ok(Self::Hash),
			_ => Err(pest::error::Error::new_from_span(
				pest::error::ErrorVariant::CustomError {
					message: "Invalid sort clause".to_string(),
				},
				pair.as_span(),
			)),
		}
	}
}


type ExecutionResult = HashSet<ImageId>;


#[derive(Debug)]
pub enum ExecutionErrorVariant {
	AttributeKeyNotFound,
	CannotCompareExists,
}

#[derive(Debug)]
pub struct ExecutionError {
	pub variant: ExecutionErrorVariant,
	pub message: String,
}

impl ExecutionError {
	fn new<R: RuleType>(variant: ExecutionErrorVariant, span: Span) -> Self {
		let message = match variant {
			ExecutionErrorVariant::AttributeKeyNotFound => "Attribute key not found",
			ExecutionErrorVariant::CannotCompareExists => "Cannot compare EXISTS()",
		};

		let error = pest::error::Error::<R>::new_from_span(pest::error::ErrorVariant::CustomError { message: message.to_string() }, span);

		Self {
			variant,
			message: error.to_string(),
		}
	}
}

#[cfg(test)]
mod tests {
	use crate::{database::StateUpdateResult, TagId, UserId};

	use super::*;

	#[test]
	fn test_parse_valid_queries() {
		let valid_queries = [
			"field = 123",
			"field = \"value\"",
			"field = 'value'",
			"field > 100",
			"field < 200",
			"field < 200.4",
			"field < 1e-3",
			"field >= 50",
			"field <= 75",
			"field = \"simple string\"",
			"field = \"string with \\\"quotes\\\"\"",
			"NOT field = 123",
			"not exists(email)",
			"field1 = 123 AND field2 = \"value\"",
			"field1 > 100 and field2 < 200 AND field3 = \"value\"",
			"field1 = 123 OR field2 = \"value\"",
			"exists(email) OR tags > 0",
			"field1 > 100 OR field2 < 200 OR field3 = \"test\"",
			"field1 = 123 OR field2 = \"value\" AND field3 > 100",
			"(field1 = 123 OR field2 = \"value\") AND field3 > 100",
			"field1 = 123 AND (field2 = \"value\" OR field3 > 100)",
			"(field1 = 123 OR field2 = \"value\") AND (field3 > 100 OR field4 < 200)",
			"NOT (field1 = 123 AND field2 = \"value\")",
			"(NOT field1 = 123) AND (NOT field2 = \"value\")",
			"tags > 10 AND (field1 = \"active\" OR NOT exists(deleted_at))",
			"field_1 = 0",
			"field_2 = \"\"",
			"((((field = 123))))",
			"(field1 = 123 AND field2 = \"value\") OR (field3 > 100 AND field4 < 200)",
			"field1 = 123 AND field2 = \"value\" AND field3 = \"test\"",
			"NOT (field1 = 123 OR field2 = \"value\")",
			"(NOT field1 = 123) OR (NOT field2 = \"value\")",
			"exists(attribute)",
			"field = 123 sort:id",
			"field = 123 sort:hash",
			"field = 123 AND (field2 = \"value\" OR field3 > 100) sort:id",
		];

		for query in valid_queries.iter() {
			let result = parse_search(query);
			assert!(result.is_ok(), "Query failed: {}, {}", query, result.err().unwrap());
		}
	}

	#[test]
	fn test_parse_invalid_queries() {
		let invalid_queries = [
			"NOT NOT field = 123",
			"field1",
			"field1 =",
			"= 123",
			"field = AND",
			"field == 123",
			"\"value\" = field",
			"field = 123 OR",
			"field = 123 AND",
			"(field = 123",
			"field = 123)",
			"field = \"unclosed string",
			"AND field = 123",
			"OR field = 123",
			"count(field",
			"exists)",
			"_field = 123",
			"123field = 123",
			"field1 ==",
			"field LIKE",
			"field IN",
			"field BETWEEN",
			"(field1 = 123 AND) OR (field2 = \"value\")",
			"NOT NOT NOT field = 123",
			"field = \"unclosed string",
			"field = 123 sort:unknown",
			"field = 123 sort:",
		];

		for query in invalid_queries.iter() {
			assert!(parse_search(query).is_err(), "Query succeeded unexpectedly: {}", query);
		}
	}

	#[tokio::test]
	async fn test_execute_queries() {
		// Create a mock database with sample data
		let db = create_mock_database().await;

		// Define test cases: (query string, expected image IDs)
		let test_cases = vec![
			("id = 0", vec![ImageId(0)]),
			("id > 0", vec![ImageId(1), ImageId(2), ImageId(3)]),
			("id >= 0", vec![ImageId(0), ImageId(1), ImageId(2), ImageId(3)]),
			("id = 1", vec![ImageId(1)]),
			("id > 1", vec![ImageId(2), ImageId(3)]),
			("id >= 1", vec![ImageId(1), ImageId(2), ImageId(3)]),
			("id >= -1", vec![ImageId(0), ImageId(1), ImageId(2), ImageId(3)]),
			("id < 3", vec![ImageId(0), ImageId(1), ImageId(2)]),
			("id <= 3", vec![ImageId(0), ImageId(1), ImageId(2), ImageId(3)]),
			("id < 2", vec![ImageId(0), ImageId(1)]),
			("id <= 2", vec![ImageId(0), ImageId(1), ImageId(2)]),
			("hash = '0303030303030303030303030303030303030303030303030303030303030303'", vec![ImageId(3)]),
			("hash = '0303030303030303030303030303030303030303030303030303030303030304'", vec![]),
			("width > 1000", vec![ImageId(3)]),
			("tag_count > 1", vec![ImageId(3)]),
			("tag = \"nature\"", vec![ImageId(0), ImageId(1), ImageId(3)]),
			("tag = \"portrait\"", vec![ImageId(2), ImageId(3)]),
			("NOT tag = \"portrait\"", vec![ImageId(0), ImageId(1)]),
			("exists(description)", vec![ImageId(1), ImageId(2)]),
			("blame(description, 0)", vec![ImageId(1), ImageId(2)]),
			("field = \"value\"", vec![]),
			("", vec![ImageId(0), ImageId(1), ImageId(2), ImageId(3)]),
		];

		for (query_str, expected_ids) in test_cases {
			let query = parse_search(query_str).unwrap();
			let result = query.execute(&db).await.unwrap();
			let mut result_ids: Vec<_> = result.into_iter().collect();
			result_ids.sort();
			assert_eq!(result_ids, expected_ids, "Query failed: {}", query_str);
		}
	}

	// Helper function to create a mock database
	async fn create_mock_database() -> Database {
		let tmpdir = tempfile::tempdir().unwrap();
		let db = Database::open(tmpdir.path(), false).await.unwrap();

		// Populate the database with sample data
		// Tags
		db.add_tag("nature".to_string(), UserId(0)).await.unwrap();
		db.add_tag("portrait".to_string(), UserId(0)).await.unwrap();

		// Image 0
		db.add_image(ImageHash([0u8; 32]), UserId(0)).await.unwrap();
		assert_eq!(db.add_image_tag(ImageId(0), TagId(0), UserId(0)).await.unwrap(), StateUpdateResult::Updated(()));

		// Image 1
		db.add_image(ImageHash([1u8; 32]), UserId(0)).await.unwrap();
		assert_eq!(db.add_image_tag(ImageId(1), TagId(0), UserId(0)).await.unwrap(), StateUpdateResult::Updated(()));
		assert_eq!(
			db.add_image_attribute(ImageId(1), "description".to_string(), "A beautiful landscape".to_string(), UserId(0))
				.await
				.unwrap(),
			StateUpdateResult::Updated(())
		);
		assert_eq!(
			db.add_image_attribute(ImageId(1), "width".to_string(), "480".to_string(), UserId(0))
				.await
				.unwrap(),
			StateUpdateResult::Updated(())
		);

		// Image 2
		db.add_image(ImageHash([2u8; 32]), UserId(0)).await.unwrap();
		assert_eq!(db.add_image_tag(ImageId(2), TagId(1), UserId(0)).await.unwrap(), StateUpdateResult::Updated(()));
		assert_eq!(
			db.add_image_attribute(ImageId(2), "description".to_string(), "A portrait of a person".to_string(), UserId(0))
				.await
				.unwrap(),
			StateUpdateResult::Updated(())
		);
		assert_eq!(
			db.add_image_attribute(ImageId(2), "width".to_string(), "720".to_string(), UserId(0))
				.await
				.unwrap(),
			StateUpdateResult::Updated(())
		);

		// Image 3
		db.add_image(ImageHash([3u8; 32]), UserId(0)).await.unwrap();
		assert_eq!(db.add_image_tag(ImageId(3), TagId(0), UserId(0)).await.unwrap(), StateUpdateResult::Updated(()));
		assert_eq!(db.add_image_tag(ImageId(3), TagId(1), UserId(0)).await.unwrap(), StateUpdateResult::Updated(()));
		assert_eq!(
			db.add_image_attribute(ImageId(3), "width".to_string(), "1920".to_string(), UserId(0))
				.await
				.unwrap(),
			StateUpdateResult::Updated(())
		);

		db
	}
}
