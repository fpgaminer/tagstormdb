//! # TagStormDB
//!
//! This library implements an asynchronous database for durably storing and searching images with tags and attributes.
//! It is optimized for fast and frequent searching and retrieval of information.  Writes are not optimized.
//!
//! A database consists of primarily an Action Log, which is an append only log of actions that have been performed on the database.
//! During operation, any action performed on the database is recorded to the log and the state of the database is updated accordingly.
//! This ensures perfect history and the ability to replay the log to recreate the state of the database at any point in time.
//!
//! During startup, the database state is reconstructed by replaying the log from the beginning, to build the current state as
//! a series of in-memory data structures.  Everything is in-memory, so the database is fast and can be queried quickly.
//!
//! Besides the Action Log, the database also contains a ancillary data structures: the string table, hash table, user table, and user token table.
//! The string table is an optimization to store strings in a single location and refer to them by their index in the table.  This way in all
//! other data structures strings are reduced to a single u64.  The hash table maps image ids to their hash.  For both tables, the id/index
//! is always [0, count) where count is the number of strings or images in the table, with no gaps.
//! The user table stores user information, and the user token table maps user authentication tokens to user ids.
//!
//! Frequent use of the new type pattern is used to ensure that the correct types are used in the correct places, and to prevent
//! accidental mixing of types.
//!
//! This top level module implements the various types used throughout the library, with other functionality implemented in submodules.
//!
pub mod errors;
pub mod search;
#[macro_use]
mod newtype_macros;
pub mod binary_format;
pub mod database;
pub mod small_db;
mod small_db_deserializer;
mod small_db_errors;
mod small_db_serializer;

pub use database::Database;

use indexmap::{Equivalent, IndexMap};
use indicatif::ProgressStyle;
use ordered_float::NotNan;
use rand::prelude::Distribution;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};


/// Assert that usize is 64 bits or more, since we need to cast between u64 and usize
const _: () = assert!(std::mem::size_of::<usize>() >= 8, "usize must be 64 bits or more");


pub fn default_progress_style() -> ProgressStyle {
	ProgressStyle::with_template("{prefix:>12.cyan.bold} [{elapsed_precise}] [{wide_bar:40.cyan/blue}] {pos}/{len} ({eta})")
		.unwrap()
		.progress_chars("#>-")
}


#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy, PartialOrd, Ord)]
pub struct ImageHash(pub [u8; 32]);

impl Serialize for ImageHash {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		serializer.serialize_str(&hex::encode(self.0))
	}
}

impl<'de> Deserialize<'de> for ImageHash {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		let s = String::deserialize(deserializer)?;
		let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
		let hash = bytes.try_into().map_err(|_| serde::de::Error::custom("Invalid hash length"))?;
		Ok(ImageHash(hash))
	}
}


#[derive(Debug, Hash, Clone, Copy)]
pub struct LoginKey(pub [u8; 32]);

impl LoginKey {
	pub fn hash(&self) -> HashedLoginKey {
		let mut hasher = Sha256::new();
		hasher.update(self.0);
		let hash = hasher.finalize();

		HashedLoginKey(hash.into())
	}
}

impl<'de> Deserialize<'de> for LoginKey {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		let s = String::deserialize(deserializer)?;
		let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
		let hash = bytes.try_into().map_err(|_| serde::de::Error::custom("Invalid login key length"))?;
		Ok(LoginKey(hash))
	}
}


#[derive(Debug, Clone, Copy)]
pub struct HashedLoginKey(pub [u8; 32]);

impl std::hash::Hash for HashedLoginKey {
	fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
		self.0.hash(state);
	}
}

// Constant time comparison
impl ::std::cmp::PartialEq for HashedLoginKey {
	fn eq(&self, other: &Self) -> bool {
		use ::subtle::ConstantTimeEq;

		self.0.ct_eq(&other.0).into()
	}
}

impl Eq for HashedLoginKey {}


#[derive(Debug, Clone, Copy)]
pub struct UserToken(pub [u8; 32]);

impl Distribution<UserToken> for rand::distributions::Standard {
	fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> UserToken {
		UserToken(rng.gen())
	}
}

impl std::hash::Hash for UserToken {
	fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
		self.0.hash(state);
	}
}

// Constant time comparison
impl ::std::cmp::PartialEq for UserToken {
	fn eq(&self, other: &Self) -> bool {
		use ::subtle::ConstantTimeEq;

		self.0.ct_eq(&other.0).into()
	}
}

impl Eq for UserToken {}

impl<'de> Deserialize<'de> for UserToken {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		let s = String::deserialize(deserializer)?;
		let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
		let hash = bytes.try_into().map_err(|_| serde::de::Error::custom("Invalid token length"))?;
		Ok(UserToken(hash))
	}
}

impl Serialize for UserToken {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		serializer.serialize_str(&hex::encode(self.0))
	}
}


define_id_type!(UserId);
define_id_type!(TagId);
define_id_type!(ImageId);
define_id_type!(StringId);
define_id_type!(AttributeKeyId, convert StringId);
define_id_type!(AttributeValueId, convert StringId);


/// Wraps IndexMap to enforce that the index is of type I
#[derive(Debug)]
pub struct IndexMapTyped<K, V, I> {
	map: IndexMap<K, V>,
	_phantom: std::marker::PhantomData<I>,
}

impl<K, V, I> IndexMapTyped<K, V, I>
where
	K: Eq + std::hash::Hash,
	I: Into<usize> + From<u64> + From<usize> + Copy,
{
	fn new() -> Self {
		Self {
			map: IndexMap::new(),
			_phantom: std::marker::PhantomData,
		}
	}

	fn with_capacity(capacity: usize) -> Self {
		Self {
			map: IndexMap::with_capacity(capacity),
			_phantom: std::marker::PhantomData,
		}
	}

	pub fn get_by_id(&self, id: I) -> Option<&V> {
		self.map.get_index(id.into()).map(|(_, v)| v)
	}

	pub fn get_by_id_mut(&mut self, id: I) -> Option<&mut V> {
		self.map.get_index_mut(id.into()).map(|(_, v)| v)
	}

	pub fn get_by_id_full(&self, id: I) -> Option<(&K, &V)> {
		self.map.get_index(id.into())
	}

	pub fn get_by_key(&self, key: &K) -> Option<&V> {
		self.map.get(key)
	}

	pub fn get_by_key_mut(&mut self, key: &K) -> Option<&mut V> {
		self.map.get_mut(key)
	}

	pub fn get_by_key_or_insert(&mut self, key: K, default: V) -> &mut V {
		let entry = self.map.entry(key);
		entry.or_insert(default)
	}

	pub fn get_by_key_full<Q>(&self, key: &Q) -> Option<(I, &K, &V)>
	where
		Q: ?Sized + std::hash::Hash + Equivalent<K>,
	{
		self.map.get_full(key).map(|(id, key, value)| (id.into(), key, value))
	}

	pub fn entry_by_key(&mut self, key: K) -> indexmap::map::Entry<K, V> {
		self.map.entry(key)
	}

	pub fn len(&self) -> usize {
		self.map.len()
	}

	pub fn is_empty(&self) -> bool {
		self.map.is_empty()
	}

	pub fn insert(&mut self, key: K, value: V) -> Option<V> {
		self.map.insert(key, value)
	}

	pub fn get_id_of<Q: ?Sized + std::hash::Hash + Equivalent<K>>(&self, key: &Q) -> Option<I> {
		self.map.get_index_of(key).map(|id| id.into())
	}

	pub fn values(&self) -> indexmap::map::Values<K, V> {
		self.map.values()
	}

	pub fn iter(&self) -> indexmap::map::Iter<K, V> {
		self.map.iter()
	}

	pub fn contains_key<Q: ?Sized + std::hash::Hash + Equivalent<K>>(&self, key: &Q) -> bool {
		self.map.contains_key(key)
	}

	pub fn contains_id(&self, id: I) -> bool {
		let i: usize = id.into();
		i < self.map.len()
	}
}


/// Wraps HashMap to restrict actions
pub struct TagIndex {
	/// tag id -> Id's of images that have the tag
	index: HashMap<TagId, HashSet<ImageId>>,
}

impl TagIndex {
	fn new() -> Self {
		Self { index: HashMap::new() }
	}

	fn add(&mut self, tag_id: TagId, image_id: ImageId) {
		self.index.entry(tag_id).or_default().insert(image_id);
	}

	fn remove(&mut self, tag_id: TagId, image_id: ImageId) {
		self.index.get_mut(&tag_id).unwrap().remove(&image_id);
	}

	fn get(&self, tag_id: TagId) -> Option<&HashSet<ImageId>> {
		self.index.get(&tag_id)
	}

	fn remove_tag(&mut self, tag_id: TagId) {
		self.index.remove(&tag_id);
	}

	fn remove_image(&mut self, image_id: ImageId) {
		for (_, image_ids) in self.index.iter_mut() {
			image_ids.remove(&image_id);
		}
	}
}


/// Wraps HashMap to restrict actions
#[derive(Debug)]
pub struct AttributeIndex {
	/// attribute key id -> attribute value id -> Id's of images that have the attribute
	index: HashMap<AttributeKeyId, HashMap<AttributeValueId, HashSet<ImageId>>>,
}

impl AttributeIndex {
	fn new() -> Self {
		Self { index: HashMap::new() }
	}

	fn add(&mut self, key_id: AttributeKeyId, value_id: AttributeValueId, image_id: ImageId) {
		self.index.entry(key_id).or_default().entry(value_id).or_default().insert(image_id);
	}

	fn remove(&mut self, key_id: AttributeKeyId, value_id: AttributeValueId, image_id: ImageId) {
		self.index.get_mut(&key_id).unwrap().get_mut(&value_id).unwrap().remove(&image_id);
	}

	fn remove_image(&mut self, image_id: ImageId) {
		for (_, values) in self.index.iter_mut() {
			for (_, image_ids) in values.iter_mut() {
				image_ids.remove(&image_id);
			}
		}
	}

	fn get_by_key(&self, key_id: AttributeKeyId) -> Option<&HashMap<AttributeValueId, HashSet<ImageId>>> {
		self.index.get(&key_id)
	}

	fn get_by_key_value(&self, key_id: AttributeKeyId, value_id: AttributeValueId) -> Option<&HashSet<ImageId>> {
		self.index.get(&key_id).and_then(|values| values.get(&value_id))
	}
}


/// Wraps HashMap to restrict actions
pub struct NumericAttributeIndex {
	/// attribute key id -> attribute value -> Id's of images that have the attribute
	index: HashMap<AttributeKeyId, BTreeMap<NotNan<f32>, HashSet<ImageId>>>,
}

impl NumericAttributeIndex {
	fn new() -> Self {
		Self { index: HashMap::new() }
	}

	fn add(&mut self, key_id: AttributeKeyId, value: NotNan<f32>, image_id: ImageId) {
		self.index.entry(key_id).or_default().entry(value).or_default().insert(image_id);
	}

	fn remove(&mut self, key_id: AttributeKeyId, value: NotNan<f32>, image_id: ImageId) {
		self.index.get_mut(&key_id).unwrap().get_mut(&value).unwrap().remove(&image_id);
	}

	fn remove_image(&mut self, image_id: ImageId) {
		for (_, values) in self.index.iter_mut() {
			for (_, image_ids) in values.iter_mut() {
				image_ids.remove(&image_id);
			}
		}
	}

	pub fn get_by_key(&self, key_id: AttributeKeyId) -> Option<&BTreeMap<NotNan<f32>, HashSet<ImageId>>> {
		self.index.get(&key_id)
	}
}
