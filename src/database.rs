//! The database module.
//! This module contains the database struct and all the methods to interact with it.
use crate::{
	binary_format::{
		append_to_hash_table, append_to_log_file, append_to_strings_table, read_hash_table, read_log_file, read_string_table, LogActionWithData, LogEntry,
	},
	default_progress_style,
	errors::DatabaseError,
	small_db::{RowId, SmallDb},
	AttributeIndex, AttributeKeyId, AttributeValueId, HashedLoginKey, ImageHash, ImageId, IndexMapTyped, NumericAttributeIndex, StringId, TagId, TagIndex,
	TaskId, UserId, UserToken,
};
use chrono::Utc;
use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use indicatif::{ProgressBar, ProgressDrawTarget};
use ordered_float::NotNan;
use rand::{rngs::OsRng, Rng};
use serde::{Deserialize, Serialize};
use std::{
	collections::{BTreeMap, HashMap},
	io::BufReader,
	path::Path,
	sync::Arc,
};
use tokio::{
	sync::{Mutex, OwnedMutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard},
	task,
};


#[derive(Debug)]
pub struct ImageEntry {
	pub id: ImageId,
	pub hash: ImageHash,
	pub tags: HashMap<TagId, UserId>,                                           // tag_id -> blame
	pub attributes: HashMap<AttributeKeyId, HashMap<AttributeValueId, UserId>>, // key_id -> value_id -> blame
	pub active: bool,
}


pub struct TagEntry {
	pub active: bool,
}


#[derive(Debug)]
pub struct UserEntry {
	pub hashed_login_key: HashedLoginKey,
	pub scopes: String,
	pub scopes_matcher: GlobSet,
	pub row_id: RowId,
}

pub fn parse_scopes(scopes: &str) -> Result<GlobSet, DatabaseError> {
	let globs = scopes.split(',').map(|s| {
		GlobBuilder::new(s.trim())
			.literal_separator(true)
			.case_insensitive(true)
			.build()
			.map_err(DatabaseError::ScopeParseError)
	});

	let mut builder = GlobSetBuilder::new();

	for glob in globs {
		builder.add(glob?);
	}

	builder.build().map_err(DatabaseError::ScopeParseError)
}

impl UserEntry {
	pub(crate) fn new(hashed_login_key: HashedLoginKey, scopes: String, row_id: RowId) -> Result<Self, DatabaseError> {
		let scopes_matcher = parse_scopes(&scopes)?;
		Ok(Self {
			hashed_login_key,
			scopes,
			scopes_matcher,
			row_id,
		})
	}
}


#[derive(Deserialize, Serialize, Clone, Copy, Eq, PartialEq, Hash, Debug)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
	/// The task is waiting to be picked up
	Waiting,
	/// The task is being worked on
	InProgress,
	/// The task is done
	Done,
}


#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct TaskEntry {
	pub id: TaskId,
	/// Task group
	pub group: StringId,
	/// JSON data for this task
	pub data: String,
	/// Task status
	pub status: TaskStatus,
	/// Time the task's status was last modified (created, acquired, completed)
	pub modified_time: i64,
	/// The last user to affect the status of this task
	pub blame: UserId,
}


#[derive(Deserialize, Serialize, Debug)]
pub enum SmallDbEntry {
	User {
		user_id: UserId,
		username: String,
		hashed_login_key: HashedLoginKey,
		scopes: String,
	},
	UserToken {
		user_id: UserId,
		token: UserToken,
	},
	Task(TaskEntry),
}


pub type ImagesRwLock = RwLock<IndexMapTyped<ImageHash, ImageEntry, ImageId>>;
type ImagesRwGuard<'a> = RwLockWriteGuard<'a, IndexMapTyped<ImageHash, ImageEntry, ImageId>>;
pub type ImagesReadGuard<'a> = RwLockReadGuard<'a, IndexMapTyped<ImageHash, ImageEntry, ImageId>>;
pub type StringTableRwLock = RwLock<IndexMapTyped<String, Option<NotNan<f32>>, StringId>>;
type StringTableRwGuard<'a> = RwLockWriteGuard<'a, IndexMapTyped<String, Option<NotNan<f32>>, StringId>>;
type StringTableReadGuard<'a> = RwLockReadGuard<'a, IndexMapTyped<String, Option<NotNan<f32>>, StringId>>;
type IndexByAttributeNumericRwGuard<'a> = RwLockWriteGuard<'a, NumericAttributeIndex>;
type UsersReadGuard<'a> = RwLockReadGuard<'a, IndexMapTyped<String, UserEntry, UserId>>;
type TaskQueueReadLock<'a> = RwLockReadGuard<'a, HashMap<TaskId, (TaskEntry, RowId)>>;
type TaskQueueWriteLock<'a> = RwLockWriteGuard<'a, HashMap<TaskId, (TaskEntry, RowId)>>;
type SmallDbGuard = OwnedMutexGuard<SmallDb<SmallDbEntry>>;


pub struct Database {
	pub images: Arc<RwLock<IndexMapTyped<ImageHash, ImageEntry, ImageId>>>,
	pub tags: RwLock<IndexMapTyped<String, TagEntry, TagId>>,
	pub string_table: Arc<RwLock<IndexMapTyped<String, Option<NotNan<f32>>, StringId>>>,
	pub users: Arc<RwLock<IndexMapTyped<String, UserEntry, UserId>>>,
	pub user_tokens: RwLock<HashMap<UserToken, (UserId, RowId)>>,
	pub task_queue: Arc<RwLock<HashMap<TaskId, (TaskEntry, RowId)>>>,

	/// tag id -> images with that tag
	pub index_by_tag: RwLock<TagIndex>,
	/// attribute key id -> attribute value id -> images with that attribute
	pub index_by_attribute: RwLock<AttributeIndex>,
	/// attribute key id -> attribute value id -> images with that attribute (numeric)
	pub index_by_attribute_numeric: RwLock<NumericAttributeIndex>,

	/// Files
	logs_file: Arc<Mutex<std::fs::File>>,
	hashes_file: Arc<Mutex<std::fs::File>>,
	strings_file: Arc<Mutex<std::fs::File>>,
	small_db: Arc<Mutex<SmallDb<SmallDbEntry>>>,
}

impl Database {
	pub async fn open<P: AsRef<Path>>(path: P, with_progress: bool) -> Result<Self, DatabaseError> {
		let path = path.as_ref().to_path_buf();

		let database = task::spawn_blocking(move || -> Result<Database, DatabaseError> {
			let hashes_file = std::fs::OpenOptions::new()
				.create(true)
				.read(true)
				.write(true)
				.truncate(false)
				.open(path.join("image_hashes.bin"))?;
			// TODO: Exclusive lock
			let strings_file = std::fs::OpenOptions::new()
				.create(true)
				.read(true)
				.write(true)
				.truncate(false)
				.open(path.join("string_table.bin"))?;
			// TODO: Exclusive lock
			let logs_file = std::fs::OpenOptions::new()
				.create(true)
				.read(true)
				.write(true)
				.truncate(false)
				.open(path.join("logs.bin"))?;
			// TODO: Exclusive lock

			// Read image hashes
			let start_time = std::time::Instant::now();
			let images = read_hash_table(BufReader::new(&hashes_file), with_progress)?;
			log::info!("Read {} image hashes in {:?}", images.len(), start_time.elapsed());

			// Read string table
			let start_time = std::time::Instant::now();
			let string_table = read_string_table(BufReader::new(&strings_file), with_progress)?;
			log::info!("Read string table with {} elements in {:?}", string_table.len(), start_time.elapsed());

			// Read smalldb tables
			let start_time = std::time::Instant::now();
			let (users, user_tokens, task_queue, small_db) = read_small_db(path.join("small_db.bin"))?;
			log::info!("Read small db tables in {:?}", start_time.elapsed());
			log::info!("Users: {}", users.len());
			log::info!("User tokens: {}", user_tokens.len());
			log::info!("Task queue: {}", task_queue.len());

			// Create the database object
			let database = Self {
				images: Arc::new(RwLock::new(images)),
				string_table: Arc::new(RwLock::new(string_table)),
				tags: RwLock::new(IndexMapTyped::new()),
				users: Arc::new(RwLock::new(users)),
				user_tokens: RwLock::new(user_tokens),
				task_queue: Arc::new(RwLock::new(task_queue)),
				index_by_tag: RwLock::new(TagIndex::new()),
				index_by_attribute: RwLock::new(AttributeIndex::new()),
				index_by_attribute_numeric: RwLock::new(NumericAttributeIndex::new()),
				logs_file: Arc::new(Mutex::new(logs_file)),
				hashes_file: Arc::new(Mutex::new(hashes_file)),
				strings_file: Arc::new(Mutex::new(strings_file)),
				small_db: Arc::new(Mutex::new(small_db)),
			};

			Ok(database)
		})
		.await
		.expect("spawn_blocking failed")?;

		// Load the database
		let start_time = std::time::Instant::now();
		database.load(with_progress).await?;
		log::info!("Loaded logs into database in {:?}", start_time.elapsed());

		Ok(database)
	}

	/// Load the database from the log file
	async fn load(&self, with_progress: bool) -> Result<(), DatabaseError> {
		let mut logs_file = self.logs_file.lock().await;

		// Note: LogReader is not async, but we're in the loading phase and the blocking is small and incremental, so it shouldn't be an issue
		let log_reader = read_log_file(BufReader::new(&mut *logs_file))?;
		let pb_target = if with_progress {
			ProgressDrawTarget::stderr()
		} else {
			ProgressDrawTarget::hidden()
		};
		let pb = ProgressBar::with_draw_target(Some(log_reader.size_hint().0 as u64), pb_target)
			.with_style(default_progress_style())
			.with_prefix("Reading logs");
		pb.enable_steady_tick(std::time::Duration::from_millis(100));

		for log in log_reader {
			let log = log?;

			match log.action {
				LogActionWithData::AddTag(tag) => match self.state_add_tag(tag).await {
					StateUpdateResult::Updated(_) => {},
					_ => panic!("Invalid log, tag already exists"),
				},
				LogActionWithData::RemoveTag(tag_id) => match self.state_remove_tag(tag_id).await {
					StateUpdateResult::Updated(_) => {},
					_ => panic!("Invalid log, tag doesn't exist"),
				},
				LogActionWithData::AddImage(image_id) => {
					let mut index_by_attribute_numeric = self.index_by_attribute_numeric.write().await;
					let mut images = self.images.write().await;

					let image = images
						.get_by_id_mut(image_id)
						.expect("Invalid log, image hash doesn't exist for AddImage action");
					assert_eq!(
						self.state_add_image(image, &mut index_by_attribute_numeric).await,
						StateUpdateResult::Updated(())
					);
				},
				LogActionWithData::RemoveImage(image_id) => {
					assert_eq!(self.state_remove_image(image_id).await, StateUpdateResult::Updated(()));
				},
				LogActionWithData::AddImageTag(image_id, tag_id) => {
					assert_eq!(self.state_add_image_tag(image_id, tag_id, log.user_id).await, StateUpdateResult::Updated(()));
				},
				LogActionWithData::RemoveImageTag(image_id, tag_id) => {
					assert_eq!(self.state_remove_image_tag(image_id, tag_id).await, StateUpdateResult::Updated(()));
				},
				LogActionWithData::AddAttribute(image_id, key_id, value_id) => {
					assert_eq!(
						self.state_add_image_attribute(image_id, key_id, value_id, log.user_id).await,
						StateUpdateResult::Updated(())
					);
				},
				LogActionWithData::RemoveAttribute(image_id, key, value) => {
					assert_eq!(self.state_remove_image_attribute(image_id, key, value).await, StateUpdateResult::Updated(()));
				},
			}

			pb.inc(1);
		}

		Ok(())
	}

	pub async fn get_tag_id(&self, tag: &str) -> Option<TagId> {
		self.tags.read().await.get_id_of(tag)
	}

	pub async fn get_string_id(&self, s: &str) -> Option<StringId> {
		self.string_table.read().await.get_id_of(s)
	}

	pub async fn get_string_by_id<'a>(&self, string_id: StringId, lock: &'a StringTableReadGuard<'a>) -> Option<&'a str> {
		lock.get_by_id_full(string_id).map(|(s, _)| s.as_str())
	}

	pub async fn get_or_insert_string_id(&self, s: String) -> Result<StringId, DatabaseError> {
		let mut string_table = self.string_table.write().await;
		let (string_id, _) = self.add_string_or_get_mut(s, &mut string_table).await?;

		Ok(string_id)
	}

	pub async fn get_image_id(&self, hash: &ImageHash) -> Option<ImageId> {
		self.images.read().await.get_id_of(hash)
	}

	pub async fn get_image_by_id<'a>(&self, image_id: ImageId, lock: &'a ImagesReadGuard<'a>) -> Option<&'a ImageEntry> {
		lock.get_by_id(image_id)
	}

	pub async fn get_image_by_hash<'a>(&self, hash: &ImageHash, lock: &'a ImagesReadGuard<'a>) -> Option<&'a ImageEntry> {
		lock.get_by_key(hash)
	}

	pub async fn get_user_id_by_token(&self, token: &UserToken) -> Option<UserId> {
		// NOTE: I think there's a very small timing attack here.
		// The sequence of events inside the hashmap is:
		// 1. Hash the token
		// 2. Do a lookup based on the hash
		// 3. Do one or more constant time comparisons to the token
		// Step 2 is where a small timing attack might exist. An attacker could brute force the buckets of the hashmap, thus
		// discovering up to 64-bits of the token.
		// However, the timing is very noisy inside the server, reducing the signal, and
		// even at 192-bits the tokens are still secure.
		self.user_tokens.read().await.get(token).map(|(user_id, _)| *user_id)
	}

	pub async fn list_user_tokens_by_user_id(&self, user_id: UserId) -> Vec<UserToken> {
		self.user_tokens
			.read()
			.await
			.iter()
			.filter_map(|(token, (id, _))| if *id == user_id { Some(*token) } else { None })
			.collect()
	}

	pub fn get_user_by_id<'a>(&self, user_id: UserId, lock: &'a UsersReadGuard<'_>) -> Option<(&'a String, &'a UserEntry)> {
		lock.get_by_id_full(user_id)
	}

	/// Add a new user to the database
	pub async fn add_user(&self, username: String, hashed_login_key: HashedLoginKey, scopes: String) -> Result<UserId, DatabaseError> {
		// Check that the scopes are valid
		parse_scopes(&scopes)?;

		// Lock the data structures
		let mut small_db_lock = self.small_db.clone().lock_owned().await;
		let mut users_lock = self.users.clone().write_owned().await;

		let entry = match users_lock.entry_by_key(username.clone()) {
			indexmap::map::Entry::Occupied(_) => return Err(DatabaseError::UserAlreadyExists),
			indexmap::map::Entry::Vacant(entry) => entry,
		};
		let user_id: UserId = entry.index().into();

		// Insert into the small db
		let db_entry = SmallDbEntry::User {
			user_id,
			username,
			hashed_login_key,
			scopes: scopes.clone(),
		};
		let row_id = task::spawn_blocking(move || small_db_lock.insert_row(&db_entry))
			.await
			.expect("spawn_blocking failed")?;

		// Insert into the users table
		let user_entry = UserEntry::new(hashed_login_key, scopes, row_id)?;
		let _ = entry.insert(user_entry);

		Ok(user_id)
	}

	/// Change a user's scopes
	pub async fn change_user_scopes(&self, user_id: UserId, new_scopes: String) -> Result<(), DatabaseError> {
		// Check that the scopes are valid
		let parsed_scopes = parse_scopes(&new_scopes)?;

		// Lock the data structures
		let mut users = self.users.clone().write_owned().await;
		let mut small_db_lock = self.small_db.clone().lock_owned().await;

		// Find the user
		let (username, user) = match users.get_by_id_full_mut(user_id) {
			Some(user) => user,
			None => return Err(DatabaseError::UserDoesNotExist),
		};

		// Update state
		user.scopes = new_scopes.clone();
		user.scopes_matcher = parsed_scopes;

		// Update the small db
		let old_row_id = user.row_id;
		let db_entry = SmallDbEntry::User {
			user_id,
			username: username.clone(),
			hashed_login_key: user.hashed_login_key,
			scopes: new_scopes,
		};
		let new_row_id = task::spawn_blocking(move || small_db_lock.update_row(old_row_id, &db_entry))
			.await
			.expect("spawn_blocking failed")?;

		// Update rowid
		user.row_id = new_row_id;

		Ok(())
	}

	/// Change a user's login key
	pub async fn change_user_login_key(&self, user_id: UserId, new_hashed_login_key: HashedLoginKey) -> Result<(), DatabaseError> {
		// Lock the data structures
		let mut users = self.users.clone().write_owned().await;
		let mut small_db_lock = self.small_db.clone().lock_owned().await;

		// Find the user
		let (username, user) = match users.get_by_id_full_mut(user_id) {
			Some(user) => user,
			None => return Err(DatabaseError::UserDoesNotExist),
		};

		// Update state
		user.hashed_login_key = new_hashed_login_key;

		// Update the small db
		let old_row_id = user.row_id;
		let db_entry = SmallDbEntry::User {
			user_id,
			username: username.clone(),
			hashed_login_key: new_hashed_login_key,
			scopes: user.scopes.clone(),
		};
		let new_row_id = task::spawn_blocking(move || small_db_lock.update_row(old_row_id, &db_entry))
			.await
			.expect("spawn_blocking failed")?;

		// Update rowid
		user.row_id = new_row_id;

		Ok(())
	}

	/// Create a new user token
	pub async fn create_user_token(&self, user_id: UserId) -> Result<UserToken, DatabaseError> {
		// Lock the data structures
		let mut user_tokens = self.user_tokens.write().await;
		let mut small_db_lock = self.small_db.clone().lock_owned().await;
		let users = self.users.read().await;

		// Check that the user exists
		if !users.contains_id(user_id) {
			return Err(DatabaseError::UserDoesNotExist);
		}

		// Generate a new token
		let token: UserToken = OsRng.gen();

		// Update the small db
		let db_entry = SmallDbEntry::UserToken { user_id, token };
		let row_id = task::spawn_blocking(move || small_db_lock.insert_row(&db_entry))
			.await
			.expect("spawn_blocking failed")?;

		// Update state
		user_tokens.insert(token, (user_id, row_id));

		Ok(token)
	}

	pub async fn invalidate_user_token(&self, token: &UserToken) -> Result<(), DatabaseError> {
		// Lock the data structures
		let mut user_tokens = self.user_tokens.write().await;
		let mut small_db_lock = self.small_db.clone().lock_owned().await;

		// Remove from state
		let (_, row_id) = match user_tokens.remove(token) {
			Some(v) => v,
			None => return Ok(()),
		};

		// Update the small db
		task::spawn_blocking(move || small_db_lock.delete_row(row_id))
			.await
			.expect("spawn_blocking failed")?;

		Ok(())
	}

	pub async fn authenticate_login(&self, username: &str, hashed_login_key: HashedLoginKey) -> Result<Option<UserId>, DatabaseError> {
		let users = self.users.read().await;

		// Find the user by username
		// NOTE: I think there's a very small timing attack here where attackers can brute force whether a username exists or not
		let (user_id, user) = match users.get_by_key_full(username) {
			Some((user_id, _, user)) => (user_id, user),
			_ => return Ok(None),
		};

		// Compare the login key hash
		// This is constant time (see HashedLoginKey::eq)
		if user.hashed_login_key == hashed_login_key {
			Ok(Some(user_id))
		} else {
			Ok(None)
		}
	}


	// ========================
	// Internal File Management
	// ========================

	/// Internal method for durably adding to the image hash table file when needed
	/// If the image already exists, returns the entry
	/// Otherwise, appends the hash to the file and returns the new entry
	async fn add_image_hash_or_get_mut<'a>(&self, hash: ImageHash, images: &'a mut ImagesRwGuard<'_>) -> Result<&'a mut ImageEntry, DatabaseError> {
		let entry = match images.entry_by_key(hash) {
			// Case where the image already exists
			indexmap::map::Entry::Occupied(entry) => return Ok(entry.into_mut()),
			// Case where the image doesn't exist
			indexmap::map::Entry::Vacant(entry) => entry,
		};

		let mut lock = self.hashes_file.clone().lock_owned().await;
		task::spawn_blocking(move || append_to_hash_table(&mut lock, &hash))
			.await
			.expect("spawn_blocking failed")?;

		// Add to our internal state
		let image_id = ImageId(entry.index() as u64);

		Ok(entry.insert(ImageEntry {
			id: image_id,
			hash,
			tags: HashMap::new(),
			attributes: HashMap::new(),
			active: false,
		}))
	}

	/// Internal method for durably adding to the string table file when needed
	/// If the string already exists, returns the entry
	/// Otherwise, appends the string to the file and returns the new entry
	async fn add_string_or_get_mut<'a>(
		&self,
		string: String,
		string_table: &'a mut StringTableRwGuard<'_>,
	) -> Result<(StringId, &'a mut Option<NotNan<f32>>), DatabaseError> {
		let entry = match string_table.entry_by_key(string.clone()) {
			// Case where the string already exists
			indexmap::map::Entry::Occupied(entry) => return Ok((entry.index().into(), entry.into_mut())),
			// Case where the string doesn't exist
			indexmap::map::Entry::Vacant(entry) => entry,
		};

		// Append to the file
		let mut strings_file = self.strings_file.clone().lock_owned().await;
		let numeric = string.parse::<NotNan<f32>>().ok();
		task::spawn_blocking(move || append_to_strings_table(&mut strings_file, &string))
			.await
			.expect("spawn_blocking failed")?;

		// Add to our internal state
		let string_id = entry.index().into();
		Ok((string_id, entry.insert(numeric)))
	}

	/// Internal method for durably adding to the log file
	async fn add_log_entry(&self, log: LogEntry) -> Result<(), DatabaseError> {
		let mut logs_file = self.logs_file.clone().lock_owned().await;

		task::spawn_blocking(move || append_to_log_file(&mut logs_file, &log))
			.await
			.expect("spawn_blocking failed")?;

		Ok(())
	}


	// ========================
	// Internal State Management
	// ========================

	/// Internal method for updating the state so that a tag exists and is active
	async fn state_add_tag(&self, tag: String) -> StateUpdateResult<TagId> {
		let mut tags = self.tags.write().await;
		let entry = tags.entry_by_key(tag);
		let tag_id: TagId = entry.index().into();

		match entry {
			// Tag already exists and is active, return NoOp
			indexmap::map::Entry::Occupied(entry) if entry.get().active => StateUpdateResult::NoOp,
			// Tag already exists but is inactive, reactivate it
			indexmap::map::Entry::Occupied(entry) => {
				entry.into_mut().active = true;
				StateUpdateResult::Updated(tag_id)
			},
			// Tag doesn't exist, add it as active
			indexmap::map::Entry::Vacant(entry) => {
				entry.insert(TagEntry { active: true });
				StateUpdateResult::Updated(tag_id)
			},
		}
	}

	/// Internal method for updating the state so that a tag either doesn't exist or is inactive
	async fn state_remove_tag(&self, tag_id: TagId) -> StateUpdateResult<TagId> {
		// Lock the data structures
		let mut tags = self.tags.write().await;
		let mut index_by_tag = self.index_by_tag.write().await;
		let mut images = self.images.write().await;

		match tags.get_by_id_mut(tag_id) {
			// Tag doesn't exist or is already inactive, return as NoOp
			None | Some(TagEntry { active: false }) => return StateUpdateResult::NoOp,
			// Tag exists and is active, deactivate it and continue
			Some(tag) => {
				tag.active = false;
			},
		}

		// Remove from all images
		if let Some(image_ids) = index_by_tag.get(tag_id) {
			for image_id in image_ids {
				let image = images.get_by_id_mut(*image_id).unwrap();
				image.tags.remove(&tag_id);
			}
		}

		// Remove from tag index
		index_by_tag.remove_tag(tag_id);

		StateUpdateResult::Updated(tag_id)
	}

	/// Internal method for updating the state so that an image is active
	async fn state_add_image(&self, image: &mut ImageEntry, index_attribute_numeric: &mut IndexByAttributeNumericRwGuard<'_>) -> StateUpdateResult<()> {
		let image_id = image.id;

		// If the image is already active, return
		if image.active {
			return StateUpdateResult::NoOp;
		}

		image.active = true;

		// Update tag count virtual attribute
		let tag_count_id: AttributeKeyId = self.get_or_insert_string_id("tag_count".to_string()).await.unwrap().into();
		let tag_count = NotNan::new(image.tags.len() as f32).unwrap();
		index_attribute_numeric.add(tag_count_id, tag_count, image_id);

		StateUpdateResult::Updated(())
	}

	/// Internal method for updating the state so that an image is inactive
	async fn state_remove_image(&self, image_id: ImageId) -> StateUpdateResult<()> {
		// Lock the data structures
		let mut images = self.images.write().await;
		let mut index_by_tag = self.index_by_tag.write().await;
		let mut index_by_attribute_numeric = self.index_by_attribute_numeric.write().await;
		let mut index_by_attribute = self.index_by_attribute.write().await;

		let image = match images.get_by_id_mut(image_id) {
			// Image exists and is active, continue
			Some(image) if image.active => image,
			// Image exists but is already inactive, return
			Some(_) => return StateUpdateResult::NoOp,
			// Image doesn't exist, return
			None => return StateUpdateResult::NoOp,
		};

		// At this point the image exists and is active, so deactivate it
		image.active = false;
		image.tags.clear();
		image.attributes.clear();

		// Remove from indexes
		index_by_tag.remove_image(image_id);
		index_by_attribute_numeric.remove_image(image_id);
		index_by_attribute.remove_image(image_id);

		StateUpdateResult::Updated(())
	}

	/// Internal method for updating the state so that an image has a tag
	async fn state_add_image_tag(&self, image_id: ImageId, tag_id: TagId, user_id: UserId) -> StateUpdateResult<()> {
		// Lock the data structures
		let mut images = self.images.write().await;
		let tags = self.tags.read().await;
		let mut index_by_tag = self.index_by_tag.write().await;
		let mut index_by_attribute_numeric = self.index_by_attribute_numeric.write().await;

		let image = match images.get_by_id_mut(image_id) {
			Some(image) => image,
			None => return StateUpdateResult::ErrorImageDoesNotExist,
		};
		let tag = match tags.get_by_id(tag_id) {
			Some(tag) => tag,
			None => return StateUpdateResult::ErrorTagDoesNotExist,
		};
		let old_tag_count = NotNan::new(image.tags.len() as f32).unwrap();
		let new_tag_count = NotNan::new((image.tags.len() + 1) as f32).unwrap();

		if !image.active {
			return StateUpdateResult::ErrorImageDoesNotExist;
		}

		if !tag.active {
			return StateUpdateResult::ErrorTagDoesNotExist;
		}

		// If the image already has the tag, return
		if image.tags.contains_key(&tag_id) {
			return StateUpdateResult::NoOp;
		}

		// Add the tag to the image
		image.tags.insert(tag_id, user_id);

		// Update the tag index
		index_by_tag.add(tag_id, image_id);

		// Update the tag count virtual attribute
		let tag_count_key_id: AttributeKeyId = self.get_string_id("tag_count").await.unwrap().into();
		index_by_attribute_numeric.remove(tag_count_key_id, old_tag_count, image_id);
		index_by_attribute_numeric.add(tag_count_key_id, new_tag_count, image_id);

		StateUpdateResult::Updated(())
	}

	/// Internal method for updating the state so that an image doesn't have a tag
	async fn state_remove_image_tag(&self, image_id: ImageId, tag_id: TagId) -> StateUpdateResult<()> {
		// Lock the data structures
		let mut images = self.images.write().await;
		let mut index_by_tag = self.index_by_tag.write().await;
		let mut index_by_attribute_numeric = self.index_by_attribute_numeric.write().await;

		let image = match images.get_by_id_mut(image_id) {
			Some(image) => image,
			None => return StateUpdateResult::ErrorImageDoesNotExist,
		};

		if !image.active {
			return StateUpdateResult::ErrorImageDoesNotExist;
		}

		// If the image doesn't have the tag, return
		if !image.tags.contains_key(&tag_id) {
			return StateUpdateResult::NoOp;
		}

		let old_tag_count = NotNan::new(image.tags.len() as f32).unwrap();
		let new_tag_count = NotNan::new((image.tags.len() - 1) as f32).unwrap();

		// Remove the tag from the image
		image.tags.remove(&tag_id);

		// Update the tag index
		index_by_tag.remove(tag_id, image_id);

		// Update the tag count virtual attribute
		let tag_count_key_id: AttributeKeyId = self.get_string_id("tag_count").await.unwrap().into();
		index_by_attribute_numeric.remove(tag_count_key_id, old_tag_count, image_id);
		index_by_attribute_numeric.add(tag_count_key_id, new_tag_count, image_id);

		StateUpdateResult::Updated(())
	}

	/// Internal method for updating the state so that an image has an attribute
	/// This is the singular version. All existing values for the key (if any) are removed and replaced with the new value.
	async fn state_add_image_attribute_singular(
		&self,
		image_id: ImageId,
		key_id: AttributeKeyId,
		value_id: AttributeValueId,
		user_id: UserId,
	) -> StateUpdateResult<Vec<AttributeValueId>> {
		// Lock the data structures
		let mut images = self.images.write().await;
		let mut index_by_attribute = self.index_by_attribute.write().await;
		let mut index_by_attribute_numeric = self.index_by_attribute_numeric.write().await;
		let string_table = self.string_table.read().await;

		let image = match images.get_by_id_mut(image_id) {
			Some(image) => image,
			None => return StateUpdateResult::ErrorImageDoesNotExist,
		};

		if !image.active {
			return StateUpdateResult::ErrorImageDoesNotExist;
		}

		// If the image already has the attribute, return
		if image
			.attributes
			.get(&key_id)
			.map_or(false, |values| values.contains_key(&value_id) && values.len() == 1)
		{
			return StateUpdateResult::NoOp;
		}

		// Remove the existing values
		let entry = image.attributes.entry(key_id).or_default();
		let removed_values = entry.drain().map(|(k, _)| k).collect::<Vec<_>>();

		// Add the new value
		entry.insert(value_id, user_id);

		// Update the attribute indexes
		for removed_value in &removed_values {
			index_by_attribute.remove(key_id, *removed_value, image_id);
		}

		index_by_attribute.add(key_id, value_id, image_id);

		// Update the numeric attribute index
		for removed_value in &removed_values {
			if let Some(n) = string_table.get_by_id((*removed_value).into()).unwrap() {
				index_by_attribute_numeric.remove(key_id, *n, image_id);
			}
		}

		if let Some(n) = string_table.get_by_id(value_id.into()).unwrap() {
			index_by_attribute_numeric.add(key_id, *n, image_id);
		}

		StateUpdateResult::Updated(removed_values)
	}

	/// Internal method for updating the state so that an image has an attribute
	async fn state_add_image_attribute(&self, image_id: ImageId, key_id: AttributeKeyId, value_id: AttributeValueId, user_id: UserId) -> StateUpdateResult<()> {
		// Lock the data structures
		let mut images = self.images.write().await;
		let mut index_by_attribute = self.index_by_attribute.write().await;
		let mut index_by_attribute_numeric = self.index_by_attribute_numeric.write().await;

		let image = match images.get_by_id_mut(image_id) {
			Some(image) => image,
			None => return StateUpdateResult::ErrorImageDoesNotExist,
		};

		if !image.active {
			return StateUpdateResult::ErrorImageDoesNotExist;
		}

		// If the image already has the attribute, return
		if image.attributes.get(&key_id).map_or(false, |values| values.contains_key(&value_id)) {
			return StateUpdateResult::NoOp;
		}

		// Add the attribute to the image
		image.attributes.entry(key_id).or_default().insert(value_id, user_id);

		// Update the attribute indexes
		index_by_attribute.add(key_id, value_id, image_id);

		// Update the numeric attribute index
		if let Some(n) = self.string_table.read().await.get_by_id(value_id.into()).unwrap() {
			index_by_attribute_numeric.add(key_id, *n, image_id);
		}

		StateUpdateResult::Updated(())
	}

	/// Internal method for updating the state so that an image doesn't have an attribute
	async fn state_remove_image_attribute(&self, image_id: ImageId, key_id: AttributeKeyId, value_id: AttributeValueId) -> StateUpdateResult<()> {
		// Lock the data structures
		let mut images = self.images.write().await;
		let mut index_by_attribute = self.index_by_attribute.write().await;
		let mut index_by_attribute_numeric = self.index_by_attribute_numeric.write().await;

		let image = match images.get_by_id_mut(image_id) {
			Some(image) => image,
			None => return StateUpdateResult::ErrorImageDoesNotExist,
		};

		if !image.active {
			return StateUpdateResult::ErrorImageDoesNotExist;
		}

		// If the image doesn't have the attribute, return
		if !image.attributes.get(&key_id).map_or(false, |values| values.contains_key(&value_id)) {
			return StateUpdateResult::NoOp;
		}

		// Remove the attribute from the image
		image.attributes.get_mut(&key_id).unwrap().remove(&value_id);

		// If the attribute list is now empty, remove the key
		// To save space, and to make it clear that this image doesn't have this attribute
		if image.attributes[&key_id].is_empty() {
			image.attributes.remove(&key_id);
		}

		// Update the attribute indexes
		index_by_attribute.remove(key_id, value_id, image_id);

		// Update the numeric attribute index
		if let Some(n) = self.string_table.read().await.get_by_id(value_id.into()).unwrap() {
			index_by_attribute_numeric.remove(key_id, *n, image_id);
		}

		StateUpdateResult::Updated(())
	}

	/// Internal method for adding a new task to the task queue
	async fn state_add_task(&self, task: TaskEntry, mut task_queue: TaskQueueWriteLock<'_>, mut small_db: SmallDbGuard) -> Result<(), DatabaseError> {
		// Make sure ID isn't already used
		if task_queue.contains_key(&task.id) {
			return Err(DatabaseError::TaskIdAlreadyExists);
		}

		// Find the next task id
		//let max_task_id = task_queue.keys().max().copied().unwrap_or(TaskId(0));
		//let task_id = max_task_id.0.checked_add(1).map(TaskId).ok_or(DatabaseError::TableIdOverflow)?;

		// Insert into small db
		let task_id = task.id;
		let task_clone = SmallDbEntry::Task(task.clone());
		let row_id = task::spawn_blocking(move || small_db.insert_row(&task_clone))
			.await
			.expect("spawn_blocking failed")?;

		// Update the state
		task_queue.insert(task_id, (task, row_id));

		Ok(())
	}

	/// Internal method for removing a task from the task queue
	async fn state_remove_task(&self, task_id: TaskId) -> Result<(), DatabaseError> {
		let mut task_queue = self.task_queue.write().await;
		let mut small_db = self.small_db.clone().lock_owned().await;

		// Remove from the state and get the row id
		let row_id = match task_queue.remove(&task_id) {
			Some((_, row_id)) => row_id,
			None => return Err(DatabaseError::TaskDoesNotExist),
		};

		// Remove from the small db
		task::spawn_blocking(move || small_db.delete_row(row_id))
			.await
			.expect("spawn_blocking failed")?;

		Ok(())
	}

	/// Internal method for updating a task
	async fn state_update_task(&self, task: TaskEntry, mut task_queue: TaskQueueWriteLock<'_>, mut small_db: SmallDbGuard) -> Result<(), DatabaseError> {
		// Get the row id
		let row_id = match task_queue.get(&task.id) {
			Some(&(_, row_id)) => row_id,
			None => return Err(DatabaseError::TaskDoesNotExist),
		};

		// Update the small db
		let task_clone = SmallDbEntry::Task(task.clone());
		let new_row_id = task::spawn_blocking(move || small_db.update_row(row_id, &task_clone))
			.await
			.expect("spawn_blocking failed")?;

		// Update the state
		task_queue.insert(task.id, (task, new_row_id));

		Ok(())
	}


	// ========================
	// Public Actions
	// ========================

	/// Execute an add_tag action on the database.
	/// If the tag already exists and is active, returns false, indicating that no changes were made.
	/// Otherwise the tag is added and the action is logged, returning true to indicate a change was made.
	pub async fn add_tag(&self, tag: String, user_id: UserId) -> Result<bool, DatabaseError> {
		match self.state_add_tag(tag.clone()).await {
			// If the tag already exists and is active, return false.
			StateUpdateResult::NoOp => return Ok(false),
			StateUpdateResult::Updated(_) => {},
			StateUpdateResult::ErrorImageDoesNotExist | StateUpdateResult::ErrorTagDoesNotExist => unreachable!(),
		}

		// Log the action
		self.add_log_entry(LogEntry {
			timestamp: Utc::now().timestamp_millis(),
			user_id,
			action: LogActionWithData::AddTag(tag),
		})
		.await?;

		Ok(true)
	}

	/// Execute a remove_tag action on the database.
	/// If the tag doesn't exist or is already inactive, returns false, indicating that no changes were made.
	/// Otherwise the tag is deactivated and the action is logged, returning true to indicate a change was made.
	pub async fn remove_tag(&self, tag_id: TagId, user_id: UserId) -> Result<bool, DatabaseError> {
		match self.state_remove_tag(tag_id).await {
			// If the tag doesn't exist or is already inactive, return false.
			StateUpdateResult::NoOp => return Ok(false),
			StateUpdateResult::Updated(_) => {},
			StateUpdateResult::ErrorImageDoesNotExist | StateUpdateResult::ErrorTagDoesNotExist => unreachable!(),
		}

		// Log the action
		self.add_log_entry(LogEntry {
			timestamp: Utc::now().timestamp_millis(),
			user_id,
			action: LogActionWithData::RemoveTag(tag_id),
		})
		.await?;

		Ok(true)
	}

	/// Execute an add_image action on the database.
	/// If the image already exists and is active, returns false, indicating that no changes were made.
	/// Otherwise the image is added and the action is logged, returning true to indicate a change was made.
	pub async fn add_image(&self, hash: ImageHash, user_id: UserId) -> Result<bool, DatabaseError> {
		// Lock the data structures
		let mut images = self.images.write().await;
		let mut index_by_attribute_numeric = self.index_by_attribute_numeric.write().await;

		// Ensure the image exists
		// If it didn't, this will add it to the image hash file
		let image = self.add_image_hash_or_get_mut(hash, &mut images).await?;

		match self.state_add_image(image, &mut index_by_attribute_numeric).await {
			// If the image already exists and is active, return false.
			StateUpdateResult::NoOp => return Ok(false),
			StateUpdateResult::Updated(_) => {},
			StateUpdateResult::ErrorImageDoesNotExist | StateUpdateResult::ErrorTagDoesNotExist => unreachable!(),
		}

		// Log the action
		let image_id = image.id;

		self.add_log_entry(LogEntry {
			timestamp: Utc::now().timestamp_millis(),
			user_id,
			action: LogActionWithData::AddImage(image_id),
		})
		.await?;

		Ok(true)
	}

	/// Execute a remove_image action on the database.
	/// If the image doesn't exist or is already inactive, returns false, indicating that no changes were made.
	/// Otherwise the image is deactivated and the action is logged, returning true to indicate a change was made.
	/// Possible side effects:
	/// - self.images
	/// - self.index_by_tag
	/// - self.index_by_attribute
	/// - self.index_by_attribute_numeric
	/// - self.string_table (tag_count_id)
	/// - self.logs_file
	/// - self.strings_file
	pub async fn remove_image(&self, image_id: ImageId, user_id: UserId) -> Result<bool, DatabaseError> {
		match self.state_remove_image(image_id).await {
			// If the image doesn't exist or is already inactive, return false.
			StateUpdateResult::NoOp => return Ok(false),
			StateUpdateResult::Updated(_) => {},
			StateUpdateResult::ErrorImageDoesNotExist | StateUpdateResult::ErrorTagDoesNotExist => unreachable!(),
		}

		// Log the action
		self.add_log_entry(LogEntry {
			timestamp: Utc::now().timestamp_millis(),
			user_id,
			action: LogActionWithData::RemoveImage(image_id),
		})
		.await?;

		Ok(true)
	}

	/// Execute an add_image_tag action on the database.
	/// Possible side effects:
	/// - self.images
	/// - self.index_by_tag
	/// - self.index_by_attribute_numeric (tag_count)
	/// - self.logs_file
	pub async fn add_image_tag(&self, image_id: ImageId, tag_id: TagId, user_id: UserId) -> Result<StateUpdateResult<()>, DatabaseError> {
		match self.state_add_image_tag(image_id, tag_id, user_id).await {
			// If the image already had the tag, return
			StateUpdateResult::NoOp => return Ok(StateUpdateResult::NoOp),
			// If the image didn't exist or the tag didn't exist, return
			StateUpdateResult::ErrorImageDoesNotExist => return Ok(StateUpdateResult::ErrorImageDoesNotExist),
			StateUpdateResult::ErrorTagDoesNotExist => return Ok(StateUpdateResult::ErrorTagDoesNotExist),
			// If the tag was added, continue to log the action
			StateUpdateResult::Updated(_) => {},
		}

		// Log the action
		self.add_log_entry(LogEntry {
			timestamp: Utc::now().timestamp_millis(),
			user_id,
			action: LogActionWithData::AddImageTag(image_id, tag_id),
		})
		.await?;

		Ok(StateUpdateResult::Updated(()))
	}

	/// Execute a remove_image_tag action on the database.
	/// Possible side effects:
	/// - self.images
	/// - self.index_by_tag
	/// - self.index_by_attribute_numeric (tag_count)
	/// - self.logs_file
	pub async fn remove_image_tag(&self, image_id: ImageId, tag_id: TagId, user_id: UserId) -> Result<StateUpdateResult<()>, DatabaseError> {
		match self.state_remove_image_tag(image_id, tag_id).await {
			// If the image didn't have the tag, return false
			StateUpdateResult::NoOp => return Ok(StateUpdateResult::NoOp),
			// If the tag was removed, continue to log the action
			StateUpdateResult::Updated(_) => {},
			// If the image doesn't exist, return an error
			StateUpdateResult::ErrorImageDoesNotExist => return Ok(StateUpdateResult::ErrorImageDoesNotExist),
			StateUpdateResult::ErrorTagDoesNotExist => unreachable!(),
		}

		// Log the action
		self.add_log_entry(LogEntry {
			timestamp: Utc::now().timestamp_millis(),
			user_id,
			action: LogActionWithData::RemoveImageTag(image_id, tag_id),
		})
		.await?;

		Ok(StateUpdateResult::Updated(()))
	}

	/// Does a singular version of add_image_attribute.
	/// This may log several actions, if any values are removed.
	/// Possible side effects:
	/// - self.images
	/// - self.index_by_attribute
	/// - self.index_by_attribute_numeric
	/// - self.logs_file
	/// - self.strings_file
	///
	/// Note: The attribute key and value strings will be added to the string table if they don't already exist.
	pub async fn add_image_attribute_singular(
		&self,
		image_id: ImageId,
		key: String,
		value: String,
		user_id: UserId,
	) -> Result<StateUpdateResult<()>, DatabaseError> {
		let key_id: AttributeKeyId = self.get_or_insert_string_id(key).await?.into();
		let value_id: AttributeValueId = self.get_or_insert_string_id(value).await?.into();

		let removed_values = match self.state_add_image_attribute_singular(image_id, key_id, value_id, user_id).await {
			// If the image already has the attribute, return
			StateUpdateResult::NoOp => return Ok(StateUpdateResult::NoOp),
			// If the attribute was added, continue to log the action
			StateUpdateResult::Updated(removed_values) => removed_values,
			// If the image doesn't exist, return an error
			StateUpdateResult::ErrorImageDoesNotExist => return Ok(StateUpdateResult::ErrorImageDoesNotExist),
			StateUpdateResult::ErrorTagDoesNotExist => unreachable!(),
		};

		// Log the removals
		for removed_value_id in removed_values {
			self.add_log_entry(LogEntry {
				timestamp: Utc::now().timestamp_millis(),
				user_id,
				action: LogActionWithData::RemoveAttribute(image_id, key_id, removed_value_id),
			})
			.await?;
		}

		// Log the addition
		self.add_log_entry(LogEntry {
			timestamp: Utc::now().timestamp_millis(),
			user_id,
			action: LogActionWithData::AddAttribute(image_id, key_id, value_id),
		})
		.await?;

		Ok(StateUpdateResult::Updated(()))
	}

	/// Execute an add_image_attribute action on the database.
	/// Possible side effects:
	/// - self.images
	/// - self.index_by_attribute
	/// - self.index_by_attribute_numeric
	/// - self.logs_file
	/// - self.strings_file
	///
	/// Note: The attribute key and value strings will be added to the string table if they don't already exist.
	pub async fn add_image_attribute(&self, image_id: ImageId, key: String, value: String, user_id: UserId) -> Result<StateUpdateResult<()>, DatabaseError> {
		let key_id: AttributeKeyId = self.get_or_insert_string_id(key).await?.into();
		let value_id: AttributeValueId = self.get_or_insert_string_id(value).await?.into();

		match self.state_add_image_attribute(image_id, key_id, value_id, user_id).await {
			// If the image already has the attribute, return
			StateUpdateResult::NoOp => return Ok(StateUpdateResult::NoOp),
			// If the attribute was added, continue to log the action
			StateUpdateResult::Updated(_) => {},
			// If the image doesn't exist, return an error
			StateUpdateResult::ErrorImageDoesNotExist => return Ok(StateUpdateResult::ErrorImageDoesNotExist),
			StateUpdateResult::ErrorTagDoesNotExist => unreachable!(),
		}

		// Log the action
		self.add_log_entry(LogEntry {
			timestamp: Utc::now().timestamp_millis(),
			user_id,
			action: LogActionWithData::AddAttribute(image_id, key_id, value_id),
		})
		.await?;

		Ok(StateUpdateResult::Updated(()))
	}

	/// Execute a remove_image_attribute action on the database.
	/// Possible side effects:
	/// - self.images
	/// - self.index_by_attribute
	/// - self.index_by_attribute_numeric
	/// - self.logs_file
	pub async fn remove_image_attribute(
		&self,
		image_id: ImageId,
		key_id: AttributeKeyId,
		value_id: AttributeValueId,
		user_id: UserId,
	) -> Result<StateUpdateResult<()>, DatabaseError> {
		match self.state_remove_image_attribute(image_id, key_id, value_id).await {
			// If the image didn't have the attribute, return
			StateUpdateResult::NoOp => return Ok(StateUpdateResult::NoOp),
			// If the attribute was removed, continue to log the action
			StateUpdateResult::Updated(_) => {},
			// If the image doesn't exist, return an error
			StateUpdateResult::ErrorImageDoesNotExist => return Ok(StateUpdateResult::ErrorImageDoesNotExist),
			StateUpdateResult::ErrorTagDoesNotExist => unreachable!(),
		}

		// Log the action
		self.add_log_entry(LogEntry {
			timestamp: Utc::now().timestamp_millis(),
			user_id,
			action: LogActionWithData::RemoveAttribute(image_id, key_id, value_id),
		})
		.await?;

		Ok(StateUpdateResult::Updated(()))
	}

	/// Add a new task to the task queue.
	/// Possible side effects:
	/// - self.task_queue
	/// - self.small_db
	/// - self.strings_file
	pub async fn add_task(&self, task_group: String, task_data: String, task_status: TaskStatus, user_id: UserId) -> Result<(), DatabaseError> {
		// Get string IDs
		let task_group = self.get_or_insert_string_id(task_group).await?;

		// Grab locks
		let task_queue = self.task_queue.write().await;
		let small_db = self.small_db.clone().lock_owned().await;

		// Find the next task id
		let task_id = {
			let max_task_id = task_queue.keys().max().copied().unwrap_or(TaskId(0));
			max_task_id.0.checked_add(1).map(TaskId).ok_or(DatabaseError::TableIdOverflow)?
		};

		let task = TaskEntry {
			id: task_id,
			group: task_group,
			data: task_data,
			status: task_status,
			modified_time: Utc::now().timestamp_millis(),
			blame: user_id,
		};

		self.state_add_task(task, task_queue, small_db).await?;

		Ok(())
	}

	/// Remove a task from the task queue.
	/// Possible side effects:
	/// - self.task_queue
	/// - self.small_db
	pub async fn remove_task(&self, task_id: TaskId) -> Result<(), DatabaseError> {
		self.state_remove_task(task_id).await
	}

	/// Update a task in the task queue.
	/// Possible side effects:
	/// - self.task_queue
	/// - self.small_db
	pub async fn update_task(
		&self,
		task_id: TaskId,
		data: Option<String>,
		status: Option<TaskStatus>,
		modified_time: Option<i64>,
		blame: Option<UserId>,
		task_queue: TaskQueueWriteLock<'_>,
	) -> Result<(), DatabaseError> {
		let small_db = self.small_db.clone().lock_owned().await;

		// Get the existing task
		let mut task = match task_queue.get(&task_id) {
			Some((task, _)) => task.clone(),
			None => return Err(DatabaseError::TaskDoesNotExist),
		};

		// Make requested changes
		if let Some(data) = data {
			task.data = data;
		}
		if let Some(status) = status {
			task.status = status;
		}
		if let Some(modified_time) = modified_time {
			task.modified_time = modified_time;
		}
		if let Some(blame) = blame {
			task.blame = blame;
		}

		// Update the task
		self.state_update_task(task, task_queue, small_db).await
	}
}


#[must_use]
#[derive(PartialEq, Eq, Debug)]
pub enum StateUpdateResult<T> {
	Updated(T),
	NoOp,
	ErrorImageDoesNotExist,
	ErrorTagDoesNotExist,
}


fn read_small_db<P: AsRef<Path>>(
	path: P,
) -> Result<
	(
		IndexMapTyped<String, UserEntry, UserId>,
		HashMap<UserToken, (UserId, RowId)>,
		HashMap<TaskId, (TaskEntry, RowId)>,
		SmallDb<SmallDbEntry>,
	),
	DatabaseError,
> {
	let mut users = BTreeMap::new();
	let mut user_tokens = HashMap::new();
	let mut task_queue = HashMap::new();

	let small_db = SmallDb::open(path.as_ref(), |row_id, row: SmallDbEntry| match row {
		SmallDbEntry::User {
			user_id,
			username,
			hashed_login_key,
			scopes,
		} => {
			users.insert(user_id, (username, UserEntry::new(hashed_login_key, scopes, row_id)));
		},
		SmallDbEntry::UserToken { token, user_id } => {
			user_tokens.insert(token, (user_id, row_id));
		},
		SmallDbEntry::Task(task) => {
			task_queue.insert(task.id, (task, row_id));
		},
	})?;

	// Build the index map
	let mut users_indexmap = IndexMapTyped::new();

	for (user_id, (username, user_entry)) in users.into_iter() {
		let user_entry = user_entry?;

		if user_id != UserId(users_indexmap.len() as u64) {
			panic!("User IDs are not contiguous");
		}

		users_indexmap.insert(username, user_entry);
	}

	Ok((users_indexmap, user_tokens, task_queue, small_db))
}
