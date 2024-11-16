//! Database file format and utilities
//!
//! Most of the database is stored in append only structures, simplifying durability considerations.
//! In _most_ cases, appending to a file only carries the risk of a partial write, which all of the
//! reader code here handles gracefully.
//! Some structures use a count at the beginning of the file to allow for more efficient reading.
//! In _most_ cases, re-writing 8 bytes at the beginning of a file is atomic, since the beginning of the
//! file should always align with a block boundary. So this operation only caries the risk of
//! inconsistency.  Which is fine since the count is only used for allocation and progress bars.
//!
//! ## String Table
//!
//! The string table is stored as:
//! - count (u64)
//! - string 1
//! - checksum 1 (u16)
//! - string 2
//! - checksum 2 (u16)
//! - ...
//!
//!
//! ## Image Hash Table
//!
//! The image hash table is stored as:
//! - hash 1 (32 bytes)
//! - checksum 1 (u8)
//! - hash 2 (32 bytes)
//! - checksum 2 (u8)
//! - ...
//!
//!
//! ## Log File
//!
//! The log file is stored as:
//! - count (u64)
//! - log entry 1 with checksum
//! - log entry 2 with checksum
//! - ...
//!
//!
//! ## Users Table
//!
//! The users table is unique, as it is NOT append only (we need to modify values in place and can't store history due to privacy concerns).
//! So during modification the updated table is written in whole to a temporary file, and then atomically swapped with the original file.
//!
//! The users table is stored as:
//! - count (u64)
//! - username 1 (string)
//! - hashed login key 1 (32 bytes)
//! - scopes 1 (string)
//! - checksum 1 (u16)
//! - username 2 (string)
//! - hashed login key 2 (32 bytes)
//! - scopes 2 (string)
//! - ...
//!
//!
//! ## User Tokens Table
//!
//! The user tokens table is stored as:
//! - user token 1 (32 bytes)
//! - user_id 1 (u64)
//! - checksum 1 (u8)
//! - user token 2 (32 bytes)
//! - user_id 2 (u64)
//! - checksum 2 (u8)
//! - ...
//!
use std::{
	collections::HashMap,
	fs::File,
	io::{BufWriter, Read, Seek, Write},
	path::Path,
};

use crate::{
	database::{ImageEntry, UserEntry},
	default_progress_style,
	errors::DatabaseError,
	AttributeKeyId, AttributeValueId, HashedLoginKey, ImageHash, ImageId, IndexMapTyped, StringId, TagId, UserId, UserToken,
};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use indicatif::{ProgressBar, ProgressDrawTarget};
use ordered_float::NotNan;
use tempfile::NamedTempFile;
use xxhash_rust::xxh3::{xxh3_64, Xxh3};


/// Used as a sigil value in some cases
pub(crate) const BAD_USER_ID: UserId = UserId(u64::MAX);


/// Wraps a reader to calculate hashes on the fly
struct HasherReader<R> {
	inner: R,
	hasher: Xxh3,
}

impl<R: Read> HasherReader<R> {
	fn new(inner: R, hasher: Xxh3) -> Self {
		Self { inner, hasher }
	}

	fn reset(&mut self) {
		self.hasher.reset();
	}

	fn digest(&self) -> u64 {
		self.hasher.digest()
	}
}

impl<R: Read> Read for HasherReader<R> {
	fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
		let n = self.inner.read(buf)?;
		self.hasher.update(&buf[..n]);
		Ok(n)
	}
}


/// Represents a LogEntry read from the log, or a LogEntry to be written to the log
/// Log entries are stored as:
/// - timestamp (i64)
/// - user_id (variable-length integer)
/// - action (u8)
/// - data (variable-length, depending on the action)
/// - checksum (u8)
///
/// A single byte checksum is used since most logs are small (~32 bytes), which 1 byte of checksum
/// is sufficient for.  Only AddTag is longer, as it encodes a string, but all tags should be short.
#[derive(Debug)]
pub(crate) struct LogEntry {
	pub timestamp: i64,
	pub user_id: UserId,
	pub action: LogActionWithData,
}

impl LogEntry {
	/// Writes this LogEntry to a writer
	fn write_to<W: Write>(&self, writer: &mut W) -> Result<(), DatabaseError> {
		let mut buffer = Vec::with_capacity(32);

		// Write timestamp
		buffer
			.write_u64::<LittleEndian>(self.timestamp as u64)
			.expect("in-memory buffer should not fail");

		// Write user_id
		write_vli(&mut buffer, self.user_id.0).expect("in-memory buffer should not fail");

		// Write action
		buffer.write_u8(self.action.to_u8()).expect("in-memory buffer should not fail");

		match &self.action {
			LogActionWithData::AddTag(tag) => {
				// Write tag
				write_string(&mut buffer, tag).expect("in-memory buffer should not fail");
			},
			LogActionWithData::RemoveTag(tag_id) => {
				// Write tag_id
				write_vli(&mut buffer, tag_id.0).expect("in-memory buffer should not fail");
			},
			LogActionWithData::AddImage(image_id) | LogActionWithData::RemoveImage(image_id) => {
				// Write image_id
				write_vli(&mut buffer, image_id.0).expect("in-memory buffer should not fail");
			},
			LogActionWithData::AddImageTag(image_id, tag_id) | LogActionWithData::RemoveImageTag(image_id, tag_id) => {
				// Write image_id
				write_vli(&mut buffer, image_id.0).expect("in-memory buffer should not fail");
				// Write tag_id
				write_vli(&mut buffer, tag_id.0).expect("in-memory buffer should not fail");
			},
			LogActionWithData::AddAttribute(image_id, key_id, value_id) | LogActionWithData::RemoveAttribute(image_id, key_id, value_id) => {
				// Write image_id
				write_vli(&mut buffer, image_id.0).expect("in-memory buffer should not fail");
				// Write key_id
				write_vli(&mut buffer, key_id.0).expect("in-memory buffer should not fail");
				// Write value_id
				write_vli(&mut buffer, value_id.0).expect("in-memory buffer should not fail");
			},
		}

		// Write checksum
		let checksum = (xxh3_64(&buffer) & 0xff) as u8;
		buffer.write_u8(checksum).expect("in-memory buffer should not fail");

		// Write the buffer to the writer
		writer.write_all(&buffer)?;

		Ok(())
	}
}


/// Represents a log action with associated data
#[derive(Debug)]
pub enum LogActionWithData {
	AddTag(String),
	RemoveTag(TagId),
	AddImage(ImageId),
	RemoveImage(ImageId),
	AddImageTag(ImageId, TagId),
	RemoveImageTag(ImageId, TagId),
	AddAttribute(ImageId, AttributeKeyId, AttributeValueId),
	RemoveAttribute(ImageId, AttributeKeyId, AttributeValueId),
}

impl LogActionWithData {
	fn to_u8(&self) -> u8 {
		match self {
			Self::AddTag(_) => 0,
			Self::RemoveTag(_) => 1,
			Self::AddImage(_) => 2,
			Self::RemoveImage(_) => 3,
			Self::AddImageTag(_, _) => 4,
			Self::RemoveImageTag(_, _) => 5,
			Self::AddAttribute(_, _, _) => 6,
			Self::RemoveAttribute(_, _, _) => 7,
		}
	}
}


/// Internal enum to represent log actions (without associated data)
enum LogAction {
	AddTag,
	RemoveTag,
	AddImage,
	RemoveImage,
	AddImageTag,
	RemoveImageTag,
	AddAttribute,
	RemoveAttribute,
}

impl LogAction {
	fn from_u8(u: u8) -> Option<Self> {
		match u {
			0 => Some(Self::AddTag),
			1 => Some(Self::RemoveTag),
			2 => Some(Self::AddImage),
			3 => Some(Self::RemoveImage),
			4 => Some(Self::AddImageTag),
			5 => Some(Self::RemoveImageTag),
			6 => Some(Self::AddAttribute),
			7 => Some(Self::RemoveAttribute),
			_ => None,
		}
	}
}


// =============================================
// Basic writing and reading functions
// =============================================

/// Write a string to a writer
/// The string is prefixed with its length as a variable-length integer,
/// and then the bytes of the string are written as UTF-8.
pub(crate) fn write_string<W: Write>(mut writer: W, s: &str) -> Result<(), std::io::Error> {
	let bytes = s.as_bytes();
	let len = bytes.len() as u64;
	write_vli(&mut writer, len)?;
	writer.write_all(bytes)?;
	Ok(())
}


/// Write a variable-length integer to a writer
/// Handles up to 64-bit integers.
/// If the integer is less than or equal to 0xfc, it is written as a single byte.
/// Otherwise, it is written as a byte followed by the integer in little-endian format.
/// The byte is 0xfd for 16-bit integers, 0xfe for 32-bit integers, and 0xff for 64-bit integers.
pub(crate) fn write_vli<W: Write>(mut writer: W, n: u64) -> Result<(), std::io::Error> {
	if n <= 0xfc {
		writer.write_all(&[n as u8])?;
	} else if n <= 0xffff {
		writer.write_all(&[0xfd])?;
		writer.write_u16::<LittleEndian>(n as u16)?;
	} else if n <= 0xffffffff {
		writer.write_all(&[0xfe])?;
		writer.write_u32::<LittleEndian>(n as u32)?;
	} else {
		writer.write_all(&[0xff])?;
		writer.write_u64::<LittleEndian>(n)?;
	}

	Ok(())
}


/// Read a variable-length integer from a reader
pub(crate) fn read_vli<R: Read>(mut reader: R) -> Result<u64, DatabaseError> {
	let byte = reader.read_u8()?;

	Ok(match byte {
		0xfd => reader.read_u16::<LittleEndian>()? as u64,
		0xfe => reader.read_u32::<LittleEndian>()? as u64,
		0xff => reader.read_u64::<LittleEndian>()?,
		_ => byte as u64,
	})
}


/// Read a string from a reader
pub(crate) fn read_string<R: Read>(mut reader: R) -> Result<String, DatabaseError> {
	let len = read_vli(&mut reader)?;
	let mut bytes = vec![0u8; len as usize];
	reader.read_exact(&mut bytes)?;
	let s = String::from_utf8(bytes)?;
	Ok(s)
}


// =============================================
// String table
// =============================================

/// Read the string table
pub fn read_string_table<R: Read + Seek>(mut reader: R, with_progress: bool) -> Result<IndexMapTyped<String, Option<NotNan<f32>>, StringId>, DatabaseError> {
	// Read count (may be inaccurate due to corruption, but is only used for allocation and the progress bar)
	reader.seek(std::io::SeekFrom::Start(0))?;
	let num_strings = match reader.read_u64::<LittleEndian>() {
		Ok(num_strings) => num_strings as usize,
		Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(IndexMapTyped::new()), // Empty file
		Err(e) => return Err(e.into()),
	};

	// Read strings
	let pb_target = if with_progress {
		ProgressDrawTarget::stderr()
	} else {
		ProgressDrawTarget::hidden()
	};
	let pb = ProgressBar::with_draw_target(Some(num_strings as u64), pb_target)
		.with_style(default_progress_style())
		.with_prefix("Reading string table");
	let mut table = IndexMapTyped::with_capacity(num_strings);
	let mut reader = HasherReader::new(reader, Xxh3::new());
	pb.enable_steady_tick(std::time::Duration::from_millis(100));

	loop {
		reader.reset();

		let key = match read_string(&mut reader) {
			Ok(key) => key,
			Err(DatabaseError::IoError(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => break, // EOF
			Err(e) => return Err(e),
		};
		let not_nan = key.parse::<NotNan<f32>>().ok();
		let calculated_checksum = (reader.digest() & 0xffff) as u16;
		let stored_checksum = match reader.read_u16::<LittleEndian>() {
			Ok(checksum) => checksum,
			Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break, // EOF
			Err(e) => return Err(e.into()),
		};

		pb.inc(1);

		if calculated_checksum != stored_checksum {
			return Err(DatabaseError::ChecksumMismatch {
				expected: calculated_checksum as u64,
				actual: stored_checksum as u64,
			});
		}

		table.insert(key, not_nan);
	}

	// Check length to detect corruption
	if table.len() != num_strings {
		log::warn!(
			"Warning: string table length mismatch: expected {}, got {}. This may indicate corruption.",
			num_strings,
			table.len()
		);
	}

	Ok(table)
}


/// Append to the strings table
pub(crate) fn append_to_strings_table(strings_file: &mut File, string: &str) -> Result<(), DatabaseError> {
	// Read the current count
	strings_file.seek(std::io::SeekFrom::Start(0))?;
	let string_count = match strings_file.read_u64::<LittleEndian>() {
		Ok(count) => count,
		Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
			// File might be empty, let's check
			if strings_file.seek(std::io::SeekFrom::End(0))? != 0 {
				// File is not empty, but we couldn't read the count
				return Err(e.into());
			}

			// File is empty, write the intial count
			strings_file.seek(std::io::SeekFrom::Start(0))?;
			strings_file.write_u64::<LittleEndian>(0)?;
			0
		},
		Err(e) => return Err(e.into()),
	};

	// Build the record
	let mut buf = Vec::new();
	write_string(&mut buf, string).expect("in-memory buffer should not fail");
	let checksum = (xxh3_64(&buf) & 0xffff) as u16;
	buf.write_u16::<LittleEndian>(checksum).expect("in-memory buffer should not fail");

	// Write the record to the end of the file
	strings_file.seek(std::io::SeekFrom::End(0))?;
	strings_file.write_all(&buf)?;

	// Update the string count
	strings_file.seek(std::io::SeekFrom::Start(0))?;
	strings_file.write_u64::<LittleEndian>(string_count + 1)?;

	// Durably sync
	strings_file.sync_all()?;

	Ok(())
}


// =============================================
// Image hash table
// =============================================

/// Read the image hash table
pub fn read_hash_table<R: Read + Seek>(mut reader: R, with_progress: bool) -> Result<IndexMapTyped<ImageHash, ImageEntry, ImageId>, DatabaseError> {
	// Calculate the number of hashes
	let file_length = reader.seek(std::io::SeekFrom::End(0))?;

	if file_length % 33 != 0 {
		log::warn!("Warning: image hash table file length is not a multiple of 33. This may indicate corruption.");
	}

	let num_hashes = (file_length / 33) as usize;
	reader.seek(std::io::SeekFrom::Start(0))?;

	// Read hashes
	let mut table: IndexMapTyped<ImageHash, _, _> = IndexMapTyped::with_capacity(num_hashes);
	let pb_target = if with_progress {
		ProgressDrawTarget::stderr()
	} else {
		ProgressDrawTarget::hidden()
	};
	let pb = ProgressBar::with_draw_target(Some(num_hashes as u64), pb_target)
		.with_prefix("Reading image hashes")
		.with_style(default_progress_style());
	pb.enable_steady_tick(std::time::Duration::from_millis(100));

	for _ in 0..num_hashes {
		let mut image_hash = ImageHash([0u8; 32]);
		reader.read_exact(&mut image_hash.0)?;
		let stored_checksum = reader.read_u8()?;
		let calculated_checksum = (xxh3_64(&image_hash.0) & 0xff) as u8;

		if calculated_checksum != stored_checksum {
			return Err(DatabaseError::ChecksumMismatch {
				expected: calculated_checksum as u64,
				actual: stored_checksum as u64,
			});
		}

		let entry = table.entry_by_key(image_hash);
		let image = ImageEntry {
			id: ImageId(entry.index() as u64),
			hash: image_hash,
			tags: HashMap::new(),
			attributes: HashMap::new(),
			active: false,
		};
		entry.or_insert(image);

		pb.inc(1);
	}

	Ok(table)
}


/// Append to the image hash table
pub(crate) fn append_to_hash_table(file: &mut File, image_hash: &ImageHash) -> Result<(), DatabaseError> {
	// Build the record
	let mut buf = [0u8; 33];
	buf[0..32].copy_from_slice(&image_hash.0); // hash
	buf[32] = (xxh3_64(&image_hash.0) & 0xff) as u8; // checksum

	// Append to the file
	file.seek(std::io::SeekFrom::End(0))?;
	file.write_all(&buf)?;

	// Durably sync
	file.sync_all()?;

	Ok(())
}


// =============================================
// Users table
// =============================================

/// Read the user table
/// Unlike the other tables, the user table is more primitive and is not append only.
/// Durability is handled through entire file replacement, so no complex recovery is needed.
pub fn read_users_table<R: Read + Seek>(mut reader: R, with_progress: bool) -> Result<IndexMapTyped<String, UserEntry, UserId>, DatabaseError> {
	// Read count
	reader.seek(std::io::SeekFrom::Start(0))?;
	let num_users = match reader.read_u64::<LittleEndian>() {
		Ok(num_users) => num_users as usize,
		Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(IndexMapTyped::new()), // Empty file
		Err(e) => return Err(e.into()),
	};

	// Read users
	let mut table = IndexMapTyped::with_capacity(num_users);
	let mut reader = HasherReader::new(reader, Xxh3::new());
	let pb_target = if with_progress {
		ProgressDrawTarget::stderr()
	} else {
		ProgressDrawTarget::hidden()
	};
	let pb = ProgressBar::with_draw_target(Some(num_users as u64), pb_target)
		.with_prefix("Reading users")
		.with_style(default_progress_style());

	for _ in 0..num_users {
		// Reset the hasher
		reader.reset();

		// Username
		let username = match read_string(&mut reader) {
			Ok(username) => username,
			Err(DatabaseError::IoError(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => break, // EOF
			Err(e) => return Err(e),
		};

		// Login key hash
		let mut hashed_login_key = HashedLoginKey([0u8; 32]);
		reader.read_exact(&mut hashed_login_key.0)?;

		// Scopes
		let scopes = read_string(&mut reader)?;

		// Checksum
		let calculated_checksum = (reader.digest() & 0xffff) as u16;
		let stored_checksum = reader.read_u16::<LittleEndian>()?;

		if calculated_checksum != stored_checksum {
			return Err(DatabaseError::ChecksumMismatch {
				expected: calculated_checksum as u64,
				actual: stored_checksum as u64,
			});
		}

		table.insert(username, UserEntry::new(hashed_login_key, scopes)?);
		pb.inc(1);
	}

	Ok(table)
}


/// Write a user table to a file
/// See notes under `read_users_table` for durability considerations
pub(crate) fn write_users_table(file: &mut File, users: &IndexMapTyped<String, UserEntry, UserId>) -> Result<(), DatabaseError> {
	{
		let mut writer = BufWriter::new(&mut *file);

		// Write count
		writer.write_u64::<LittleEndian>(users.len() as u64)?;

		// Write users
		let mut buffer = Vec::new();
		for (username, user) in users.iter() {
			// Reset the buffer
			buffer.clear();

			// Write username
			write_string(&mut buffer, username).expect("in-memory buffer should not fail");

			// Write login key hash
			std::io::Write::write_all(&mut buffer, &user.hashed_login_key.0).expect("in-memory buffer should not fail");

			// Write scopes
			write_string(&mut buffer, &user.scopes).expect("in-memory buffer should not fail");

			// Write checksum
			let checksum = (xxh3_64(&buffer) & 0xffff) as u16;
			buffer.write_u16::<LittleEndian>(checksum).expect("in-memory buffer should not fail");

			// Write the buffer to the file
			writer.write_all(&buffer)?;
		}

		// Flush
		writer.flush()?;
	}

	// Durably sync
	file.sync_all()?;

	Ok(())
}


/// Update users table file
/// Writes the updated version to a temporary file
/// And then atomically swaps it with the original file
pub(crate) fn update_users_table(dest_path: &Path, users: &IndexMapTyped<String, UserEntry, UserId>) -> Result<File, DatabaseError> {
	let mut tmp_file = NamedTempFile::new_in(dest_path.parent().expect("Users table file should have a parent directory"))?;

	// Write the updated table to the temporary file
	write_users_table(tmp_file.as_file_mut(), users)?;

	// Sync
	tmp_file.as_file_mut().sync_all()?;

	// Replace the original file with the temporary file
	let file = tmp_file.persist(dest_path).map_err(|e| DatabaseError::IoError(e.error))?;

	// TODO: Exclusive lock

	Ok(file)
}


// =============================================
// User tokens table
// =============================================

/// Read user tokens table from a file
pub(crate) fn read_user_tokens_table<R: Read + Seek>(mut reader: R, with_progress: bool) -> Result<HashMap<UserToken, UserId>, DatabaseError> {
	// Calculate the number of tokens
	let file_length = reader.seek(std::io::SeekFrom::End(0))?;

	if file_length % 41 != 0 {
		log::warn!("Warning: user tokens table file length is not a multiple of 41. This may indicate corruption.");
	}

	let num_tokens = (file_length / 41) as usize;
	reader.seek(std::io::SeekFrom::Start(0))?;

	// Read hashes
	let mut table = HashMap::with_capacity(num_tokens);
	let mut buffer = [0u8; 41];
	let pb_target = if with_progress {
		ProgressDrawTarget::stderr()
	} else {
		ProgressDrawTarget::hidden()
	};
	let pb = ProgressBar::with_draw_target(Some(num_tokens as u64), pb_target)
		.with_prefix("Reading user tokens")
		.with_style(default_progress_style());
	pb.enable_steady_tick(std::time::Duration::from_millis(100));

	for _ in 0..num_tokens {
		// Read user token and user_id
		reader.read_exact(&mut buffer)?;
		let user_token = UserToken(buffer[0..32].try_into().unwrap());
		let user_id = UserId(u64::from_le_bytes(buffer[32..40].try_into().unwrap()));
		let stored_checksum = buffer[40];
		let calculated_checksum = (xxh3_64(&buffer[0..40]) & 0xff) as u8;

		if calculated_checksum != stored_checksum {
			return Err(DatabaseError::ChecksumMismatch {
				expected: calculated_checksum as u64,
				actual: stored_checksum as u64,
			});
		}

		pb.inc(1);

		if user_id == BAD_USER_ID {
			// Sigil for a token that has been invalidated
			table.remove(&user_token);
			continue;
		}

		table.insert(user_token, user_id);
	}

	Ok(table)
}


/// Append to the user tokens table
pub(crate) fn append_to_user_tokens_table(file: &mut File, user_token: UserToken, user_id: UserId) -> Result<(), DatabaseError> {
	// Write user token and user_id
	let mut buffer = [0u8; 41];
	buffer[0..32].copy_from_slice(&user_token.0);
	buffer[32..40].copy_from_slice(&user_id.0.to_le_bytes());
	buffer[40] = (xxh3_64(&buffer[0..40]) & 0xff) as u8;

	file.seek(std::io::SeekFrom::End(0))?;
	file.write_all(&buffer)?;

	// Durably sync
	file.sync_all()?;

	Ok(())
}


// =============================================================================
// ===== Log file
// =============================================================================

/// Read a log entry from a reader
fn read_log_entry<R: Read>(reader: &mut HasherReader<R>) -> Result<LogEntry, DatabaseError> {
	reader.reset();

	// Read timestamp (i64)
	let timestamp = reader.read_i64::<LittleEndian>()?; // milliseconds since UNIX epoch

	// Read user_id (i64)
	let user_id = UserId(read_vli(&mut *reader)?);

	// Read action (u8)
	let action = LogAction::from_u8(reader.read_u8()?).ok_or(DatabaseError::CorruptedDatabase)?;

	let log = match action {
		LogAction::AddTag => {
			// Read tag (length-prefixed string)
			let tag = read_string(&mut *reader)?;
			LogEntry {
				timestamp,
				user_id,
				action: LogActionWithData::AddTag(tag),
			}
		},
		LogAction::RemoveTag => {
			// Read tag id
			let tag_id = TagId(read_vli(&mut *reader)?);
			LogEntry {
				timestamp,
				user_id,
				action: LogActionWithData::RemoveTag(tag_id),
			}
		},
		LogAction::AddImage => {
			let image_id = ImageId(read_vli(&mut *reader)?);
			LogEntry {
				timestamp,
				user_id,
				action: LogActionWithData::AddImage(image_id),
			}
		},
		LogAction::RemoveImage => {
			let image_id = ImageId(read_vli(&mut *reader)?);
			LogEntry {
				timestamp,
				user_id,
				action: LogActionWithData::RemoveImage(image_id),
			}
		},
		LogAction::AddImageTag | LogAction::RemoveImageTag => {
			let image_id = ImageId(read_vli(&mut *reader)?);
			let tag_id = TagId(read_vli(&mut *reader)?);

			LogEntry {
				timestamp,
				user_id,
				action: match action {
					LogAction::AddImageTag => LogActionWithData::AddImageTag(image_id, tag_id),
					LogAction::RemoveImageTag => LogActionWithData::RemoveImageTag(image_id, tag_id),
					_ => unreachable!(),
				},
			}
		},
		LogAction::AddAttribute => {
			let image_id = ImageId(read_vli(&mut *reader)?);
			let attribute_key_id = AttributeKeyId(read_vli(&mut *reader)?);
			let attribute_value_id = AttributeValueId(read_vli(&mut *reader)?);

			LogEntry {
				timestamp,
				user_id,
				action: LogActionWithData::AddAttribute(image_id, attribute_key_id, attribute_value_id),
			}
		},
		LogAction::RemoveAttribute => {
			let image_id = ImageId(read_vli(&mut *reader)?);
			let attribute_key_id = AttributeKeyId(read_vli(&mut *reader)?);
			let attribute_value_id = AttributeValueId(read_vli(&mut *reader)?);

			LogEntry {
				timestamp,
				user_id,
				action: LogActionWithData::RemoveAttribute(image_id, attribute_key_id, attribute_value_id),
			}
		},
	};

	let calculated_checksum = (reader.digest() & 0xff) as u8;
	let stored_checksum = reader.read_u8()?;

	if calculated_checksum != stored_checksum {
		return Err(DatabaseError::ChecksumMismatch {
			expected: calculated_checksum as u64,
			actual: stored_checksum as u64,
		});
	}

	Ok(log)
}


/// Append a log entry to the log file
pub(crate) fn append_to_log_file(logs_file: &mut File, log: &LogEntry) -> Result<(), DatabaseError> {
	// Read the current log count
	logs_file.seek(std::io::SeekFrom::Start(0))?;
	let log_count = match logs_file.read_u64::<LittleEndian>() {
		Ok(count) => count,
		Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
			// File might be empty, let's check
			if logs_file.seek(std::io::SeekFrom::End(0))? != 0 {
				// File is not empty, but we couldn't read the count
				return Err(e.into());
			}

			// File is empty, write the intial count
			logs_file.seek(std::io::SeekFrom::Start(0))?;
			logs_file.write_u64::<LittleEndian>(0)?;
			0
		},
		Err(e) => return Err(e.into()),
	};

	// Write the log entry
	logs_file.seek(std::io::SeekFrom::End(0))?;
	log.write_to(logs_file)?;

	// Update the log count
	logs_file.seek(std::io::SeekFrom::Start(0))?;
	logs_file.write_u64::<LittleEndian>(log_count + 1)?;

	// Durably sync
	logs_file.sync_all()?;

	Ok(())
}


pub(crate) struct LogsReader<R> {
	reader: HasherReader<R>,
	pub(crate) remaining_logs: u64, // Only an estimate
}

/// Read a log file
/// Returns a reader that yields log entries
pub(crate) fn read_log_file<R: Read + Seek>(mut reader: R) -> Result<LogsReader<R>, DatabaseError> {
	// Read the count (may be inaccurate due to corruption, but is only used for allocation and the progress bar)
	reader.seek(std::io::SeekFrom::Start(0))?;
	let log_count = match reader.read_u64::<LittleEndian>() {
		Ok(log_count) => log_count,
		Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
			// Empty file
			// Seek to the end so read_log_entry will return EOF
			reader.seek(std::io::SeekFrom::End(0))?;
			0
		},
		Err(e) => return Err(e.into()),
	};

	Ok(LogsReader {
		reader: HasherReader::new(reader, Xxh3::new()),
		remaining_logs: log_count,
	})
}

impl<R: Read> Iterator for LogsReader<R> {
	type Item = Result<LogEntry, DatabaseError>;

	fn next(&mut self) -> Option<Self::Item> {
		match read_log_entry(&mut self.reader) {
			Ok(log) => {
				self.remaining_logs -= 1;
				Some(Ok(log))
			},
			// EOF
			// This may either be because we've correctly reached the end of the file, or because an entry was partially written
			// Both cases are correct
			Err(DatabaseError::IoError(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => None,
			Err(e) => Some(Err(e)),
		}
	}

	fn size_hint(&self) -> (usize, Option<usize>) {
		(self.remaining_logs as usize, Some(self.remaining_logs as usize))
	}
}


// =============================================
// Unit Tests
// =============================================

#[cfg(test)]
mod tests {
	use super::*;
	use std::io::{BufReader, Cursor};

	/// Test writing variable-length integers
	#[test]
	fn test_write_vli() {
		let mut buf = Vec::new();
		write_vli(&mut buf, 0xfc).unwrap();
		assert_eq!(buf, vec![0xfc]);

		buf.clear();
		write_vli(&mut buf, 0xfd).unwrap();
		assert_eq!(buf, vec![0xfd, 0xfd, 0x00]);

		buf.clear();
		write_vli(&mut buf, 0xffff).unwrap();
		assert_eq!(buf, vec![0xfd, 0xff, 0xff]);

		buf.clear();
		write_vli(&mut buf, 0x1_0000).unwrap();
		assert_eq!(buf, vec![0xfe, 0x00, 0x00, 0x01, 0x00]);

		buf.clear();
		write_vli(&mut buf, 0xffff_ffff).unwrap();
		assert_eq!(buf, vec![0xfe, 0xff, 0xff, 0xff, 0xff]);

		buf.clear();
		write_vli(&mut buf, 0x1_0000_0000).unwrap();
		assert_eq!(buf, vec![0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]);
	}

	/// Test reading variable-length integers
	#[test]
	fn test_read_vli() {
		let data = vec![0xfc];
		let mut cursor = Cursor::new(data);
		let value = read_vli(&mut cursor).unwrap();
		assert_eq!(value, 0xfc);

		let data = vec![0xfd, 0xfd, 0x00];
		let mut cursor = Cursor::new(data);
		let value = read_vli(&mut cursor).unwrap();
		assert_eq!(value, 0x00fd);

		let data = vec![0xfe, 0xff, 0xff, 0x00, 0x00];
		let mut cursor = Cursor::new(data);
		let value = read_vli(&mut cursor).unwrap();
		assert_eq!(value, 0x0000_ffff);

		let data = vec![0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00];
		let mut cursor = Cursor::new(data);
		let value = read_vli(&mut cursor).unwrap();
		assert_eq!(value, 0x0000_0000_ffff_ffff);
	}

	/// Test writing and reading strings
	#[test]
	fn test_write_and_read_string() {
		let s = "Hello, world!";
		let mut buf = Vec::new();
		write_string(&mut buf, s).unwrap();

		let mut cursor = Cursor::new(buf);
		let s_read = read_string(&mut cursor).unwrap();
		assert_eq!(s_read, s);
	}

	/// Test LogEntry serialization and checksum
	#[test]
	fn test_log_entry_to_bytes() {
		let log_entry = LogEntry {
			timestamp: 1637625600,
			user_id: UserId(42),
			action: LogActionWithData::AddTag("test_tag".to_string()),
		};

		// Serialize the LogEntry
		let mut bytes = Vec::new();
		log_entry.write_to(&mut bytes).unwrap();

		// Verify the checksum
		let calculated_checksum = (xxh3_64(&bytes[..bytes.len() - 1]) & 0xff) as u8;
		let stored_checksum = bytes[bytes.len() - 1];
		assert_eq!(calculated_checksum, stored_checksum);

		// Read back the data
		let mut cursor = Cursor::new(&bytes[..bytes.len() - 1]);
		let timestamp = cursor.read_u64::<LittleEndian>().unwrap();
		assert_eq!(timestamp, 1637625600);

		let user_id = read_vli(&mut cursor).unwrap();
		assert_eq!(user_id, 42);

		let action_u8 = cursor.read_u8().unwrap();
		assert_eq!(action_u8, 0); // AddTag

		let tag = read_string(&mut cursor).unwrap();
		assert_eq!(tag, "test_tag");

		// Make sure the cursor is at the end
		assert_eq!(cursor.position(), bytes.len() as u64 - 1);
	}

	/// Test reading a LogEntry from bytes
	#[test]
	fn test_read_log_entry() {
		// Prepare a LogEntry and serialize it
		let log_entry = LogEntry {
			timestamp: 1637625600,
			user_id: UserId(42),
			action: LogActionWithData::AddTag("test_tag".to_string()),
		};

		let mut bytes = Vec::new();
		log_entry.write_to(&mut bytes).unwrap();

		// Read the LogEntry back
		let mut cursor = Cursor::new(bytes.clone());
		let mut reader = HasherReader::new(&mut cursor, Xxh3::new());
		let read_entry = read_log_entry(&mut reader).unwrap();

		assert_eq!(read_entry.timestamp, log_entry.timestamp);
		assert_eq!(read_entry.user_id.0, log_entry.user_id.0);

		match read_entry.action {
			LogActionWithData::AddTag(tag) => {
				assert_eq!(tag, "test_tag");
			},
			_ => panic!("Expected AddTag action"),
		}
	}

	/// Test HasherReader functionality
	#[test]
	fn test_hasher_reader() {
		let data = b"test data";
		let cursor = Cursor::new(data);
		let mut hasher_reader = HasherReader::new(cursor, Xxh3::new());

		let mut buf = Vec::new();
		hasher_reader.read_to_end(&mut buf).unwrap();

		assert_eq!(buf, data);

		let digest = hasher_reader.digest();
		let expected_digest = xxh3_64(data);

		assert_eq!(digest, expected_digest);
	}

	/// Test combined write and read of variable-length integers
	#[test]
	fn test_write_and_read_vli() {
		let mut buf = Vec::new();
		write_vli(&mut buf, 0xfc).unwrap();
		write_vli(&mut buf, 0x1_0000_0000).unwrap();
		write_vli(&mut buf, 0xffff).unwrap();

		let mut cursor = Cursor::new(buf);

		let v1 = read_vli(&mut cursor).unwrap();
		assert_eq!(v1, 0xfc);

		let v2 = read_vli(&mut cursor).unwrap();
		assert_eq!(v2, 0x1_0000_0000);

		let v3 = read_vli(&mut cursor).unwrap();
		assert_eq!(v3, 0xffff);
	}

	/// Test corruption detection in the string table
	#[test]
	fn test_string_table_corruption() {
		let mut file = tempfile::tempfile().unwrap();

		append_to_strings_table(&mut file, "test").unwrap();

		// Corrupt the file
		file.seek(std::io::SeekFrom::End(-4)).unwrap();
		file.write_u32::<LittleEndian>(0xdeadbeef).unwrap();

		// Read the string table
		let result = read_string_table(BufReader::new(file), false);
		assert!(result.is_err());
	}

	/// Test corruption detection in the image hash table
	#[test]
	fn test_hash_table_corruption() {
		let mut file = tempfile::tempfile().unwrap();

		append_to_hash_table(&mut file, &ImageHash([0u8; 32])).unwrap();

		// Corrupt the file
		file.seek(std::io::SeekFrom::End(-7)).unwrap();
		file.write_u64::<LittleEndian>(0xdeadbeef).unwrap();

		// Read the hash table
		let result = read_hash_table(BufReader::new(file), false);
		assert!(result.is_err());
	}

	/// Test corruption detection in the users table
	#[test]
	fn test_users_table_corruption() {
		let mut file = tempfile::tempfile().unwrap();

		let mut users = IndexMapTyped::new();
		users.insert("test".to_string(), UserEntry::new(HashedLoginKey([0u8; 32]), "test".to_string()).unwrap());
		write_users_table(&mut file, &users).unwrap();

		// Corrupt the file
		file.seek(std::io::SeekFrom::End(-2)).unwrap();
		file.write_u16::<LittleEndian>(0xbeef).unwrap();

		// Read the users table
		let result = read_users_table(BufReader::new(file), false);
		assert!(result.is_err());
	}

	/// Test corruption detection in the user tokens table
	#[test]
	fn test_user_tokens_table_corruption() {
		let mut file = tempfile::tempfile().unwrap();

		append_to_user_tokens_table(&mut file, UserToken([0u8; 32]), UserId(42)).unwrap();

		// Corrupt the file
		file.seek(std::io::SeekFrom::End(-5)).unwrap();
		file.write_u32::<LittleEndian>(0xdeadbeef).unwrap();

		// Read the user tokens table
		let result = read_user_tokens_table(&mut file, false);
		assert!(result.is_err());
	}

	/// Test corruption detection in the log file
	#[test]
	fn test_log_file_corruption() {
		let mut file = tempfile::tempfile().unwrap();

		let log_entry = LogEntry {
			timestamp: 1637625600,
			user_id: UserId(42),
			action: LogActionWithData::AddTag("test_tag".to_string()),
		};

		append_to_log_file(&mut file, &log_entry).unwrap();

		// Corrupt the file
		file.seek(std::io::SeekFrom::End(-1)).unwrap();
		file.write_u8(0xde).unwrap();

		// Read the log file
		let mut reader = read_log_file(BufReader::new(file)).unwrap();
		assert_eq!(reader.size_hint(), (1, Some(1)));

		match reader.next().unwrap() {
			Err(DatabaseError::ChecksumMismatch { expected: _, actual }) => {
				assert_eq!(actual, 0xde);
			},
			e => panic!("Expected checksum mismatch error, got {:?}", e),
		}
	}

	/// Test appending to and reading from the strings table
	#[test]
	fn test_append_and_read_strings_table() {
		let mut file = tempfile::tempfile().unwrap();

		// Append strings to the strings table
		append_to_strings_table(&mut file, "test1").unwrap();
		append_to_strings_table(&mut file, "test2").unwrap();
		append_to_strings_table(&mut file, "test3").unwrap();

		// Read the strings table
		let table = read_string_table(&mut file, false).unwrap();

		// Verify the contents
		assert_eq!(table.len(), 3);
		assert_eq!(table.get_by_id_full(0u64.into()).unwrap().0, "test1");
		assert_eq!(table.get_by_id_full(1u64.into()).unwrap().0, "test2");
		assert_eq!(table.get_by_id_full(2u64.into()).unwrap().0, "test3");
	}

	/// Test appending to and reading from the image hash table
	#[test]
	fn test_append_and_read_hash_table() {
		let mut file = tempfile::tempfile().unwrap();

		// Create image hashes
		let hash1 = ImageHash([1u8; 32]);
		let hash2 = ImageHash([2u8; 32]);
		let hash3 = ImageHash([3u8; 32]);

		// Append hashes to the hash table
		append_to_hash_table(&mut file, &hash1).unwrap();
		append_to_hash_table(&mut file, &hash2).unwrap();
		append_to_hash_table(&mut file, &hash3).unwrap();

		// Read the hash table
		let table = read_hash_table(&mut file, false).unwrap();

		// Verify the contents
		assert_eq!(table.len(), 3);
		assert_eq!(*table.get_by_id_full(0u64.into()).unwrap().0, hash1);
		assert_eq!(*table.get_by_id_full(1u64.into()).unwrap().0, hash2);
		assert_eq!(*table.get_by_id_full(2u64.into()).unwrap().0, hash3);
	}

	/// Test writing to and reading from the users table
	#[test]
	fn test_write_and_read_users_table() {
		let mut file = tempfile::tempfile().unwrap();

		let mut users = IndexMapTyped::new();
		users.insert("user1".to_string(), UserEntry::new(HashedLoginKey([1u8; 32]), "scope1".to_string()).unwrap());
		users.insert("user2".to_string(), UserEntry::new(HashedLoginKey([2u8; 32]), "scope2".to_string()).unwrap());
		users.insert("user3".to_string(), UserEntry::new(HashedLoginKey([3u8; 32]), "scope3".to_string()).unwrap());

		// Write the users table
		write_users_table(&mut file, &users).unwrap();

		// Read the users table
		let read_users = read_users_table(&mut file, false).unwrap();

		// Verify the contents
		assert_eq!(read_users.len(), 3);
		assert_eq!(read_users.get_by_id_full(UserId(0)).unwrap().0, "user1");
		assert_eq!(read_users.get_by_id_full(UserId(1)).unwrap().0, "user2");
		assert_eq!(read_users.get_by_id_full(UserId(2)).unwrap().0, "user3");
	}

	/// Test appending to and reading from the user tokens table
	#[test]
	fn test_append_and_read_user_tokens_table() {
		let mut file = tempfile::tempfile().unwrap();

		let token1 = UserToken([1u8; 32]);
		let token2 = UserToken([2u8; 32]);
		let token3 = UserToken([3u8; 32]);

		// Append user tokens to the table
		append_to_user_tokens_table(&mut file, token1, UserId(1)).unwrap();
		append_to_user_tokens_table(&mut file, token2, UserId(2)).unwrap();
		append_to_user_tokens_table(&mut file, token3, UserId(3)).unwrap();

		// Read the user tokens table
		let tokens = read_user_tokens_table(&mut file, false).unwrap();

		// Verify the contents
		assert_eq!(tokens.len(), 3);
		assert_eq!(tokens.get(&token1), Some(&UserId(1)));
		assert_eq!(tokens.get(&token2), Some(&UserId(2)));
		assert_eq!(tokens.get(&token3), Some(&UserId(3)));
	}

	/// Test appending to and reading from the log file
	#[test]
	fn test_append_and_read_log_file() {
		let mut file = tempfile::tempfile().unwrap();

		let log_entry1 = LogEntry {
			timestamp: 1637625600,
			user_id: UserId(1),
			action: LogActionWithData::AddTag("tag1".to_string()),
		};
		let log_entry2 = LogEntry {
			timestamp: 1637625601,
			user_id: UserId(2),
			action: LogActionWithData::AddImage(ImageId(1)),
		};
		let log_entry3 = LogEntry {
			timestamp: 1637625602,
			user_id: UserId(3),
			action: LogActionWithData::AddImageTag(ImageId(1), TagId(1)),
		};

		// Append log entries to the log file
		append_to_log_file(&mut file, &log_entry1).unwrap();
		append_to_log_file(&mut file, &log_entry2).unwrap();
		append_to_log_file(&mut file, &log_entry3).unwrap();

		// Read the log file
		let logs_reader = read_log_file(&mut file).unwrap();
		let logs: Vec<_> = logs_reader.collect::<Result<_, _>>().unwrap();

		// Verify the contents
		assert_eq!(logs.len(), 3);
		assert_eq!(logs[0].timestamp, log_entry1.timestamp);
		assert_eq!(logs[1].timestamp, log_entry2.timestamp);
		assert_eq!(logs[2].timestamp, log_entry3.timestamp);
	}

	/// Test updating the users table with update_users_table function
	#[test]
	fn test_update_users_table() {
		let temp_dir = tempfile::tempdir().unwrap();
		let mut file = File::create(temp_dir.path().join("users_table")).unwrap();

		let mut users = IndexMapTyped::new();
		users.insert("user1".to_string(), UserEntry::new(HashedLoginKey([1u8; 32]), "scope1".to_string()).unwrap());

		// Write the initial users table
		write_users_table(&mut file, &users).unwrap();

		// Update the users table
		users.insert("user2".to_string(), UserEntry::new(HashedLoginKey([2u8; 32]), "scope2".to_string()).unwrap());

		let file = update_users_table(&temp_dir.path().join("users_table"), &users).unwrap();

		// Read back the users table
		let read_users = read_users_table(&file, false).unwrap();

		// Verify the contents
		assert_eq!(read_users.len(), 2);
		assert!(read_users.contains_key("user1"));
		assert!(read_users.contains_key("user2"));
	}

	/// Test LogsReader iterator with multiple log entries
	#[test]
	fn test_logs_reader_iterator() {
		let mut file = tempfile::tempfile().unwrap();

		let log_entries = vec![
			LogEntry {
				timestamp: 1637625600,
				user_id: UserId(1),
				action: LogActionWithData::AddTag("tag1".to_string()),
			},
			LogEntry {
				timestamp: 1637625601,
				user_id: UserId(2),
				action: LogActionWithData::AddImage(ImageId(1)),
			},
			LogEntry {
				timestamp: 1637625602,
				user_id: UserId(3),
				action: LogActionWithData::AddImageTag(ImageId(1), TagId(1)),
			},
			LogEntry {
				timestamp: 1637625603,
				user_id: UserId(4),
				action: LogActionWithData::AddAttribute(ImageId(1), AttributeKeyId(1), AttributeValueId(1)),
			},
		];

		// Append log entries to the log file
		for log_entry in &log_entries {
			append_to_log_file(&mut file, log_entry).unwrap();
		}

		// Read the log file
		let logs_reader = read_log_file(&mut file).unwrap();
		let logs: Vec<_> = logs_reader.collect::<Result<_, _>>().unwrap();

		// Verify the contents
		assert_eq!(logs.len(), log_entries.len());
		for (read_log, expected_log) in logs.iter().zip(log_entries.iter()) {
			assert_eq!(read_log.timestamp, expected_log.timestamp);
			assert_eq!(read_log.user_id, expected_log.user_id);
			// For simplicity, compare the action as strings
			assert_eq!(format!("{:?}", read_log.action), format!("{:?}", expected_log.action));
		}
	}

	/// Test reading from empty files
	#[test]
	fn test_read_empty_files() {
		// Empty strings table
		let file = tempfile::tempfile().unwrap();
		let table = read_string_table(&file, false).unwrap();
		assert!(table.is_empty());

		// Empty hash table
		let file = tempfile::tempfile().unwrap();
		let table = read_hash_table(&file, false).unwrap();
		assert!(table.is_empty());

		// Empty users table
		let file = tempfile::tempfile().unwrap();
		let table = read_users_table(&file, false).unwrap();
		assert!(table.is_empty());

		// Empty user tokens table
		let file = tempfile::tempfile().unwrap();
		let table = read_user_tokens_table(&file, false).unwrap();
		assert!(table.is_empty());

		// Empty log file
		let file = tempfile::tempfile().unwrap();
		let logs_reader = read_log_file(&file).unwrap();
		let logs: Vec<_> = logs_reader.collect::<Result<_, _>>().unwrap();
		assert!(logs.is_empty());
	}

	/// Test reading from files with incorrect counts
	#[test]
	fn test_incorrect_counts() {
		// Strings table with incorrect count
		let mut file = tempfile::tempfile().unwrap();
		file.write_u64::<LittleEndian>(10).unwrap(); // Incorrect count
		let mut buffer = Vec::new();
		write_string(&mut buffer, "test").unwrap();
		let checksum = (xxh3_64(&buffer) & 0xffff) as u16;
		file.write_all(&buffer).unwrap();
		file.write_u16::<LittleEndian>(checksum).unwrap();
		file.seek(std::io::SeekFrom::Start(0)).unwrap();
		let table = read_string_table(&mut file, false).unwrap();
		assert_eq!(table.len(), 1);

		// Hash table with incorrect length
		let mut file = tempfile::tempfile().unwrap();
		file.write_all(&[0u8; 32]).unwrap(); // Hash
		file.write_u8((xxh3_64(&[0u8; 32]) & 0xff) as u8).unwrap(); // Checksum
		file.write_all(b"test").unwrap(); // Simulate a partial write
									// No more data, but length suggests more entries
		file.seek(std::io::SeekFrom::Start(0)).unwrap();
		let table = read_hash_table(&mut file, false).unwrap();
		assert_eq!(table.len(), 1);
	}

	/// Test handling of invalid data in files
	#[test]
	fn test_invalid_data_handling() {
		// Invalid action code in log file
		let mut file = tempfile::tempfile().unwrap();
		file.write_u64::<LittleEndian>(1).unwrap(); // Count
		file.write_i64::<LittleEndian>(1637625600).unwrap(); // Timestamp
		write_vli(&mut file, 1).unwrap(); // User ID
		file.write_u8(255).unwrap(); // Invalid action code
		let checksum = (xxh3_64(&[0u8; 0]) & 0xff) as u8;
		file.write_u8(checksum).unwrap();
		let logs_reader = read_log_file(&mut file).unwrap();
		let logs: Result<Vec<_>, DatabaseError> = logs_reader.collect::<Result<_, _>>();
		assert!(logs.is_err());
	}

	/// Test handling of partial writes (e.g., due to crash during write)
	#[test]
	fn test_partial_writes_handling() {
		// Simulate partial write in strings table
		let mut file = tempfile::tempfile().unwrap();

		append_to_strings_table(&mut file, "test1").unwrap();
		append_to_strings_table(&mut file, "test2").unwrap();
		append_to_strings_table(&mut file, "test3").unwrap();

		// Simulate crash
		let len = file.seek(std::io::SeekFrom::End(0)).unwrap();
		file.set_len(len - 1).unwrap();

		// Read the strings table
		let table = read_string_table(&mut file, false).unwrap();
		assert_eq!(table.len(), 2);
	}

	/// Test invalidating user tokens
	#[test]
	fn test_invalidate_user_tokens() {
		let mut file = tempfile::tempfile().unwrap();

		let token = UserToken([1u8; 32]);
		let user_id = UserId(42);

		// Append user token
		append_to_user_tokens_table(&mut file, token, user_id).unwrap();

		// Invalidate the token by writing BAD_USER_ID
		append_to_user_tokens_table(&mut file, token, BAD_USER_ID).unwrap();

		// Read the user tokens table
		let tokens = read_user_tokens_table(&mut file, false).unwrap();

		// Verify that the token has been removed
		assert!(tokens.get(&token).is_none());
	}

	/// Test adding and removing attributes in log entries
	#[test]
	fn test_log_entry_add_remove_attribute() {
		let mut file = tempfile::tempfile().unwrap();

		let add_attribute_entry = LogEntry {
			timestamp: 1637625600,
			user_id: UserId(1),
			action: LogActionWithData::AddAttribute(ImageId(1), AttributeKeyId(1), AttributeValueId(1)),
		};

		let remove_attribute_entry = LogEntry {
			timestamp: 1637625601,
			user_id: UserId(1),
			action: LogActionWithData::RemoveAttribute(ImageId(1), AttributeKeyId(1), AttributeValueId(1)),
		};

		// Append log entries
		append_to_log_file(&mut file, &add_attribute_entry).unwrap();
		append_to_log_file(&mut file, &remove_attribute_entry).unwrap();

		// Read the log file
		let logs_reader = read_log_file(&mut file).unwrap();
		let logs: Vec<_> = logs_reader.collect::<Result<_, _>>().unwrap();

		// Verify the contents
		assert_eq!(logs.len(), 2);
		assert_eq!(format!("{:?}", logs[0].action), format!("{:?}", add_attribute_entry.action));
		assert_eq!(format!("{:?}", logs[1].action), format!("{:?}", remove_attribute_entry.action));
	}
}
