/// We need some database capabilities that are a bit more flexible than the append-only tables of the main database logic.
/// This module implements a very simple database that is NOT append-only.
/// Used for the user table, user tokens, work queues, etc.
/// 
/// Format:
/// - Each record is prefixed by a 4-byte length&active field, where the least significant bit is the active flag and the rest is the length of the record
/// - The record data follows, serialized into a simple binary format and possibly padded
/// - The record ends with a 2-byte checksum of the record data (not including the length&active field)
/// - The database file is a sequence of these records
/// 
/// The database is not append-only, so records can be updated and deleted. Deleted records are marked as inactive and their space can be reused by insert or update.
/// On insert, empty space is found by searching for inactive records of the same or larger size. If no space is found, the record is appended to the end of the file.
/// A WAL is written, to handle crashes. The WAL is replayed on startup to restore consistency.
/// An update is like a delete followed by an insert, condensed into a single operation. The WAL contains both the deletion and the insertion.
use std::{backtrace::Backtrace, collections::BTreeMap, fmt, fs::{File, OpenOptions}, io::{BufReader, Read, Seek, SeekFrom, Write}, path::{Path, PathBuf}};


use byteorder::{LittleEndian, WriteBytesExt, ReadBytesExt};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use xxhash_rust::xxh3::xxh3_64;

use crate::{small_db_deserializer::from_bytes, small_db_errors::DbError, small_db_serializer::to_bytes};


pub struct SmallDb {
	/// Map of inactive records, indexed by their length
	inactive_map: BTreeMap<u32, Vec<u64>>,

	/// The file handle to the database
	pub file: File,

	/// Parent directory
	parent_dir: PathBuf,

	#[doc(hidden)]
	_internal_use_danger_do_not_use_wal_failure_test: bool,
}


#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash, Debug)]
pub struct RowId(pub u64);

impl fmt::Display for RowId {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "RowId({})", self.0)
	}
}


pub fn debug_db<'a, T: Deserialize<'a> + fmt::Debug>(file: &mut File) {
	file.seek(SeekFrom::Start(0)).unwrap();
	let mut r = BufReader::new(file);
	let mut buffer = Vec::new();

	loop {
		// Read length and active state
		let start_position = r.stream_position().unwrap();
		let (active, len) = match r.read_u32::<LittleEndian>() {
			Ok(len) => ((len & 1) != 0, len >> 1),
			Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => break,
			Err(err) => {
				println!("Error reading record at position {}: {}", start_position, err);
				return;
			},
		};

		// All records must at least have space for the checksum
		if len < 2 {
			println!("Record too short at position {}: {}", start_position, len);
			return;
		}

		// Sanity check, might need to be adjusted
		if len > (32*1024*1024) {
			println!("Record too long at position {}: {}", start_position, len);
			return;
		}

		// Read the record
		buffer.resize(len as usize, 0);
		match r.read_exact(&mut buffer) {
			Ok(_) => {},
			Err(err) => {
				println!("Error reading record at position {}: {}", start_position, err);
				return;
			},
		}

		// Verify the checksum
		let stored_checksum = u16::from_le_bytes([buffer[len as usize - 2], buffer[len as usize - 1]]);
		let computed_checksum = (xxh3_64(&buffer[..len as usize - 2]) & 0xffff) as u16;

		let value = if active && stored_checksum == computed_checksum {
			let record: T = from_bytes(&buffer[..len as usize - 2]).unwrap();
			Some(record)
		} else {
			None
		};

		println!("Record at position {}: active={}, len={}, stored_checksum={}, computed_checksum={}, value={:?}", start_position, active, len, stored_checksum, computed_checksum, value);
	}
}


fn read_db<'a, T: Deserialize<'a>>(file: &mut File, mut callback: impl FnMut(RowId, T)) -> Result<BTreeMap<u32, Vec<u64>>, DbError> {
	file.seek(SeekFrom::Start(0)).unwrap();
	let mut r = BufReader::new(file);
	let mut buffer = Vec::new();
	let mut inactive_map = BTreeMap::new();

	loop {
		// Read length and active state
		let start_position = r.stream_position()?;
		let (active, len) = match r.read_u32::<LittleEndian>() {
			Ok(len) => ((len & 1) != 0, len >> 1),
			Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => break,
			Err(err) => return Err(err.into()),
		};

		// All records must at least have space for the checksum
		if len < 2 {
			return Err(DbError::CorruptDatabase("Record too short".to_string(), Backtrace::capture()));
		}

		if !active {
			// Skip the record
			r.seek(SeekFrom::Current(len as i64))?;

			// Update the inactive map
			let inactive_entry = inactive_map.entry(len).or_insert_with(Vec::new);
			inactive_entry.push(start_position);

			continue;
		}

		// Read the record
		buffer.resize(len as usize, 0);
		r.read_exact(&mut buffer)?;

		// Verify the checksum
		let stored_checksum = u16::from_le_bytes([buffer[len as usize - 2], buffer[len as usize - 1]]);
		let computed_checksum = (xxh3_64(&buffer[..len as usize - 2]) & 0xffff) as u16;

		if stored_checksum != computed_checksum {
			return Err(DbError::CorruptDatabase(format!("Checksum mismatch at position {}: stored={}, computed={}", start_position, stored_checksum, computed_checksum), Backtrace::capture()));
		}

		// Deserialize the record
		let record: T = from_bytes(&buffer[..len as usize - 2])?;
		callback(RowId(start_position), record);
	}

	Ok(inactive_map)
}


impl SmallDb {
	pub fn open<T: DeserializeOwned>(path: &Path, callback: impl FnMut(RowId, T)) -> Result<SmallDb, DbError> {
		let parent_dir = path.parent().ok_or_else(|| DbError::IoError(std::io::Error::new(std::io::ErrorKind::NotFound, "Parent directory not found"), Backtrace::capture()))?;
		let mut file = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(path)?;

		// Replay the WAL
		SmallDb::play_wal(&mut file, parent_dir)?;

		// Read the database
		Ok(SmallDb {
			inactive_map: read_db(&mut file, callback)?,
			file,
			parent_dir: parent_dir.to_path_buf(),
			_internal_use_danger_do_not_use_wal_failure_test: false,
		})
	}

	/// If a WAL exists, replays it to restore consistency
	fn play_wal(file: &mut File, wal_dir: &Path) -> Result<(), DbError> {
		let mut buffer = Vec::new();
		let wal_path = wal_dir.join("wal");

		// Read the WAL
		{
			let mut wal = match File::open(&wal_path) {
				Ok(f) => f,
				Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
				Err(err) => return Err(err.into()),
			};

			log::info!("Replaying WAL");
			wal.read_to_end(&mut buffer)?;
		}

		if buffer.len() < 2 {
			// WAL was not completely written
			log::warn!("WAL was not completely written, any changes not synced were lost");

			// Delete
			std::fs::remove_file(&wal_path)?;

			return Ok(());
		}

		let stored_checksum = u16::from_le_bytes([buffer[buffer.len() - 2], buffer[buffer.len() - 1]]);
		let computed_checksum = (xxh3_64(&buffer[..buffer.len() - 2]) & 0xffff) as u16;

		if stored_checksum != computed_checksum {
			// WAL was likely not completely written
			log::warn!("WAL checksum mismatch, any changes not synced were lost");

			// Delete
			std::fs::remove_file(&wal_path)?;

			return Ok(());
		}

		// Replay the WAL
		let mut reader = &buffer[..buffer.len() - 2];

		while !reader.is_empty() {
			if reader.len() < 12 {
				panic!("WAL is corrupt despite checksum verification");
			}

			let record_position = u64::from_le_bytes(reader[..8].try_into().unwrap());
			let record_len = u32::from_le_bytes(reader[8..12].try_into().unwrap());
			reader = &reader[12..];

			if reader.len() < record_len as usize {
				panic!("WAL is corrupt despite checksum verification");
			}

			let data = &reader[..record_len as usize];
			reader = &reader[record_len as usize..];

			// Write the record
			log::debug!("Replaying WAL record at position {}: len={}", record_position, record_len);
			file.seek(SeekFrom::Start(record_position))?;
			file.write_all(data)?;
		}

		// Sync the database
		file.sync_all()?;

		// First, truncate the WAL and sync it, so we don't replay it again in case there's a crash after this point
		let wal = OpenOptions::new().write(true).truncate(true).open(&wal_path)?;
		wal.sync_all()?;
		drop(wal);

		// Delete the WAL
		std::fs::remove_file(&wal_path)?;

		Ok(())
	}

	fn find_free_space(&mut self, len: u32) -> (u64, u32) {
		// Find all inactive records that are at least as large as the new record
		for (record_len, positions) in self.inactive_map.range_mut(len..) {
			if let Some(position) = positions.pop() {
				return (position, *record_len);
			}
		}

		// No free space found, return the end of the file
		(self.file.seek(SeekFrom::End(0)).unwrap(), len)
	}

	pub fn insert_row<T: Serialize>(&mut self, record: &T) -> Result<RowId, DbError> {
		let wal_path = self.parent_dir.join("wal");

		// Serialize the record
		let record_bytes = to_bytes(record).unwrap();
		assert!((record_bytes.len() + 2) <= 0x7FFF_FFFF);

		// Find somewhere to put it that is at least as large as the serialized data plus the checksum
		let (record_position, record_len) = self.find_free_space(record_bytes.len() as u32 + 2);

		// Build our WAL buffer: write position, write length, record length with active bit, record data, padding, checksum, WAL checksum
		let buffer_len = 12 + 4 + record_len as usize + 2;
		let mut buffer = vec![0; buffer_len];

		buffer[..8].copy_from_slice(&record_position.to_le_bytes());
		buffer[8..12].copy_from_slice(&(record_len + 4).to_le_bytes());
		buffer[12..16].copy_from_slice(&((record_len << 1) | 1).to_le_bytes());
		buffer[16..16 + record_bytes.len()].copy_from_slice(&record_bytes);
		
		let checksum = (xxh3_64(&buffer[16..16 + (record_len - 2) as usize]) & 0xffff) as u16;
		buffer[buffer_len - 4..buffer_len - 2].copy_from_slice(&checksum.to_le_bytes());

		// WAL checksum
		let checksum = (xxh3_64(&buffer[..buffer.len() - 2]) & 0xffff) as u16;
		buffer[buffer_len - 2..].copy_from_slice(&checksum.to_le_bytes());

		// Write the WAL and sync it
		let mut wal = OpenOptions::new().create(true).write(true).truncate(true).open(&wal_path)?;
		wal.write_all(&buffer)?;
		wal.sync_all()?;

		// Internal testing: simulate power failure
		if self._internal_use_danger_do_not_use_wal_failure_test {
			return Err(DbError::IoError(std::io::Error::new(std::io::ErrorKind::Other, "WAL failure test"), Backtrace::capture()));
		}

		// Write the record and sync it
		self.file.seek(SeekFrom::Start(record_position))?;
		self.file.write_all(&buffer[12..16 + record_len as usize])?;
		self.file.sync_all()?;

		// Truncate the WAL and sync it
		wal.set_len(0)?;
		wal.sync_all()?;
		drop(wal);

		// Remove the WAL
		std::fs::remove_file(&wal_path)?;

		Ok(RowId(record_position))
	}

	/// Delete a row from the database
	pub fn delete_row(&mut self, position: RowId) -> Result<(), DbError> {
		// Read the record length
		self.file.seek(SeekFrom::Start(position.0))?;
		let b = self.file.read_u8()?;

		// Mask out the active bit
		let new_b = b & !1;

		// Write to the database
		// Record deletions are atomic, because they only require a single byte write which cannot cross a page boundary
		self.file.seek(SeekFrom::Start(position.0))?;
		self.file.write_u8(new_b)?;

		// Sync the database
		self.file.sync_all()?;

		Ok(())
	}

	/// Update a row in the database
	pub fn update_row<T: Serialize>(&mut self, position: RowId, record: &T) -> Result<RowId, DbError> {
		let wal_path = self.parent_dir.join("wal");

		// Serialize the new record
		let record_bytes = to_bytes(record).unwrap();
		assert!((record_bytes.len() + 2) <= 0x7FFF_FFFF);

		// Read the old record length
		self.file.seek(SeekFrom::Start(position.0))?;
		let mut old_record_len_bytes = [0u8; 4];
		self.file.read_exact(&mut old_record_len_bytes)?; 
		let old_record_len = u32::from_le_bytes(old_record_len_bytes) >> 1;

		// Check if the new record fits in the old space
		let (old_record, new_record_position, new_record_len) = if old_record_len < (record_bytes.len() as u32 + 2) {
			// Find somewhere to put the new record
			let (record_position, record_len) = self.find_free_space(record_bytes.len() as u32 + 2);

			// Prepare the byte for deleting the old record
			let old_record_byte = old_record_len_bytes[0] & !1;

			(Some((position.0, old_record_byte)), record_position, record_len)
		} else {
			(None, position.0, old_record_len)
		};

		// Build our WAL buffer: write position, write length, record length with active bit, record data, padding, checksum
		// Potentially two entries: one for the new record, one for the old record
		let buffer_len = 12 + 4 + new_record_len as usize + old_record.map(|_| 13).unwrap_or(0) + 2;
		let mut buffer = vec![0; buffer_len];

		buffer[..8].copy_from_slice(&new_record_position.to_le_bytes());
		buffer[8..12].copy_from_slice(&(new_record_len + 4).to_le_bytes());
		buffer[12..16].copy_from_slice(&((new_record_len << 1) | 1).to_le_bytes());
		buffer[16..16 + record_bytes.len()].copy_from_slice(&record_bytes);

		let checksum = (xxh3_64(&buffer[16..16+(new_record_len - 2) as usize]) & 0xffff) as u16;
		buffer[16 + new_record_len as usize - 2..16 + new_record_len as usize].copy_from_slice(&checksum.to_le_bytes());

		// If we have an old record, add its deletion to the WAL
		if let Some((old_record_position, old_record_byte)) = old_record {
			buffer[buffer_len - 15..buffer_len - 7].copy_from_slice(&old_record_position.to_le_bytes());
			buffer[buffer_len - 7..buffer_len - 3].copy_from_slice(&(1u32.to_le_bytes()));
			buffer[buffer_len - 3] = old_record_byte;
		}

		// WAL checksum
		let checksum = (xxh3_64(&buffer[..buffer.len() - 2]) & 0xffff) as u16;
		buffer[buffer_len - 2..].copy_from_slice(&checksum.to_le_bytes());

		// Write the WAL and sync it
		let mut wal = OpenOptions::new().create(true).write(true).truncate(true).open(&wal_path)?;
		wal.write_all(&buffer)?;
		wal.sync_all()?;

		// Internal testing: simulate power failure
		if self._internal_use_danger_do_not_use_wal_failure_test {
			return Err(DbError::IoError(std::io::Error::new(std::io::ErrorKind::Other, "WAL failure test"), Backtrace::capture()));
		}

		// Write the new record
		self.file.seek(SeekFrom::Start(new_record_position))?;
		self.file.write_all(&buffer[12..16 + new_record_len as usize])?;

		// Delete the old record if necessary
		if let Some((old_record_position, old_record_byte)) = old_record {
			self.file.seek(SeekFrom::Start(old_record_position))?;
			self.file.write_u8(old_record_byte)?;
		}

		// Sync the database
		self.file.sync_all()?;

		// Truncate the WAL and sync it
		wal.set_len(0)?;
		wal.sync_all()?;
		drop(wal);

		// Remove the WAL
		std::fs::remove_file(&wal_path)?;

		// Update the inactive map if necessary
		if let Some((old_record_position, _)) = old_record {
			let inactive_entry = self.inactive_map.entry(old_record_len).or_default();
			inactive_entry.push(old_record_position);
		}

		Ok(RowId(new_record_position))
	}
}


#[cfg(test)]
mod tests {
    use std::{collections::HashMap, fs::OpenOptions, io::{Read, Seek, SeekFrom, Write}};

    use rand::{seq::SliceRandom, Rng};
    use serde::{Deserialize, Serialize};

    use crate::{small_db::{debug_db, SmallDb}, small_db_errors::DbError};

	#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
	enum TestDataEnum {
		A(i16),
		B(String),
	}

	#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
	struct TestData {
		a: u32,
		b: String,
		c: Vec<u8>,
		d: TestDataEnum,
	}

	fn random_test_data() -> TestData {
		let mut rng = rand::thread_rng();
		TestData {
			a: rng.gen(),
			b: random_string(),
			c: (0..rng.gen_range(0..100)).map(|_| rng.gen()).collect(),
			d: match rng.gen_range(0..2) {
				0 => TestDataEnum::A(rng.gen()),
				1 => TestDataEnum::B(random_string()),
				_ => unreachable!(),
			},
		}
	}

	fn random_string() -> String {
		let mut rng = rand::thread_rng();
		let len = rng.gen_range(1..=100);
		let mut s = String::with_capacity(len);
		for _ in 0..len {
			//s.push(rng.gen_range(b'a'..=b'z') as char);
			s.push(rng.gen())
		}
		s
	}

	/// Test SmallDb by inserting, updating, and deleting random rows
	#[test]
	fn random_database_test() {
		let tmpdir = tempfile::tempdir().unwrap();
		let mut expected = HashMap::new();

		// Randomly manipulate the database
		{
			let mut db = SmallDb::open(&tmpdir.path().join("test.db"), |_, _: TestData| {
				unreachable!();
			}).unwrap();
			let mut rng = rand::thread_rng();

			for _ in 0..1024 {
				match rng.gen_range(0..4) {
					// Insert
					0..2 => {
						let row = random_test_data();
						let rowid = db.insert_row(&row).unwrap();
						expected.insert(rowid, row);
					},
					// Update
					2..3 if expected.len() > 0 => {
						let rowid = **expected.keys().collect::<Vec<_>>().choose(&mut rng).unwrap();
						let new_row = random_test_data();
						let new_rowid = db.update_row(rowid, &new_row).unwrap();
						expected.remove(&rowid);
						expected.insert(new_rowid, new_row);
					},
					// Delete
					3..4 if expected.len() > 0 => {
						let rowid = **expected.keys().collect::<Vec<_>>().choose(&mut rng).unwrap();
						db.delete_row(rowid).unwrap();
						expected.remove(&rowid);
					},
					n => assert!(n < 4),
				}
			}

			debug_db::<TestData>(&mut db.file);
			println!("");
		}

		// Reopen the database and check that all rows are as expected
		let _ = SmallDb::open(&tmpdir.path().join("test.db"), |row_id, row: TestData| {
			let expected_row = expected.remove(&row_id).unwrap();
			assert_eq!(row, expected_row);
		}).unwrap();

		// Check that all rows were visited
		assert_eq!(expected.len(), 0);
	}

	/// Test SmallDb's WAL recovery
	#[test]
	fn wal_recovery_test() {
		let tmpdir = tempfile::tempdir().unwrap();
		let mut expected = HashMap::new();

		// Write a test with the last insert failing
		let failed_row = {
			let mut db = SmallDb::open(&tmpdir.path().join("test.db"), |_, _: TestData| {
				unreachable!();
			}).unwrap();

			let row = random_test_data();
			let rowid1 = db.insert_row(&row).unwrap();
			expected.insert(rowid1, row);

			let row = random_test_data();
			let rowid2 = db.insert_row(&row).unwrap();
			expected.insert(rowid2, row);

			let row = random_test_data();
			let rowid3 = db.insert_row(&row).unwrap();
			expected.insert(rowid3, row);

			db.delete_row(rowid1).unwrap();
			expected.remove(&rowid1);

			let row = random_test_data();
			let rowid4 = db.update_row(rowid2, &row).unwrap();
			expected.remove(&rowid2);
			expected.insert(rowid4, row);

			// Fail the last insert
			db._internal_use_danger_do_not_use_wal_failure_test = true;
			let row = random_test_data();
			assert!(db.insert_row(&row).is_err());
			row
		};

		// The WAL file should exist and have data
		let wal_path = tmpdir.path().join("wal");
		assert!(wal_path.exists());
		let wal_file = std::fs::read(&wal_path).unwrap();
		assert!(!wal_file.is_empty());

		// Reopen the database and check that all rows are as expected, including the failed row
		let mut checked_rows = expected.clone();
		let mut failed_row_found = false;
		{
			let _ = SmallDb::open(&tmpdir.path().join("test.db"), |row_id, row: TestData| {
				if row == failed_row && !failed_row_found {
					expected.insert(row_id, failed_row.clone());
					failed_row_found = true;
					return;
				}

				let expected_row = checked_rows.remove(&row_id).unwrap();
				assert_eq!(row, expected_row);
			}).unwrap();
		}

		// Check that all rows were visited
		assert_eq!(checked_rows.len(), 0);
		assert!(failed_row_found);

		// The WAL file should be gone
		assert!(!wal_path.exists());

		// Second test, this time with a failure during an update
		let failed_row = {
			let mut db = SmallDb::open(&tmpdir.path().join("test.db"), |rowid, _: TestData| {
				println!("reading: rowid: {}:", rowid);
			}).unwrap();

			let row = random_test_data();
			let rowid1 = db.insert_row(&row).unwrap();
			expected.insert(rowid1, row);

			// Fail the update
			db._internal_use_danger_do_not_use_wal_failure_test = true;
			let row = random_test_data();
			assert!(db.update_row(rowid1, &row).is_err());
			expected.remove(&rowid1);

			row
		};

		// The WAL file should exist and have data
		let wal_path = tmpdir.path().join("wal");
		assert!(wal_path.exists());
		let wal_file = std::fs::read(&wal_path).unwrap();
		assert!(!wal_file.is_empty());

		// Reopen the database and check that all rows are as expected, including the failed row
		let mut failed_row_found = false;
		{
			let _ = SmallDb::open(&tmpdir.path().join("test.db"), |row_id, row: TestData| {
				if row == failed_row && !failed_row_found {
					failed_row_found = true;
					return;
				}

				let expected_row = expected.remove(&row_id).expect(format!("Row not found: {}", row_id).as_str());
				assert_eq!(row, expected_row);
			}).unwrap();
		}

		// Check that all rows were visited
		assert_eq!(expected.len(), 0);
		assert!(failed_row_found);

		// The WAL file should be gone
		assert!(!wal_path.exists());
	}

	/// Test that the database detects corrupted records
	#[test]
	fn test_corrupted_record_detection() {
		#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
		struct TestDataSimple {
			data: Vec<u8>,
		}

		let tmpdir = tempfile::tempdir().unwrap();

		// Insert a record
		{
			let mut db = SmallDb::open(&tmpdir.path().join("test.db"), |_, _: TestDataSimple| {
				unreachable!();
			})
			.unwrap();

			let data = vec![1u8, 2, 3, 4, 5];
			let record = TestDataSimple { data: data.clone() };
			let _rowid = db.insert_row(&record).unwrap();
		}

		// Corrupt the database file by flipping some bits
		{
			let db_path = tmpdir.path().join("test.db");
			let mut file = OpenOptions::new().read(true).write(true).open(&db_path).unwrap();
			let mut contents = Vec::new();
			file.read_to_end(&mut contents).unwrap();
			// Flip some bits in the record data
			contents[10] ^= 0xFF;
			
			// Write back the corrupted data
			file.seek(SeekFrom::Start(0)).unwrap();
			file.write_all(&contents).unwrap();
			file.sync_all().unwrap();
		}

		// Attempt to reopen the database and check that an error is returned
		let result = SmallDb::open(&tmpdir.path().join("test.db"), |_, _: TestDataSimple| {
			panic!("Should not have read any records");
		});

		match result {
			Ok(_) => panic!("Expected an error"),
			Err(DbError::CorruptDatabase(_, _)) => {}
			Err(err) => panic!("Unexpected error: {:?}", err),
		}
	}

	/// Test inserting and reading empty vectors
	#[test]
	fn test_insert_empty_record() {
		#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
		struct TestDataSimple {
			data: Vec<u8>,
		}

		let tmpdir = tempfile::tempdir().unwrap();
		let mut expected = HashMap::new();

		let mut db = SmallDb::open(&tmpdir.path().join("test.db"), |_, _: TestDataSimple| {
			unreachable!();
		})
		.unwrap();

		// Insert an empty vector
		let record = TestDataSimple { data: Vec::new() };
		let rowid = db.insert_row(&record).unwrap();
		expected.insert(rowid, record.clone());

		// Reopen the database and verify the data
		let mut actual = HashMap::new();
		let _ = SmallDb::open(&tmpdir.path().join("test.db"), |row_id, row: TestDataSimple| {
			assert!(!actual.contains_key(&row_id));
			actual.insert(row_id, row);
		})
		.unwrap();
		assert_eq!(actual, expected);
	}
}