use futures::TryStreamExt;
/// This program reads the older Postgres database and writes it to our new binary format.
use indexmap::IndexSet;
use indicatif::{ProgressBar, ProgressStyle};
use sqlx::{
	postgres::{PgConnectOptions, PgPoolOptions},
	FromRow,
};
use std::{
	collections::HashMap,
	fs::File,
	io::{BufWriter, Seek, Write},
	path::Path,
};
use tagstormdb::ImageHash;
use xxhash_rust::xxh3::xxh3_64;


#[derive(Debug, FromRow)]
struct LogEntry {
	#[allow(dead_code)]
	id: i64,
	timestamp: chrono::NaiveDateTime,
	user_id: i64,
	action: String,
	image_hash: Option<Vec<u8>>,
	tag: Option<String>,
	attribute_key: Option<String>,
	attribute_value: Option<String>,
}


enum LogAction {
	AddTag,
	RemoveTag,
	AddImage,
	RemoveImage,
	AddImageTag,
	RemoveImageTag,
	AddAttribute,
	RemoveAttribute,
	Caption,
}

impl LogAction {
	fn from_str(s: &str) -> Option<Self> {
		match s {
			"add_tag" => Some(Self::AddTag),
			"remove_tag" => Some(Self::RemoveTag),
			"add_image" => Some(Self::AddImage),
			"remove_image" => Some(Self::RemoveImage),
			"add_image_tag" => Some(Self::AddImageTag),
			"remove_image_tag" => Some(Self::RemoveImageTag),
			"add_attribute" => Some(Self::AddAttribute),
			"remove_attribute" => Some(Self::RemoveAttribute),
			"caption" => Some(Self::Caption),
			_ => None,
		}
	}

	fn to_u8(&self) -> u8 {
		match self {
			Self::AddTag => 0,
			Self::RemoveTag => 1,
			Self::AddImage => 2,
			Self::RemoveImage => 3,
			Self::AddImageTag => 4,
			Self::RemoveImageTag => 5,
			Self::AddAttribute => 6,
			Self::RemoveAttribute => 7,
			Self::Caption => 8,
		}
	}

	fn write<W: Write>(&self, writer: &mut W) -> Result<(), Box<dyn std::error::Error>> {
		writer.write_all(&[self.to_u8()])?;
		Ok(())
	}
}


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
	let db_path = Path::new("/home/night/tag-machine/pg-socket");
	let options = PgConnectOptions::new()
		.host(db_path.to_str().unwrap())
		.username("postgres")
		.password("password")
		.database("postgres");

	let pool = PgPoolOptions::new().max_connections(5).connect_with(options).await?;

	let log_file = File::create("logs.bin")?;
	let image_hashes_file = File::create("image_hashes.bin")?;
	let string_table_file = File::create("string_table.bin")?;

	let pb = ProgressBar::new(244343515);
	pb.set_style(
		ProgressStyle::default_bar()
			.template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
			.unwrap()
			.progress_chars("#>-"),
	);

	let mut logs = sqlx::query_as::<_, LogEntry>("SELECT * FROM logs ORDER BY timestamp ASC").fetch(&pool);

	let mut log_writer = LogWriter::new(log_file, image_hashes_file, string_table_file);

	while let Some(log) = logs.try_next().await? {
		log_writer.write_log_entry(log)?;
		pb.inc(1);
	}

	pb.finish_with_message("done");

	log_writer.finish()?;

	Ok(())
}


struct LogWriter {
	log_writer: BufWriter<File>,
	hash_table_writer: BufWriter<File>,
	string_table_writer: BufWriter<File>,

	image_hash_to_id: IndexSet<ImageHash>,
	string_to_id: IndexSet<String>,
	tag_to_id: IndexSet<String>,
	caption_state: HashMap<u64, u64>,
	n_logs: u64,
	buffer: Vec<u8>,
}

impl LogWriter {
	fn new(log_file: File, hash_table_file: File, string_table_file: File) -> Self {
		let mut log_writer = BufWriter::new(log_file);
		log_writer.write_all(&0u64.to_le_bytes()).unwrap();

		Self {
			log_writer,
			hash_table_writer: BufWriter::new(hash_table_file),
			string_table_writer: BufWriter::new(string_table_file),
			image_hash_to_id: IndexSet::new(),
			string_to_id: IndexSet::new(),
			tag_to_id: IndexSet::new(),
			caption_state: HashMap::new(),
			n_logs: 0,
			buffer: Vec::new(),
		}
	}

	fn write_log_entry(&mut self, log: LogEntry) -> Result<(), Box<dyn std::error::Error>> {
		self.n_logs += 1;

		// Reset the hasher
		self.buffer.clear();

		// Write timestamp as milliseconds since UNIX epoch (i64)
		let millis = log.timestamp.and_utc().timestamp_millis();
		self.buffer.write_all(&millis.to_le_bytes())?;

		// Write user_id (i64)
		write_vli(&mut self.buffer, log.user_id as u64)?;

		let action = LogAction::from_str(&log.action).unwrap();

		let image_hash = log.image_hash.map(|v| ImageHash(v.as_slice().try_into().unwrap()));
		let image_id = image_hash.map(|hash| self.image_hash_to_id.insert_full(hash).0 as u64);
		let attribute_key_id = log.attribute_key.map(|key| self.string_to_id.insert_full(key).0 as u64);
		let attribute_value_id = log.attribute_value.map(|value| self.string_to_id.insert_full(value).0 as u64);
		let tag_id = log.tag.as_ref().map(|tag| self.tag_to_id.insert_full(tag.clone()).0 as u64);

		match action {
			LogAction::AddTag => {
				action.write(&mut self.buffer)?;
				write_string(&mut self.buffer, log.tag.as_ref().unwrap())?;
			},
			LogAction::RemoveTag => {
				action.write(&mut self.buffer)?;
				write_vli(&mut self.buffer, tag_id.unwrap())?;
			},
			LogAction::AddImage | LogAction::RemoveImage => {
				action.write(&mut self.buffer)?;
				write_vli(&mut self.buffer, image_id.unwrap())?;
			},
			LogAction::AddImageTag | LogAction::RemoveImageTag => {
				action.write(&mut self.buffer)?;
				write_vli(&mut self.buffer, image_id.unwrap())?;
				write_vli(&mut self.buffer, tag_id.unwrap())?;
			},
			LogAction::AddAttribute => {
				action.write(&mut self.buffer)?;
				write_vli(&mut self.buffer, image_id.unwrap())?;
				write_vli(&mut self.buffer, attribute_key_id.unwrap())?;
				write_vli(&mut self.buffer, attribute_value_id.unwrap())?;
			},
			LogAction::RemoveAttribute => {
				action.write(&mut self.buffer)?;
				write_vli(&mut self.buffer, image_id.unwrap())?;
				write_vli(&mut self.buffer, attribute_key_id.unwrap())?;
				write_vli(&mut self.buffer, attribute_value_id.unwrap())?;
			},
			LogAction::Caption => {
				let image_id = image_id.unwrap();
				let key_id = self.string_to_id.insert_full("caption".to_string()).0 as u64;

				// Recode as an attribute
				if let Some(caption) = self.caption_state.remove(&image_id) {
					// Write remove_attribute
					LogAction::RemoveAttribute.write(&mut self.buffer)?;
					write_vli(&mut self.buffer, image_id)?;
					write_vli(&mut self.buffer, key_id)?;
					write_vli(&mut self.buffer, caption)?;

					self.write_log_record()?;

					// Restart writing the log
					self.buffer.clear();
					self.buffer.write_all(&millis.to_le_bytes())?;
					write_vli(&mut self.buffer, log.user_id as u64)?;
					self.n_logs += 1;
				}

				// Write add_attribute
				LogAction::AddAttribute.write(&mut self.buffer)?;
				write_vli(&mut self.buffer, image_id)?;
				write_vli(&mut self.buffer, key_id)?;
				write_vli(&mut self.buffer, attribute_value_id.unwrap())?;

				self.caption_state.insert(image_id, attribute_value_id.unwrap());
			},
		}

		self.write_log_record()?;

		Ok(())
	}

	fn write_log_record(&mut self) -> Result<(), Box<dyn std::error::Error>> {
		let checksum = (xxh3_64(&self.buffer) & 0xff) as u8;
		self.log_writer.write_all(&self.buffer)?;
		self.log_writer.write_all(&checksum.to_le_bytes())?;
		Ok(())
	}

	fn write_image_table(&mut self) -> Result<(), Box<dyn std::error::Error>> {
		//self.hash_table_writer.write_all(&(self.image_hash_to_id.len() as u64).to_le_bytes())?;

		for hash in &self.image_hash_to_id {
			self.hash_table_writer.write_all(&hash.0)?;
			let checksum = (xxh3_64(&hash.0) & 0xff) as u8;
			self.hash_table_writer.write_all(&checksum.to_le_bytes())?;
		}

		Ok(())
	}

	fn write_string_table(&mut self) -> Result<(), Box<dyn std::error::Error>> {
		self.string_table_writer.write_all(&(self.string_to_id.len() as u64).to_le_bytes())?;

		for string in &self.string_to_id {
			self.buffer.clear();
			write_string(&mut self.buffer, string)?;
			let checksum = (xxh3_64(&self.buffer) & 0xffff) as u16;
			self.string_table_writer.write_all(&self.buffer)?;
			self.string_table_writer.write_all(&checksum.to_le_bytes())?;
		}


		Ok(())
	}

	fn finish(mut self) -> Result<(), Box<dyn std::error::Error>> {
		// Write the tables
		self.write_image_table()?;
		self.write_string_table()?;

		// Write the log length
		self.log_writer.seek(std::io::SeekFrom::Start(0))?;
		self.log_writer.write_all(&self.n_logs.to_le_bytes())?;

		Ok(())
	}
}


fn write_string<W: Write>(writer: &mut W, s: &str) -> Result<(), Box<dyn std::error::Error>> {
	let bytes = s.as_bytes();
	let len = bytes.len() as u64;
	write_vli(writer, len)?;
	writer.write_all(bytes)?;
	Ok(())
}


fn write_vli<W: Write>(writer: &mut W, n: u64) -> Result<(), Box<dyn std::error::Error>> {
	if n <= 0xfc {
		writer.write_all(&[n as u8])?;
	} else if n <= 0xffff {
		writer.write_all(&[0xfd])?;
		writer.write_all(&(n as u16).to_le_bytes())?;
	} else if n <= 0xffffffff {
		writer.write_all(&[0xfe])?;
		writer.write_all(&(n as u32).to_le_bytes())?;
	} else {
		writer.write_all(&[0xff])?;
		writer.write_all(&n.to_le_bytes())?;
	}

	Ok(())
}
