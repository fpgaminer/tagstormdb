use byteorder::WriteBytesExt;
use tagstormdb::binary_format::{write_string, write_vli};

pub struct SearchProtocolWriter<W: std::io::Write> {
	writer: W,
}

impl<W: std::io::Write> SearchProtocolWriter<W> {
	pub fn new(writer: W) -> Self {
		SearchProtocolWriter { writer }
	}

	pub fn write_header(&mut self, has_ids: bool, has_hashes: bool, has_tags: bool, has_attributes: bool) -> std::io::Result<()> {
		// Helps identify the format
		self.writer.write_all(b"TMS")?;

		// Bitflags for the presence of ids, hashes, tags, and attributes
		let flags = (has_ids as u8) << 3 | (has_hashes as u8) << 2 | (has_tags as u8) << 1 | (has_attributes as u8);
		self.writer.write_u8(flags)?;

		// Header is 4 bytes: "TMS" + 1 byte for flags, so it's aligned to 4 bytes

		Ok(())
	}

	pub fn write_id(&mut self, id: u32) -> std::io::Result<()> {
		// Writen as a fixed sized u32 so that if only ids are present, they can be read as a simple u32 array without parsing or copying
		self.writer.write_u32::<byteorder::LittleEndian>(id)
	}

	pub fn write_hash(&mut self, hash: &[u8; 32]) -> std::io::Result<()> {
		self.writer.write_all(hash)
	}

	pub fn write_tags<I>(&mut self, tags: I) -> std::io::Result<()>
	where
		I: ExactSizeIterator<Item = (u32, u32)>,
	{
		// Write the number of tags
		write_vli(&mut self.writer, tags.len() as u64)?;

		// Write each tag as a pair of u32 values (tag_id, tag_value)
		for (tag_id, tag_value) in tags {
			write_vli(&mut self.writer, tag_id as u64)?;
			write_vli(&mut self.writer, tag_value as u64)?;
		}

		Ok(())
	}

	pub fn write_attributes<'a, I, J>(&mut self, attributes: I) -> std::io::Result<()>
	where
		I: ExactSizeIterator<Item = (&'a String, J)>,
		J: ExactSizeIterator<Item = (&'a String, u32)>,
	{
		// Write the number of attributes
		write_vli(&mut self.writer, attributes.len() as u64)?;

		for (attr_key, attr_values) in attributes {
			// Write the attribute key
			write_string(&mut self.writer, attr_key)?;

			// Write the number of values for this attribute
			write_vli(&mut self.writer, attr_values.len() as u64)?;

			// Write each value as a pair of (value, user_id)
			for (value, id) in attr_values {
				write_string(&mut self.writer, value)?;
				write_vli(&mut self.writer, id as u64)?;
			}
		}

		Ok(())
	}
}
