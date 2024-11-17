use std::io::Write;
use byteorder::{LittleEndian, WriteBytesExt};
use serde::{ser, Serialize};

use crate::{binary_format::{write_string, write_vli}, small_db_errors::SerializeError};


pub struct Serializer {
	output: Vec<u8>,
}


type SerializerResult<T> = Result<T, SerializeError>;


pub fn to_bytes<T>(value: &T) -> Result<Vec<u8>, SerializeError>
where
    T: Serialize,
{
	let mut serializer = Serializer {
		output: Vec::new(),
	};
	value.serialize(&mut serializer)?;
	Ok(serializer.output)
}

impl<'a> ser::Serializer for &'a mut Serializer {
	type Ok = ();
	type Error = SerializeError;

	type SerializeSeq = Self;
	type SerializeTuple = Self;
	type SerializeTupleStruct = Self;
	type SerializeTupleVariant = Self;
	type SerializeMap = Self;
	type SerializeStruct = Self;
	type SerializeStructVariant = Self;

	fn serialize_bool(self, v: bool) -> SerializerResult<()> {
		self.output.write_u8(if v { 1 } else { 0 }).unwrap();
		Ok(())
	}

	fn serialize_i8(self, v: i8) -> SerializerResult<()> {
		self.output.write_i8(v).unwrap();
		Ok(())
	}

	fn serialize_i16(self, v: i16) -> SerializerResult<()> {
		self.output.write_i16::<LittleEndian>(v).unwrap();
		Ok(())
	}

	fn serialize_i32(self, v: i32) -> SerializerResult<()> {
		self.output.write_i32::<LittleEndian>(v).unwrap();
		Ok(())
	}

	fn serialize_i64(self, v: i64) -> SerializerResult<()> {
		self.output.write_i64::<LittleEndian>(v).unwrap();
		Ok(())
	}

	fn serialize_u8(self, v: u8) -> SerializerResult<()> {
		self.output.write_u8(v).unwrap();
		Ok(())
	}

	fn serialize_u16(self, v: u16) -> SerializerResult<()> {
		self.output.write_u16::<LittleEndian>(v).unwrap();
		Ok(())
	}

	fn serialize_u32(self, v: u32) -> SerializerResult<()> {
		self.output.write_u32::<LittleEndian>(v).unwrap();
		Ok(())
	}

	fn serialize_u64(self, v: u64) -> SerializerResult<()> {
		self.output.write_u64::<LittleEndian>(v).unwrap();
		Ok(())
	}

	fn serialize_f32(self, v: f32) -> SerializerResult<()> {
		self.output.write_f32::<LittleEndian>(v).unwrap();
		Ok(())
	}

	fn serialize_f64(self, v: f64) -> SerializerResult<()> {
		self.output.write_f64::<LittleEndian>(v).unwrap();
		Ok(())
	}

	fn serialize_char(self, v: char) -> SerializerResult<()> {
		self.serialize_str(&v.to_string())
	}

	fn serialize_str(self, v: &str) -> SerializerResult<()> {
		write_string(&mut self.output, v).unwrap();
		Ok(())
	}

	fn serialize_bytes(self, v: &[u8]) -> SerializerResult<()> {
		write_vli(&mut self.output, v.len() as u64).unwrap();
		self.output.write_all(v).unwrap();
		Ok(())
	}

	fn serialize_none(self) -> SerializerResult<()> {
		self.output.write_u8(0).unwrap();
		Ok(())
	}

	fn serialize_some<T>(self, value: &T) -> SerializerResult<()>
	where
		T: ?Sized + Serialize,
	{
		self.output.write_u8(1).unwrap();
		value.serialize(self)
	}

	fn serialize_unit(self) -> SerializerResult<()> {
		Ok(())
	}

	fn serialize_unit_struct(self, _name: &'static str) -> SerializerResult<()> {
		self.serialize_unit()
	}

	fn serialize_unit_variant(
		self,
		_name: &'static str,
		variant_index: u32,
		_variant: &'static str,
	) -> SerializerResult<()> {
		write_vli(&mut self.output, variant_index as u64).unwrap();
		Ok(())
	}

	fn serialize_newtype_struct<T>(
		self,
		_name: &'static str,
		value: &T,
	) -> SerializerResult<()>
	where
		T: ?Sized + Serialize,
	{
		value.serialize(self)
	}

	fn serialize_newtype_variant<T>(
		self,
		_name: &'static str,
		variant_index: u32,
		_variant: &'static str,
		value: &T,
	) -> SerializerResult<()>
	where
		T: ?Sized + Serialize,
	{
		write_vli(&mut self.output, variant_index as u64).unwrap();
		value.serialize(self)
	}

	fn serialize_seq(self, len: Option<usize>) -> SerializerResult<Self::SerializeSeq> {
		write_vli(&mut self.output, len.unwrap() as u64).unwrap();
		Ok(self)
	}

	fn serialize_tuple(self, _len: usize) -> SerializerResult<Self::SerializeTuple> {
		Ok(self)
	}

	fn serialize_tuple_struct(
		self,
		_name: &'static str,
		len: usize,
	) -> SerializerResult<Self::SerializeTupleStruct> {
		self.serialize_seq(Some(len))
	}

	fn serialize_tuple_variant(
		self,
		_name: &'static str,
		variant_index: u32,
		_variant: &'static str,
		_len: usize,
	) -> SerializerResult<Self::SerializeTupleVariant> {
		write_vli(&mut self.output, variant_index as u64).unwrap();
		Ok(self)
	}

	fn serialize_map(self, _len: Option<usize>) -> SerializerResult<Self::SerializeMap> {
		unimplemented!()
	}

	fn serialize_struct(
		self,
		_name: &'static str,
		_len: usize,
	) -> SerializerResult<Self::SerializeStruct> {
		Ok(self)
	}

	fn serialize_struct_variant(
		self,
		_name: &'static str,
		_variant_index: u32,
		_variant: &'static str,
		_len: usize,
	) -> SerializerResult<Self::SerializeStructVariant> {
		unimplemented!()
	}
}


impl<'a> ser::SerializeSeq for &'a mut Serializer {
	type Ok = ();
	type Error = SerializeError;

	fn serialize_element<T>(&mut self, value: &T) -> SerializerResult<()>
	where
		T: ?Sized + Serialize,
	{
		value.serialize(&mut **self)
	}

	fn end(self) -> SerializerResult<()> {
		Ok(())
	}
}

impl<'a> ser::SerializeTuple for &'a mut Serializer {
	type Ok = ();
	type Error = SerializeError;

	fn serialize_element<T>(&mut self, value: &T) -> SerializerResult<()>
	where
		T: ?Sized + Serialize,
	{
		value.serialize(&mut **self)
	}

	fn end(self) -> SerializerResult<()> {
		Ok(())
	}
}

impl<'a> ser::SerializeTupleStruct for &'a mut Serializer {
	type Ok = ();
	type Error = SerializeError;

	fn serialize_field<T>(&mut self, value: &T) -> SerializerResult<()>
	where
		T: ?Sized + Serialize,
	{
		value.serialize(&mut **self)
	}

	fn end(self) -> SerializerResult<()> {
		Ok(())
	}
}

impl<'a> ser::SerializeTupleVariant for &'a mut Serializer {
	type Ok = ();
	type Error = SerializeError;

	fn serialize_field<T>(&mut self, value: &T) -> SerializerResult<()>
	where
		T: ?Sized + Serialize,
	{
		value.serialize(&mut **self)
	}

	fn end(self) -> SerializerResult<()> {
		Ok(())
	}
}

impl<'a> ser::SerializeMap for &'a mut Serializer {
	type Ok = ();
	type Error = SerializeError;

	fn serialize_key<T>(&mut self, _key: &T) -> SerializerResult<()>
	where
		T: ?Sized + Serialize,
	{
		unimplemented!()
	}

	fn serialize_value<T>(&mut self, _value: &T) -> SerializerResult<()>
	where
		T: ?Sized + Serialize,
	{
		unimplemented!()
	}

	fn end(self) -> SerializerResult<()> {
		unimplemented!()
	}
}

impl<'a> ser::SerializeStruct for &'a mut Serializer {
	type Ok = ();
	type Error = SerializeError;

	fn serialize_field<T>(&mut self, _key: &'static str, value: &T) -> SerializerResult<()>
	where
		T: ?Sized + Serialize,
	{
		value.serialize(&mut **self)
	}

	fn end(self) -> SerializerResult<()> {
		Ok(())
	}
}

impl<'a> ser::SerializeStructVariant for &'a mut Serializer {
	type Ok = ();
	type Error = SerializeError;

	fn serialize_field<T>(&mut self, _key: &'static str, value: &T) -> SerializerResult<()>
	where
		T: ?Sized + Serialize,
	{
		value.serialize(&mut **self)
	}

	fn end(self) -> SerializerResult<()> {
		Ok(())
	}
}