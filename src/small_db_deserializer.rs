use std::io::Read;

use serde::de::value::U32Deserializer;
use serde::Deserialize;
use serde::de::{
    self, DeserializeSeed, EnumAccess, IntoDeserializer, SeqAccess,
    VariantAccess, Visitor,
};
use byteorder::ReadBytesExt;

use crate::binary_format::read_vli;
use crate::small_db_errors::DeserializeError;



type Result<T> = std::result::Result<T, DeserializeError>;


pub struct Deserializer<R> {
	input: R,
}

impl<R> Deserializer<R> {
    pub fn from_reader(input: R) -> Self {
        Deserializer { input }
    }
}

pub fn from_bytes<'a, T>(s: &[u8]) -> Result<T>
where
    T: Deserialize<'a>,
{
	let mut cursor = std::io::Cursor::new(s);
    let deserializer = Deserializer::from_reader(&mut cursor);
    let t = T::deserialize(deserializer)?;
	Ok(t)
}

#[allow(dead_code)]
pub fn from_reader<'a, T, R>(mut r: R) -> Result<T>
where
	T: Deserialize<'a>,
	R: Read,
{
	let deserializer = Deserializer::from_reader(&mut r);
	let t = T::deserialize(deserializer)?;
	Ok(t)
}


impl<'de, 'a, R: Read> de::Deserializer<'de> for Deserializer<R> {
    type Error = DeserializeError;

    fn deserialize_any<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
		unimplemented!()
    }

    fn deserialize_bool<V>(mut self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_bool(self.input.read_u8()? != 0)
    }

    fn deserialize_i8<V>(mut self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_i8(self.input.read_i8()?)
    }

    fn deserialize_i16<V>(mut self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_i16(self.input.read_i16::<byteorder::LittleEndian>()?)
    }

    fn deserialize_i32<V>(mut self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_i32(self.input.read_i32::<byteorder::LittleEndian>()?)
    }

    fn deserialize_i64<V>(mut self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_i64(self.input.read_i64::<byteorder::LittleEndian>()?)
    }

    fn deserialize_u8<V>(mut self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_u8(self.input.read_u8()?)
    }

    fn deserialize_u16<V>(mut self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_u16(self.input.read_u16::<byteorder::LittleEndian>()?)
    }

    fn deserialize_u32<V>(mut self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_u32(self.input.read_u32::<byteorder::LittleEndian>()?)
    }

    fn deserialize_u64<V>(mut self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_u64(self.input.read_u64::<byteorder::LittleEndian>()?)
    }

    fn deserialize_f32<V>(mut self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_f32(self.input.read_f32::<byteorder::LittleEndian>()?)
    }

    fn deserialize_f64<V>(mut self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_f64(self.input.read_f64::<byteorder::LittleEndian>()?)
    }

    fn deserialize_char<V>(mut self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
		let s = read_string(&mut self.input)?;
		if s.len() == 1 {
			visitor.visit_char(s.chars().next().unwrap())
		} else {
			Err(DeserializeError::Custom("Expected a single character".to_string()))
		}
    }

    fn deserialize_str<V>(mut self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
		visitor.visit_str(&read_string(&mut self.input)?)
    }

    fn deserialize_string<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.deserialize_str(visitor)
    }

    fn deserialize_bytes<V>(mut self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
		let len = read_vli(&mut self.input)?;
		let mut buf = vec![0; len as usize];
		self.input.read_exact(&mut buf)?;
		visitor.visit_bytes(&buf)
    }

    fn deserialize_byte_buf<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
		self.deserialize_bytes(visitor)
    }

    fn deserialize_option<V>(mut self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        if self.input.read_u8()? == 0 {
            visitor.visit_none()
        } else {
            visitor.visit_some(self)
        }
    }

    fn deserialize_unit<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
		visitor.visit_unit()
    }

    // Unit struct means a named value containing no data.
    fn deserialize_unit_struct<V>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.deserialize_unit(visitor)
    }

    fn deserialize_newtype_struct<V>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_seq<V>(mut self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
		let len = read_vli(&mut self.input)? as usize;
		self.deserialize_tuple(len, visitor)
    }

    fn deserialize_tuple<V>(mut self, len: usize, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
		// https://github.com/bincode-org/bincode/blob/980f63812707def85bf51c67956ebf313eb74f32/src/features/serde/de_owned.rs#L293
        struct Access<'a, R> {
			de: &'a mut Deserializer<R>,
			len: usize,
		}

		impl<'de, 'a, R: Read> SeqAccess<'de> for Access<'a, R> {
            type Error = DeserializeError;

            fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>>
            where
                T: DeserializeSeed<'de>,
            {
                if self.len > 0 {
                    self.len -= 1;
					let value = DeserializeSeed::deserialize(seed, Deserializer {
						input: &mut self.de.input,
					})?;
					Ok(Some(value))
                } else {
                    Ok(None)
                }
            }

            fn size_hint(&self) -> Option<usize> {
                Some(self.len)
            }
        }

        visitor.visit_seq(Access {
            de: &mut self,
            len,
        })
    }

    fn deserialize_tuple_struct<V>(
        self,
        _name: &'static str,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.deserialize_seq(visitor)
    }

    fn deserialize_map<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
		unimplemented!()
    }

    fn deserialize_struct<V>(
        self,
        _name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.deserialize_tuple(fields.len(), visitor)
    }

    fn deserialize_enum<V>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_enum(self)
    }

    fn deserialize_identifier<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }

    fn deserialize_ignored_any<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }
}


impl<'de, R: Read> EnumAccess<'de> for Deserializer<R> {
    type Error = DeserializeError;
    type Variant = Self;

    fn variant_seed<V>(mut self, seed: V) -> Result<(V::Value, Self::Variant)>
    where
        V: DeserializeSeed<'de>,
    {
		let idx = read_vli(&mut self.input)? as u32;
        let val = seed.deserialize::<U32Deserializer<DeserializeError>>(idx.into_deserializer())?;
        Ok((val, self))
    }
}

impl<'de, R: Read> VariantAccess<'de> for Deserializer<R> {
    type Error = DeserializeError;

    fn unit_variant(self) -> Result<()> {
        Ok(())
    }

    fn newtype_variant_seed<T>(self, seed: T) -> Result<T::Value>
    where
        T: DeserializeSeed<'de>,
    {
        DeserializeSeed::deserialize(seed, self)
    }

    fn tuple_variant<V>(self, len: usize, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        serde::de::Deserializer::deserialize_tuple(self, len, visitor)
    }

    fn struct_variant<V>(
        self,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        serde::de::Deserializer::deserialize_tuple(self, fields.len(), visitor)
    }
}


fn read_string<R: Read>(mut input: R) -> Result<String> {
	let len = read_vli(&mut input)?;
	let mut buf = vec![0; len as usize];
	input.read_exact(&mut buf)?;
	String::from_utf8(buf).map_err(|_| DeserializeError::InvalidUtf8)
}