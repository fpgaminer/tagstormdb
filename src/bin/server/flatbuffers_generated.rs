// automatically generated by the FlatBuffers compiler, do not modify


// @generated

use core::{cmp::Ordering, mem};

extern crate flatbuffers;
use self::flatbuffers::{EndianScalar, Follow};

#[allow(unused_imports, dead_code, clippy::all)]
pub mod tag_storm_db {

	use core::{cmp::Ordering, mem};

	extern crate flatbuffers;
	use self::flatbuffers::{EndianScalar, Follow};

	#[deprecated(since = "2.0.0", note = "Use associated constants instead. This will no longer be generated in 2021.")]
	pub const ENUM_MIN_RESPONSE_TYPE: u8 = 0;
	#[deprecated(since = "2.0.0", note = "Use associated constants instead. This will no longer be generated in 2021.")]
	pub const ENUM_MAX_RESPONSE_TYPE: u8 = 3;
	#[deprecated(since = "2.0.0", note = "Use associated constants instead. This will no longer be generated in 2021.")]
	#[allow(non_camel_case_types)]
	pub const ENUM_VALUES_RESPONSE_TYPE: [ResponseType; 4] = [
		ResponseType::NONE,
		ResponseType::IDResponse,
		ResponseType::HashResponse,
		ResponseType::ImageResponse,
	];

	#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
	#[repr(transparent)]
	pub struct ResponseType(pub u8);
	#[allow(non_upper_case_globals)]
	impl ResponseType {
		pub const NONE: Self = Self(0);
		pub const IDResponse: Self = Self(1);
		pub const HashResponse: Self = Self(2);
		pub const ImageResponse: Self = Self(3);

		pub const ENUM_MIN: u8 = 0;
		pub const ENUM_MAX: u8 = 3;
		pub const ENUM_VALUES: &'static [Self] = &[Self::NONE, Self::IDResponse, Self::HashResponse, Self::ImageResponse];
		/// Returns the variant's name or "" if unknown.
		pub fn variant_name(self) -> Option<&'static str> {
			match self {
				Self::NONE => Some("NONE"),
				Self::IDResponse => Some("IDResponse"),
				Self::HashResponse => Some("HashResponse"),
				Self::ImageResponse => Some("ImageResponse"),
				_ => None,
			}
		}
	}
	impl core::fmt::Debug for ResponseType {
		fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
			if let Some(name) = self.variant_name() {
				f.write_str(name)
			} else {
				f.write_fmt(format_args!("<UNKNOWN {:?}>", self.0))
			}
		}
	}
	impl<'a> flatbuffers::Follow<'a> for ResponseType {
		type Inner = Self;
		#[inline]
		unsafe fn follow(buf: &'a [u8], loc: usize) -> Self::Inner {
			let b = flatbuffers::read_scalar_at::<u8>(buf, loc);
			Self(b)
		}
	}

	impl flatbuffers::Push for ResponseType {
		type Output = ResponseType;
		#[inline]
		unsafe fn push(&self, dst: &mut [u8], _written_len: usize) {
			flatbuffers::emplace_scalar::<u8>(dst, self.0);
		}
	}

	impl flatbuffers::EndianScalar for ResponseType {
		type Scalar = u8;
		#[inline]
		fn to_little_endian(self) -> u8 {
			self.0.to_le()
		}
		#[inline]
		#[allow(clippy::wrong_self_convention)]
		fn from_little_endian(v: u8) -> Self {
			let b = u8::from_le(v);
			Self(b)
		}
	}

	impl<'a> flatbuffers::Verifiable for ResponseType {
		#[inline]
		fn run_verifier(v: &mut flatbuffers::Verifier, pos: usize) -> Result<(), flatbuffers::InvalidFlatbuffer> {
			use self::flatbuffers::Verifiable;
			u8::run_verifier(v, pos)
		}
	}

	impl flatbuffers::SimpleToVerifyInSlice for ResponseType {}
	pub struct ResponseTypeUnionTableOffset {}

	// struct Hash, aligned to 1
	#[repr(transparent)]
	#[derive(Clone, Copy, PartialEq)]
	pub struct Hash(pub [u8; 32]);
	impl Default for Hash {
		fn default() -> Self {
			Self([0; 32])
		}
	}
	impl core::fmt::Debug for Hash {
		fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
			f.debug_struct("Hash").field("hash", &self.hash()).finish()
		}
	}

	impl flatbuffers::SimpleToVerifyInSlice for Hash {}
	impl<'a> flatbuffers::Follow<'a> for Hash {
		type Inner = &'a Hash;
		#[inline]
		unsafe fn follow(buf: &'a [u8], loc: usize) -> Self::Inner {
			<&'a Hash>::follow(buf, loc)
		}
	}
	impl<'a> flatbuffers::Follow<'a> for &'a Hash {
		type Inner = &'a Hash;
		#[inline]
		unsafe fn follow(buf: &'a [u8], loc: usize) -> Self::Inner {
			flatbuffers::follow_cast_ref::<Hash>(buf, loc)
		}
	}
	impl<'b> flatbuffers::Push for Hash {
		type Output = Hash;
		#[inline]
		unsafe fn push(&self, dst: &mut [u8], _written_len: usize) {
			let src = ::core::slice::from_raw_parts(self as *const Hash as *const u8, Self::size());
			dst.copy_from_slice(src);
		}
	}

	impl<'a> flatbuffers::Verifiable for Hash {
		#[inline]
		fn run_verifier(v: &mut flatbuffers::Verifier, pos: usize) -> Result<(), flatbuffers::InvalidFlatbuffer> {
			use self::flatbuffers::Verifiable;
			v.in_buffer::<Self>(pos)
		}
	}

	impl<'a> Hash {
		#[allow(clippy::too_many_arguments)]
		pub fn new(hash: &[u8; 32]) -> Self {
			let mut s = Self([0; 32]);
			s.set_hash(hash);
			s
		}

		pub fn hash(&'a self) -> flatbuffers::Array<'a, u8, 32> {
			// Safety:
			// Created from a valid Table for this object
			// Which contains a valid array in this slot
			unsafe { flatbuffers::Array::follow(&self.0, 0) }
		}

		pub fn set_hash(&mut self, items: &[u8; 32]) {
			// Safety:
			// Created from a valid Table for this object
			// Which contains a valid array in this slot
			unsafe { flatbuffers::emplace_scalar_array(&mut self.0, 0, items) };
		}
	}

	pub enum TagWithBlameOffset {}
	#[derive(Copy, Clone, PartialEq)]

	pub struct TagWithBlame<'a> {
		pub _tab: flatbuffers::Table<'a>,
	}

	impl<'a> flatbuffers::Follow<'a> for TagWithBlame<'a> {
		type Inner = TagWithBlame<'a>;
		#[inline]
		unsafe fn follow(buf: &'a [u8], loc: usize) -> Self::Inner {
			Self {
				_tab: flatbuffers::Table::new(buf, loc),
			}
		}
	}

	impl<'a> TagWithBlame<'a> {
		pub const VT_TAG: flatbuffers::VOffsetT = 4;
		pub const VT_BLAME: flatbuffers::VOffsetT = 6;

		#[inline]
		pub unsafe fn init_from_table(table: flatbuffers::Table<'a>) -> Self {
			TagWithBlame { _tab: table }
		}
		#[allow(unused_mut)]
		pub fn create<'bldr: 'args, 'args: 'mut_bldr, 'mut_bldr, A: flatbuffers::Allocator + 'bldr>(
			_fbb: &'mut_bldr mut flatbuffers::FlatBufferBuilder<'bldr, A>,
			args: &'args TagWithBlameArgs,
		) -> flatbuffers::WIPOffset<TagWithBlame<'bldr>> {
			let mut builder = TagWithBlameBuilder::new(_fbb);
			builder.add_blame(args.blame);
			builder.add_tag(args.tag);
			builder.finish()
		}


		#[inline]
		pub fn tag(&self) -> u32 {
			// Safety:
			// Created from valid Table for this object
			// which contains a valid value in this slot
			unsafe { self._tab.get::<u32>(TagWithBlame::VT_TAG, Some(0)).unwrap() }
		}
		#[inline]
		pub fn blame(&self) -> u32 {
			// Safety:
			// Created from valid Table for this object
			// which contains a valid value in this slot
			unsafe { self._tab.get::<u32>(TagWithBlame::VT_BLAME, Some(0)).unwrap() }
		}
	}

	impl flatbuffers::Verifiable for TagWithBlame<'_> {
		#[inline]
		fn run_verifier(v: &mut flatbuffers::Verifier, pos: usize) -> Result<(), flatbuffers::InvalidFlatbuffer> {
			use self::flatbuffers::Verifiable;
			v.visit_table(pos)?
				.visit_field::<u32>("tag", Self::VT_TAG, false)?
				.visit_field::<u32>("blame", Self::VT_BLAME, false)?
				.finish();
			Ok(())
		}
	}
	pub struct TagWithBlameArgs {
		pub tag: u32,
		pub blame: u32,
	}
	impl<'a> Default for TagWithBlameArgs {
		#[inline]
		fn default() -> Self {
			TagWithBlameArgs { tag: 0, blame: 0 }
		}
	}

	pub struct TagWithBlameBuilder<'a: 'b, 'b, A: flatbuffers::Allocator + 'a> {
		fbb_: &'b mut flatbuffers::FlatBufferBuilder<'a, A>,
		start_: flatbuffers::WIPOffset<flatbuffers::TableUnfinishedWIPOffset>,
	}
	impl<'a: 'b, 'b, A: flatbuffers::Allocator + 'a> TagWithBlameBuilder<'a, 'b, A> {
		#[inline]
		pub fn add_tag(&mut self, tag: u32) {
			self.fbb_.push_slot::<u32>(TagWithBlame::VT_TAG, tag, 0);
		}
		#[inline]
		pub fn add_blame(&mut self, blame: u32) {
			self.fbb_.push_slot::<u32>(TagWithBlame::VT_BLAME, blame, 0);
		}
		#[inline]
		pub fn new(_fbb: &'b mut flatbuffers::FlatBufferBuilder<'a, A>) -> TagWithBlameBuilder<'a, 'b, A> {
			let start = _fbb.start_table();
			TagWithBlameBuilder { fbb_: _fbb, start_: start }
		}
		#[inline]
		pub fn finish(self) -> flatbuffers::WIPOffset<TagWithBlame<'a>> {
			let o = self.fbb_.end_table(self.start_);
			flatbuffers::WIPOffset::new(o.value())
		}
	}

	impl core::fmt::Debug for TagWithBlame<'_> {
		fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
			let mut ds = f.debug_struct("TagWithBlame");
			ds.field("tag", &self.tag());
			ds.field("blame", &self.blame());
			ds.finish()
		}
	}
	pub enum AttributeWithBlameOffset {}
	#[derive(Copy, Clone, PartialEq)]

	pub struct AttributeWithBlame<'a> {
		pub _tab: flatbuffers::Table<'a>,
	}

	impl<'a> flatbuffers::Follow<'a> for AttributeWithBlame<'a> {
		type Inner = AttributeWithBlame<'a>;
		#[inline]
		unsafe fn follow(buf: &'a [u8], loc: usize) -> Self::Inner {
			Self {
				_tab: flatbuffers::Table::new(buf, loc),
			}
		}
	}

	impl<'a> AttributeWithBlame<'a> {
		pub const VT_KEY: flatbuffers::VOffsetT = 4;
		pub const VT_VALUE: flatbuffers::VOffsetT = 6;
		pub const VT_BLAME: flatbuffers::VOffsetT = 8;

		#[inline]
		pub unsafe fn init_from_table(table: flatbuffers::Table<'a>) -> Self {
			AttributeWithBlame { _tab: table }
		}
		#[allow(unused_mut)]
		pub fn create<'bldr: 'args, 'args: 'mut_bldr, 'mut_bldr, A: flatbuffers::Allocator + 'bldr>(
			_fbb: &'mut_bldr mut flatbuffers::FlatBufferBuilder<'bldr, A>,
			args: &'args AttributeWithBlameArgs<'args>,
		) -> flatbuffers::WIPOffset<AttributeWithBlame<'bldr>> {
			let mut builder = AttributeWithBlameBuilder::new(_fbb);
			builder.add_blame(args.blame);
			if let Some(x) = args.value {
				builder.add_value(x);
			}
			if let Some(x) = args.key {
				builder.add_key(x);
			}
			builder.finish()
		}


		#[inline]
		pub fn key(&self) -> Option<&'a str> {
			// Safety:
			// Created from valid Table for this object
			// which contains a valid value in this slot
			unsafe { self._tab.get::<flatbuffers::ForwardsUOffset<&str>>(AttributeWithBlame::VT_KEY, None) }
		}
		#[inline]
		pub fn value(&self) -> Option<&'a str> {
			// Safety:
			// Created from valid Table for this object
			// which contains a valid value in this slot
			unsafe { self._tab.get::<flatbuffers::ForwardsUOffset<&str>>(AttributeWithBlame::VT_VALUE, None) }
		}
		#[inline]
		pub fn blame(&self) -> u32 {
			// Safety:
			// Created from valid Table for this object
			// which contains a valid value in this slot
			unsafe { self._tab.get::<u32>(AttributeWithBlame::VT_BLAME, Some(0)).unwrap() }
		}
	}

	impl flatbuffers::Verifiable for AttributeWithBlame<'_> {
		#[inline]
		fn run_verifier(v: &mut flatbuffers::Verifier, pos: usize) -> Result<(), flatbuffers::InvalidFlatbuffer> {
			use self::flatbuffers::Verifiable;
			v.visit_table(pos)?
				.visit_field::<flatbuffers::ForwardsUOffset<&str>>("key", Self::VT_KEY, false)?
				.visit_field::<flatbuffers::ForwardsUOffset<&str>>("value", Self::VT_VALUE, false)?
				.visit_field::<u32>("blame", Self::VT_BLAME, false)?
				.finish();
			Ok(())
		}
	}
	pub struct AttributeWithBlameArgs<'a> {
		pub key: Option<flatbuffers::WIPOffset<&'a str>>,
		pub value: Option<flatbuffers::WIPOffset<&'a str>>,
		pub blame: u32,
	}
	impl<'a> Default for AttributeWithBlameArgs<'a> {
		#[inline]
		fn default() -> Self {
			AttributeWithBlameArgs {
				key: None,
				value: None,
				blame: 0,
			}
		}
	}

	pub struct AttributeWithBlameBuilder<'a: 'b, 'b, A: flatbuffers::Allocator + 'a> {
		fbb_: &'b mut flatbuffers::FlatBufferBuilder<'a, A>,
		start_: flatbuffers::WIPOffset<flatbuffers::TableUnfinishedWIPOffset>,
	}
	impl<'a: 'b, 'b, A: flatbuffers::Allocator + 'a> AttributeWithBlameBuilder<'a, 'b, A> {
		#[inline]
		pub fn add_key(&mut self, key: flatbuffers::WIPOffset<&'b str>) {
			self.fbb_.push_slot_always::<flatbuffers::WIPOffset<_>>(AttributeWithBlame::VT_KEY, key);
		}
		#[inline]
		pub fn add_value(&mut self, value: flatbuffers::WIPOffset<&'b str>) {
			self.fbb_.push_slot_always::<flatbuffers::WIPOffset<_>>(AttributeWithBlame::VT_VALUE, value);
		}
		#[inline]
		pub fn add_blame(&mut self, blame: u32) {
			self.fbb_.push_slot::<u32>(AttributeWithBlame::VT_BLAME, blame, 0);
		}
		#[inline]
		pub fn new(_fbb: &'b mut flatbuffers::FlatBufferBuilder<'a, A>) -> AttributeWithBlameBuilder<'a, 'b, A> {
			let start = _fbb.start_table();
			AttributeWithBlameBuilder { fbb_: _fbb, start_: start }
		}
		#[inline]
		pub fn finish(self) -> flatbuffers::WIPOffset<AttributeWithBlame<'a>> {
			let o = self.fbb_.end_table(self.start_);
			flatbuffers::WIPOffset::new(o.value())
		}
	}

	impl core::fmt::Debug for AttributeWithBlame<'_> {
		fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
			let mut ds = f.debug_struct("AttributeWithBlame");
			ds.field("key", &self.key());
			ds.field("value", &self.value());
			ds.field("blame", &self.blame());
			ds.finish()
		}
	}
	pub enum ImageOffset {}
	#[derive(Copy, Clone, PartialEq)]

	pub struct Image<'a> {
		pub _tab: flatbuffers::Table<'a>,
	}

	impl<'a> flatbuffers::Follow<'a> for Image<'a> {
		type Inner = Image<'a>;
		#[inline]
		unsafe fn follow(buf: &'a [u8], loc: usize) -> Self::Inner {
			Self {
				_tab: flatbuffers::Table::new(buf, loc),
			}
		}
	}

	impl<'a> Image<'a> {
		pub const VT_ID: flatbuffers::VOffsetT = 4;
		pub const VT_HASH: flatbuffers::VOffsetT = 6;
		pub const VT_TAGS: flatbuffers::VOffsetT = 8;
		pub const VT_ATTRIBUTES: flatbuffers::VOffsetT = 10;

		#[inline]
		pub unsafe fn init_from_table(table: flatbuffers::Table<'a>) -> Self {
			Image { _tab: table }
		}
		#[allow(unused_mut)]
		pub fn create<'bldr: 'args, 'args: 'mut_bldr, 'mut_bldr, A: flatbuffers::Allocator + 'bldr>(
			_fbb: &'mut_bldr mut flatbuffers::FlatBufferBuilder<'bldr, A>,
			args: &'args ImageArgs<'args>,
		) -> flatbuffers::WIPOffset<Image<'bldr>> {
			let mut builder = ImageBuilder::new(_fbb);
			if let Some(x) = args.attributes {
				builder.add_attributes(x);
			}
			if let Some(x) = args.tags {
				builder.add_tags(x);
			}
			if let Some(x) = args.hash {
				builder.add_hash(x);
			}
			builder.add_id(args.id);
			builder.finish()
		}


		#[inline]
		pub fn id(&self) -> u32 {
			// Safety:
			// Created from valid Table for this object
			// which contains a valid value in this slot
			unsafe { self._tab.get::<u32>(Image::VT_ID, Some(0)).unwrap() }
		}
		#[inline]
		pub fn hash(&self) -> Option<&'a Hash> {
			// Safety:
			// Created from valid Table for this object
			// which contains a valid value in this slot
			unsafe { self._tab.get::<Hash>(Image::VT_HASH, None) }
		}
		#[inline]
		pub fn tags(&self) -> Option<flatbuffers::Vector<'a, flatbuffers::ForwardsUOffset<TagWithBlame<'a>>>> {
			// Safety:
			// Created from valid Table for this object
			// which contains a valid value in this slot
			unsafe {
				self._tab
					.get::<flatbuffers::ForwardsUOffset<flatbuffers::Vector<'a, flatbuffers::ForwardsUOffset<TagWithBlame>>>>(Image::VT_TAGS, None)
			}
		}
		#[inline]
		pub fn attributes(&self) -> Option<flatbuffers::Vector<'a, flatbuffers::ForwardsUOffset<AttributeWithBlame<'a>>>> {
			// Safety:
			// Created from valid Table for this object
			// which contains a valid value in this slot
			unsafe {
				self._tab
					.get::<flatbuffers::ForwardsUOffset<flatbuffers::Vector<'a, flatbuffers::ForwardsUOffset<AttributeWithBlame>>>>(Image::VT_ATTRIBUTES, None)
			}
		}
	}

	impl flatbuffers::Verifiable for Image<'_> {
		#[inline]
		fn run_verifier(v: &mut flatbuffers::Verifier, pos: usize) -> Result<(), flatbuffers::InvalidFlatbuffer> {
			use self::flatbuffers::Verifiable;
			v.visit_table(pos)?
				.visit_field::<u32>("id", Self::VT_ID, false)?
				.visit_field::<Hash>("hash", Self::VT_HASH, false)?
				.visit_field::<flatbuffers::ForwardsUOffset<flatbuffers::Vector<'_, flatbuffers::ForwardsUOffset<TagWithBlame>>>>("tags", Self::VT_TAGS, false)?
				.visit_field::<flatbuffers::ForwardsUOffset<flatbuffers::Vector<'_, flatbuffers::ForwardsUOffset<AttributeWithBlame>>>>(
					"attributes",
					Self::VT_ATTRIBUTES,
					false,
				)?
				.finish();
			Ok(())
		}
	}
	pub struct ImageArgs<'a> {
		pub id: u32,
		pub hash: Option<&'a Hash>,
		pub tags: Option<flatbuffers::WIPOffset<flatbuffers::Vector<'a, flatbuffers::ForwardsUOffset<TagWithBlame<'a>>>>>,
		pub attributes: Option<flatbuffers::WIPOffset<flatbuffers::Vector<'a, flatbuffers::ForwardsUOffset<AttributeWithBlame<'a>>>>>,
	}
	impl<'a> Default for ImageArgs<'a> {
		#[inline]
		fn default() -> Self {
			ImageArgs {
				id: 0,
				hash: None,
				tags: None,
				attributes: None,
			}
		}
	}

	pub struct ImageBuilder<'a: 'b, 'b, A: flatbuffers::Allocator + 'a> {
		fbb_: &'b mut flatbuffers::FlatBufferBuilder<'a, A>,
		start_: flatbuffers::WIPOffset<flatbuffers::TableUnfinishedWIPOffset>,
	}
	impl<'a: 'b, 'b, A: flatbuffers::Allocator + 'a> ImageBuilder<'a, 'b, A> {
		#[inline]
		pub fn add_id(&mut self, id: u32) {
			self.fbb_.push_slot::<u32>(Image::VT_ID, id, 0);
		}
		#[inline]
		pub fn add_hash(&mut self, hash: &Hash) {
			self.fbb_.push_slot_always::<&Hash>(Image::VT_HASH, hash);
		}
		#[inline]
		pub fn add_tags(&mut self, tags: flatbuffers::WIPOffset<flatbuffers::Vector<'b, flatbuffers::ForwardsUOffset<TagWithBlame<'b>>>>) {
			self.fbb_.push_slot_always::<flatbuffers::WIPOffset<_>>(Image::VT_TAGS, tags);
		}
		#[inline]
		pub fn add_attributes(&mut self, attributes: flatbuffers::WIPOffset<flatbuffers::Vector<'b, flatbuffers::ForwardsUOffset<AttributeWithBlame<'b>>>>) {
			self.fbb_.push_slot_always::<flatbuffers::WIPOffset<_>>(Image::VT_ATTRIBUTES, attributes);
		}
		#[inline]
		pub fn new(_fbb: &'b mut flatbuffers::FlatBufferBuilder<'a, A>) -> ImageBuilder<'a, 'b, A> {
			let start = _fbb.start_table();
			ImageBuilder { fbb_: _fbb, start_: start }
		}
		#[inline]
		pub fn finish(self) -> flatbuffers::WIPOffset<Image<'a>> {
			let o = self.fbb_.end_table(self.start_);
			flatbuffers::WIPOffset::new(o.value())
		}
	}

	impl core::fmt::Debug for Image<'_> {
		fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
			let mut ds = f.debug_struct("Image");
			ds.field("id", &self.id());
			ds.field("hash", &self.hash());
			ds.field("tags", &self.tags());
			ds.field("attributes", &self.attributes());
			ds.finish()
		}
	}
	pub enum ImageResponseOffset {}
	#[derive(Copy, Clone, PartialEq)]

	pub struct ImageResponse<'a> {
		pub _tab: flatbuffers::Table<'a>,
	}

	impl<'a> flatbuffers::Follow<'a> for ImageResponse<'a> {
		type Inner = ImageResponse<'a>;
		#[inline]
		unsafe fn follow(buf: &'a [u8], loc: usize) -> Self::Inner {
			Self {
				_tab: flatbuffers::Table::new(buf, loc),
			}
		}
	}

	impl<'a> ImageResponse<'a> {
		pub const VT_IMAGES: flatbuffers::VOffsetT = 4;

		#[inline]
		pub unsafe fn init_from_table(table: flatbuffers::Table<'a>) -> Self {
			ImageResponse { _tab: table }
		}
		#[allow(unused_mut)]
		pub fn create<'bldr: 'args, 'args: 'mut_bldr, 'mut_bldr, A: flatbuffers::Allocator + 'bldr>(
			_fbb: &'mut_bldr mut flatbuffers::FlatBufferBuilder<'bldr, A>,
			args: &'args ImageResponseArgs<'args>,
		) -> flatbuffers::WIPOffset<ImageResponse<'bldr>> {
			let mut builder = ImageResponseBuilder::new(_fbb);
			if let Some(x) = args.images {
				builder.add_images(x);
			}
			builder.finish()
		}


		#[inline]
		pub fn images(&self) -> Option<flatbuffers::Vector<'a, flatbuffers::ForwardsUOffset<Image<'a>>>> {
			// Safety:
			// Created from valid Table for this object
			// which contains a valid value in this slot
			unsafe {
				self._tab
					.get::<flatbuffers::ForwardsUOffset<flatbuffers::Vector<'a, flatbuffers::ForwardsUOffset<Image>>>>(ImageResponse::VT_IMAGES, None)
			}
		}
	}

	impl flatbuffers::Verifiable for ImageResponse<'_> {
		#[inline]
		fn run_verifier(v: &mut flatbuffers::Verifier, pos: usize) -> Result<(), flatbuffers::InvalidFlatbuffer> {
			use self::flatbuffers::Verifiable;
			v.visit_table(pos)?
				.visit_field::<flatbuffers::ForwardsUOffset<flatbuffers::Vector<'_, flatbuffers::ForwardsUOffset<Image>>>>("images", Self::VT_IMAGES, false)?
				.finish();
			Ok(())
		}
	}
	pub struct ImageResponseArgs<'a> {
		pub images: Option<flatbuffers::WIPOffset<flatbuffers::Vector<'a, flatbuffers::ForwardsUOffset<Image<'a>>>>>,
	}
	impl<'a> Default for ImageResponseArgs<'a> {
		#[inline]
		fn default() -> Self {
			ImageResponseArgs { images: None }
		}
	}

	pub struct ImageResponseBuilder<'a: 'b, 'b, A: flatbuffers::Allocator + 'a> {
		fbb_: &'b mut flatbuffers::FlatBufferBuilder<'a, A>,
		start_: flatbuffers::WIPOffset<flatbuffers::TableUnfinishedWIPOffset>,
	}
	impl<'a: 'b, 'b, A: flatbuffers::Allocator + 'a> ImageResponseBuilder<'a, 'b, A> {
		#[inline]
		pub fn add_images(&mut self, images: flatbuffers::WIPOffset<flatbuffers::Vector<'b, flatbuffers::ForwardsUOffset<Image<'b>>>>) {
			self.fbb_.push_slot_always::<flatbuffers::WIPOffset<_>>(ImageResponse::VT_IMAGES, images);
		}
		#[inline]
		pub fn new(_fbb: &'b mut flatbuffers::FlatBufferBuilder<'a, A>) -> ImageResponseBuilder<'a, 'b, A> {
			let start = _fbb.start_table();
			ImageResponseBuilder { fbb_: _fbb, start_: start }
		}
		#[inline]
		pub fn finish(self) -> flatbuffers::WIPOffset<ImageResponse<'a>> {
			let o = self.fbb_.end_table(self.start_);
			flatbuffers::WIPOffset::new(o.value())
		}
	}

	impl core::fmt::Debug for ImageResponse<'_> {
		fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
			let mut ds = f.debug_struct("ImageResponse");
			ds.field("images", &self.images());
			ds.finish()
		}
	}
	pub enum IDResponseOffset {}
	#[derive(Copy, Clone, PartialEq)]

	pub struct IDResponse<'a> {
		pub _tab: flatbuffers::Table<'a>,
	}

	impl<'a> flatbuffers::Follow<'a> for IDResponse<'a> {
		type Inner = IDResponse<'a>;
		#[inline]
		unsafe fn follow(buf: &'a [u8], loc: usize) -> Self::Inner {
			Self {
				_tab: flatbuffers::Table::new(buf, loc),
			}
		}
	}

	impl<'a> IDResponse<'a> {
		pub const VT_IDS: flatbuffers::VOffsetT = 4;

		#[inline]
		pub unsafe fn init_from_table(table: flatbuffers::Table<'a>) -> Self {
			IDResponse { _tab: table }
		}
		#[allow(unused_mut)]
		pub fn create<'bldr: 'args, 'args: 'mut_bldr, 'mut_bldr, A: flatbuffers::Allocator + 'bldr>(
			_fbb: &'mut_bldr mut flatbuffers::FlatBufferBuilder<'bldr, A>,
			args: &'args IDResponseArgs<'args>,
		) -> flatbuffers::WIPOffset<IDResponse<'bldr>> {
			let mut builder = IDResponseBuilder::new(_fbb);
			if let Some(x) = args.ids {
				builder.add_ids(x);
			}
			builder.finish()
		}


		#[inline]
		pub fn ids(&self) -> Option<flatbuffers::Vector<'a, u32>> {
			// Safety:
			// Created from valid Table for this object
			// which contains a valid value in this slot
			unsafe {
				self._tab
					.get::<flatbuffers::ForwardsUOffset<flatbuffers::Vector<'a, u32>>>(IDResponse::VT_IDS, None)
			}
		}
	}

	impl flatbuffers::Verifiable for IDResponse<'_> {
		#[inline]
		fn run_verifier(v: &mut flatbuffers::Verifier, pos: usize) -> Result<(), flatbuffers::InvalidFlatbuffer> {
			use self::flatbuffers::Verifiable;
			v.visit_table(pos)?
				.visit_field::<flatbuffers::ForwardsUOffset<flatbuffers::Vector<'_, u32>>>("ids", Self::VT_IDS, false)?
				.finish();
			Ok(())
		}
	}
	pub struct IDResponseArgs<'a> {
		pub ids: Option<flatbuffers::WIPOffset<flatbuffers::Vector<'a, u32>>>,
	}
	impl<'a> Default for IDResponseArgs<'a> {
		#[inline]
		fn default() -> Self {
			IDResponseArgs { ids: None }
		}
	}

	pub struct IDResponseBuilder<'a: 'b, 'b, A: flatbuffers::Allocator + 'a> {
		fbb_: &'b mut flatbuffers::FlatBufferBuilder<'a, A>,
		start_: flatbuffers::WIPOffset<flatbuffers::TableUnfinishedWIPOffset>,
	}
	impl<'a: 'b, 'b, A: flatbuffers::Allocator + 'a> IDResponseBuilder<'a, 'b, A> {
		#[inline]
		pub fn add_ids(&mut self, ids: flatbuffers::WIPOffset<flatbuffers::Vector<'b, u32>>) {
			self.fbb_.push_slot_always::<flatbuffers::WIPOffset<_>>(IDResponse::VT_IDS, ids);
		}
		#[inline]
		pub fn new(_fbb: &'b mut flatbuffers::FlatBufferBuilder<'a, A>) -> IDResponseBuilder<'a, 'b, A> {
			let start = _fbb.start_table();
			IDResponseBuilder { fbb_: _fbb, start_: start }
		}
		#[inline]
		pub fn finish(self) -> flatbuffers::WIPOffset<IDResponse<'a>> {
			let o = self.fbb_.end_table(self.start_);
			flatbuffers::WIPOffset::new(o.value())
		}
	}

	impl core::fmt::Debug for IDResponse<'_> {
		fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
			let mut ds = f.debug_struct("IDResponse");
			ds.field("ids", &self.ids());
			ds.finish()
		}
	}
	pub enum HashResponseOffset {}
	#[derive(Copy, Clone, PartialEq)]

	pub struct HashResponse<'a> {
		pub _tab: flatbuffers::Table<'a>,
	}

	impl<'a> flatbuffers::Follow<'a> for HashResponse<'a> {
		type Inner = HashResponse<'a>;
		#[inline]
		unsafe fn follow(buf: &'a [u8], loc: usize) -> Self::Inner {
			Self {
				_tab: flatbuffers::Table::new(buf, loc),
			}
		}
	}

	impl<'a> HashResponse<'a> {
		pub const VT_HASHES: flatbuffers::VOffsetT = 4;

		#[inline]
		pub unsafe fn init_from_table(table: flatbuffers::Table<'a>) -> Self {
			HashResponse { _tab: table }
		}
		#[allow(unused_mut)]
		pub fn create<'bldr: 'args, 'args: 'mut_bldr, 'mut_bldr, A: flatbuffers::Allocator + 'bldr>(
			_fbb: &'mut_bldr mut flatbuffers::FlatBufferBuilder<'bldr, A>,
			args: &'args HashResponseArgs<'args>,
		) -> flatbuffers::WIPOffset<HashResponse<'bldr>> {
			let mut builder = HashResponseBuilder::new(_fbb);
			if let Some(x) = args.hashes {
				builder.add_hashes(x);
			}
			builder.finish()
		}


		#[inline]
		pub fn hashes(&self) -> Option<flatbuffers::Vector<'a, Hash>> {
			// Safety:
			// Created from valid Table for this object
			// which contains a valid value in this slot
			unsafe {
				self._tab
					.get::<flatbuffers::ForwardsUOffset<flatbuffers::Vector<'a, Hash>>>(HashResponse::VT_HASHES, None)
			}
		}
	}

	impl flatbuffers::Verifiable for HashResponse<'_> {
		#[inline]
		fn run_verifier(v: &mut flatbuffers::Verifier, pos: usize) -> Result<(), flatbuffers::InvalidFlatbuffer> {
			use self::flatbuffers::Verifiable;
			v.visit_table(pos)?
				.visit_field::<flatbuffers::ForwardsUOffset<flatbuffers::Vector<'_, Hash>>>("hashes", Self::VT_HASHES, false)?
				.finish();
			Ok(())
		}
	}
	pub struct HashResponseArgs<'a> {
		pub hashes: Option<flatbuffers::WIPOffset<flatbuffers::Vector<'a, Hash>>>,
	}
	impl<'a> Default for HashResponseArgs<'a> {
		#[inline]
		fn default() -> Self {
			HashResponseArgs { hashes: None }
		}
	}

	pub struct HashResponseBuilder<'a: 'b, 'b, A: flatbuffers::Allocator + 'a> {
		fbb_: &'b mut flatbuffers::FlatBufferBuilder<'a, A>,
		start_: flatbuffers::WIPOffset<flatbuffers::TableUnfinishedWIPOffset>,
	}
	impl<'a: 'b, 'b, A: flatbuffers::Allocator + 'a> HashResponseBuilder<'a, 'b, A> {
		#[inline]
		pub fn add_hashes(&mut self, hashes: flatbuffers::WIPOffset<flatbuffers::Vector<'b, Hash>>) {
			self.fbb_.push_slot_always::<flatbuffers::WIPOffset<_>>(HashResponse::VT_HASHES, hashes);
		}
		#[inline]
		pub fn new(_fbb: &'b mut flatbuffers::FlatBufferBuilder<'a, A>) -> HashResponseBuilder<'a, 'b, A> {
			let start = _fbb.start_table();
			HashResponseBuilder { fbb_: _fbb, start_: start }
		}
		#[inline]
		pub fn finish(self) -> flatbuffers::WIPOffset<HashResponse<'a>> {
			let o = self.fbb_.end_table(self.start_);
			flatbuffers::WIPOffset::new(o.value())
		}
	}

	impl core::fmt::Debug for HashResponse<'_> {
		fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
			let mut ds = f.debug_struct("HashResponse");
			ds.field("hashes", &self.hashes());
			ds.finish()
		}
	}
	pub enum SearchResultResponseOffset {}
	#[derive(Copy, Clone, PartialEq)]

	pub struct SearchResultResponse<'a> {
		pub _tab: flatbuffers::Table<'a>,
	}

	impl<'a> flatbuffers::Follow<'a> for SearchResultResponse<'a> {
		type Inner = SearchResultResponse<'a>;
		#[inline]
		unsafe fn follow(buf: &'a [u8], loc: usize) -> Self::Inner {
			Self {
				_tab: flatbuffers::Table::new(buf, loc),
			}
		}
	}

	impl<'a> SearchResultResponse<'a> {
		pub const VT_DATA_TYPE: flatbuffers::VOffsetT = 4;
		pub const VT_DATA: flatbuffers::VOffsetT = 6;

		#[inline]
		pub unsafe fn init_from_table(table: flatbuffers::Table<'a>) -> Self {
			SearchResultResponse { _tab: table }
		}
		#[allow(unused_mut)]
		pub fn create<'bldr: 'args, 'args: 'mut_bldr, 'mut_bldr, A: flatbuffers::Allocator + 'bldr>(
			_fbb: &'mut_bldr mut flatbuffers::FlatBufferBuilder<'bldr, A>,
			args: &'args SearchResultResponseArgs,
		) -> flatbuffers::WIPOffset<SearchResultResponse<'bldr>> {
			let mut builder = SearchResultResponseBuilder::new(_fbb);
			if let Some(x) = args.data {
				builder.add_data(x);
			}
			builder.add_data_type(args.data_type);
			builder.finish()
		}


		#[inline]
		pub fn data_type(&self) -> ResponseType {
			// Safety:
			// Created from valid Table for this object
			// which contains a valid value in this slot
			unsafe {
				self._tab
					.get::<ResponseType>(SearchResultResponse::VT_DATA_TYPE, Some(ResponseType::NONE))
					.unwrap()
			}
		}
		#[inline]
		pub fn data(&self) -> Option<flatbuffers::Table<'a>> {
			// Safety:
			// Created from valid Table for this object
			// which contains a valid value in this slot
			unsafe {
				self._tab
					.get::<flatbuffers::ForwardsUOffset<flatbuffers::Table<'a>>>(SearchResultResponse::VT_DATA, None)
			}
		}
		#[inline]
		#[allow(non_snake_case)]
		pub fn data_as_idresponse(&self) -> Option<IDResponse<'a>> {
			if self.data_type() == ResponseType::IDResponse {
				self.data().map(|t| {
					// Safety:
					// Created from a valid Table for this object
					// Which contains a valid union in this slot
					unsafe { IDResponse::init_from_table(t) }
				})
			} else {
				None
			}
		}

		#[inline]
		#[allow(non_snake_case)]
		pub fn data_as_hash_response(&self) -> Option<HashResponse<'a>> {
			if self.data_type() == ResponseType::HashResponse {
				self.data().map(|t| {
					// Safety:
					// Created from a valid Table for this object
					// Which contains a valid union in this slot
					unsafe { HashResponse::init_from_table(t) }
				})
			} else {
				None
			}
		}

		#[inline]
		#[allow(non_snake_case)]
		pub fn data_as_image_response(&self) -> Option<ImageResponse<'a>> {
			if self.data_type() == ResponseType::ImageResponse {
				self.data().map(|t| {
					// Safety:
					// Created from a valid Table for this object
					// Which contains a valid union in this slot
					unsafe { ImageResponse::init_from_table(t) }
				})
			} else {
				None
			}
		}
	}

	impl flatbuffers::Verifiable for SearchResultResponse<'_> {
		#[inline]
		fn run_verifier(v: &mut flatbuffers::Verifier, pos: usize) -> Result<(), flatbuffers::InvalidFlatbuffer> {
			use self::flatbuffers::Verifiable;
			v.visit_table(pos)?
				.visit_union::<ResponseType, _>("data_type", Self::VT_DATA_TYPE, "data", Self::VT_DATA, false, |key, v, pos| match key {
					ResponseType::IDResponse => v.verify_union_variant::<flatbuffers::ForwardsUOffset<IDResponse>>("ResponseType::IDResponse", pos),
					ResponseType::HashResponse => v.verify_union_variant::<flatbuffers::ForwardsUOffset<HashResponse>>("ResponseType::HashResponse", pos),
					ResponseType::ImageResponse => v.verify_union_variant::<flatbuffers::ForwardsUOffset<ImageResponse>>("ResponseType::ImageResponse", pos),
					_ => Ok(()),
				})?
				.finish();
			Ok(())
		}
	}
	pub struct SearchResultResponseArgs {
		pub data_type: ResponseType,
		pub data: Option<flatbuffers::WIPOffset<flatbuffers::UnionWIPOffset>>,
	}
	impl<'a> Default for SearchResultResponseArgs {
		#[inline]
		fn default() -> Self {
			SearchResultResponseArgs {
				data_type: ResponseType::NONE,
				data: None,
			}
		}
	}

	pub struct SearchResultResponseBuilder<'a: 'b, 'b, A: flatbuffers::Allocator + 'a> {
		fbb_: &'b mut flatbuffers::FlatBufferBuilder<'a, A>,
		start_: flatbuffers::WIPOffset<flatbuffers::TableUnfinishedWIPOffset>,
	}
	impl<'a: 'b, 'b, A: flatbuffers::Allocator + 'a> SearchResultResponseBuilder<'a, 'b, A> {
		#[inline]
		pub fn add_data_type(&mut self, data_type: ResponseType) {
			self.fbb_
				.push_slot::<ResponseType>(SearchResultResponse::VT_DATA_TYPE, data_type, ResponseType::NONE);
		}
		#[inline]
		pub fn add_data(&mut self, data: flatbuffers::WIPOffset<flatbuffers::UnionWIPOffset>) {
			self.fbb_.push_slot_always::<flatbuffers::WIPOffset<_>>(SearchResultResponse::VT_DATA, data);
		}
		#[inline]
		pub fn new(_fbb: &'b mut flatbuffers::FlatBufferBuilder<'a, A>) -> SearchResultResponseBuilder<'a, 'b, A> {
			let start = _fbb.start_table();
			SearchResultResponseBuilder { fbb_: _fbb, start_: start }
		}
		#[inline]
		pub fn finish(self) -> flatbuffers::WIPOffset<SearchResultResponse<'a>> {
			let o = self.fbb_.end_table(self.start_);
			flatbuffers::WIPOffset::new(o.value())
		}
	}

	impl core::fmt::Debug for SearchResultResponse<'_> {
		fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
			let mut ds = f.debug_struct("SearchResultResponse");
			ds.field("data_type", &self.data_type());
			match self.data_type() {
				ResponseType::IDResponse => {
					if let Some(x) = self.data_as_idresponse() {
						ds.field("data", &x)
					} else {
						ds.field("data", &"InvalidFlatbuffer: Union discriminant does not match value.")
					}
				},
				ResponseType::HashResponse => {
					if let Some(x) = self.data_as_hash_response() {
						ds.field("data", &x)
					} else {
						ds.field("data", &"InvalidFlatbuffer: Union discriminant does not match value.")
					}
				},
				ResponseType::ImageResponse => {
					if let Some(x) = self.data_as_image_response() {
						ds.field("data", &x)
					} else {
						ds.field("data", &"InvalidFlatbuffer: Union discriminant does not match value.")
					}
				},
				_ => {
					let x: Option<()> = None;
					ds.field("data", &x)
				},
			};
			ds.finish()
		}
	}
	#[inline]
	/// Verifies that a buffer of bytes contains a `SearchResultResponse`
	/// and returns it.
	/// Note that verification is still experimental and may not
	/// catch every error, or be maximally performant. For the
	/// previous, unchecked, behavior use
	/// `root_as_search_result_response_unchecked`.
	pub fn root_as_search_result_response(buf: &[u8]) -> Result<SearchResultResponse, flatbuffers::InvalidFlatbuffer> {
		flatbuffers::root::<SearchResultResponse>(buf)
	}
	#[inline]
	/// Verifies that a buffer of bytes contains a size prefixed
	/// `SearchResultResponse` and returns it.
	/// Note that verification is still experimental and may not
	/// catch every error, or be maximally performant. For the
	/// previous, unchecked, behavior use
	/// `size_prefixed_root_as_search_result_response_unchecked`.
	pub fn size_prefixed_root_as_search_result_response(buf: &[u8]) -> Result<SearchResultResponse, flatbuffers::InvalidFlatbuffer> {
		flatbuffers::size_prefixed_root::<SearchResultResponse>(buf)
	}
	#[inline]
	/// Verifies, with the given options, that a buffer of bytes
	/// contains a `SearchResultResponse` and returns it.
	/// Note that verification is still experimental and may not
	/// catch every error, or be maximally performant. For the
	/// previous, unchecked, behavior use
	/// `root_as_search_result_response_unchecked`.
	pub fn root_as_search_result_response_with_opts<'b, 'o>(
		opts: &'o flatbuffers::VerifierOptions,
		buf: &'b [u8],
	) -> Result<SearchResultResponse<'b>, flatbuffers::InvalidFlatbuffer> {
		flatbuffers::root_with_opts::<SearchResultResponse<'b>>(opts, buf)
	}
	#[inline]
	/// Verifies, with the given verifier options, that a buffer of
	/// bytes contains a size prefixed `SearchResultResponse` and returns
	/// it. Note that verification is still experimental and may not
	/// catch every error, or be maximally performant. For the
	/// previous, unchecked, behavior use
	/// `root_as_search_result_response_unchecked`.
	pub fn size_prefixed_root_as_search_result_response_with_opts<'b, 'o>(
		opts: &'o flatbuffers::VerifierOptions,
		buf: &'b [u8],
	) -> Result<SearchResultResponse<'b>, flatbuffers::InvalidFlatbuffer> {
		flatbuffers::size_prefixed_root_with_opts::<SearchResultResponse<'b>>(opts, buf)
	}
	#[inline]
	/// Assumes, without verification, that a buffer of bytes contains a SearchResultResponse and returns it.
	/// # Safety
	/// Callers must trust the given bytes do indeed contain a valid `SearchResultResponse`.
	pub unsafe fn root_as_search_result_response_unchecked(buf: &[u8]) -> SearchResultResponse {
		flatbuffers::root_unchecked::<SearchResultResponse>(buf)
	}
	#[inline]
	/// Assumes, without verification, that a buffer of bytes contains a size prefixed SearchResultResponse and returns it.
	/// # Safety
	/// Callers must trust the given bytes do indeed contain a valid size prefixed `SearchResultResponse`.
	pub unsafe fn size_prefixed_root_as_search_result_response_unchecked(buf: &[u8]) -> SearchResultResponse {
		flatbuffers::size_prefixed_root_unchecked::<SearchResultResponse>(buf)
	}
	#[inline]
	pub fn finish_search_result_response_buffer<'a, 'b, A: flatbuffers::Allocator + 'a>(
		fbb: &'b mut flatbuffers::FlatBufferBuilder<'a, A>,
		root: flatbuffers::WIPOffset<SearchResultResponse<'a>>,
	) {
		fbb.finish(root, None);
	}

	#[inline]
	pub fn finish_size_prefixed_search_result_response_buffer<'a, 'b, A: flatbuffers::Allocator + 'a>(
		fbb: &'b mut flatbuffers::FlatBufferBuilder<'a, A>,
		root: flatbuffers::WIPOffset<SearchResultResponse<'a>>,
	) {
		fbb.finish_size_prefixed(root, None);
	}
} // pub mod TagStormDb
