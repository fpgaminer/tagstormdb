# TagStormDB

Built for Tag Machine.  Primarily an append-only database for keeping track of images and their associated tags and other metadata.  Focus is on _speed_, so it can handle very large datasets (10s of millions of images) efficiently.

This README pertains to the database "library" itself.  See [README.server.md](./README.server.md) for the server that uses this database.


## Structure

The database is split into the following components:

* image_hashes
* string_table
* logs
* small_db


Unless noted otherwise, everything is little-endian.

The database is conceptually just a log.  The program just replays the log to reconstruct the current state of the database in memory.  The log consists of actions taken on the database, such as adding images, tagging images, removing tags, etc.  When an action is taken locks are acquired, the state is updated and the logs written to disk, and then the locks are released.  This ensures that the database is always in a consistent state.  The locks are RwLocks, allowing multiple readers at a time, but only one writer at a time.

When adding an image, its 32 byte hash is added to the Image Hashes table if not in there already, and then an AddImage action is performed, which marks that image as active.  When removed, a RemoveImage action is performed, marking it as inactive.

When adding a tag, the tag string is added to the String Table if not in there already, and then an AddTag action is performed, which adds the tag to the database.  When removed, a RemoveTag action is performed, marking the tag as inactive.

When tagging an image, an AddImageTag action is performed, associating the image and tag.  When removing a tag from an image, a RemoveImageTag action is performed.

Attributes are key/value pairs associated with images.  Attribute keys and values are stored in the String Table and referenced by their string IDs in the log.  Attributes are added and removed using AddAttribute and RemoveAttribute actions.  An existing attribute can be updated by removing it and then adding it again with the new value.  There can be multiple values associated with a single attribute key for an image.  This allows attributes like "source" to have multiple sources associated with an image.  RemoveAttributes action specifies the specific key/value pair to remove because of this.  It is up to the external application using TagStormDB to treat any given attribute as "singular" or not; i.e. should a given attribute key only have one value associated with it, or can it have multiple values.


### Image Hashes

This can be thought of as a simple 32-byte image hash to u64 table.  It is append only.  Normally images would be referenced by their 32 byte hash, but that gets expensive.  This table allows each image to instead have a unique u64 identifier, which can be converted back and forth to the respective 32 byte hash using this table.

The binary format is simple, no header, just a sequence of image hashes.  Each image hash is stored as 33 bytes; the 32 byte hash followed by a single bye checksum.  The checksum is the least significant byte of the xxh3_64 hash of the 32 byte image hash.

Each entry in the table is assigned an index, starting at 0.


### String Table

This table is similar in spirit to the Image Hashes table.  It maps strings to unique u64 identifiers, allowing the reference of strings by their u64 for storage efficiency.  It is append only.

The binary format is simple, no header, just a sequence of strings.  Each string is stored as: vli length, utf8 string bytes, u16 checksum.  The checksum is the least significant 16 bits of the xxh3_64 hash of the string bytes.

Each entry in the table is assigned an index, starting at 0.


### Logs

This is the real meat of the database.  It is an append only log of all actions taken on the database, such as adding images, tagging images, removing tags, etc.  The log is used to reconstruct the current state of the database into memory on startup.


#### Binary Format

The log file starts with a u64 suggesting how many log entries are in the file.  It does _not_ need to be accurate; it is a convenience for pre-allocating memory, displaying a progress bar, etc.  It is followed immediately by a sequence of log entries.


#### Log Entry Format

* timestamp: i64 (unix timestamp in milliseconds)
* user_id: u64 (user who performed the action)
* action type: u8
* action data: [varies by action type]
* checksum: u8

The checksum is the least significant byte of the xxh3_64 hash of everything except the checksum itself.

#### Action Types

* 0 = Add Tag
  - tag length: vli
  - tag: [utf8 bytes]
* 1 = Remove Tag
  - tag_id: vli
* 2 = Add Image
  - image_id: vli
* 3 = Remove Image
  - image_id: vli
* 4 = Add Image Tag
  - image_id: vli
  - tag_id: vli
* 5 = Remove Image Tag
  - image_id: vli
  - tag_id: vli
* 6 = Add Attribute
  - image_id: vli
  - attribute_key_id: vli
  - attribute_value_id: vli
* 7 = Remove Attribute
  - image_id: vli
  - attribute_key_id: vli
  - attribute_value_id: vli


### Small DB

We need some "normal" database capabilities for things like user accounts, user tokens, work queues, etc.  Small DB implements a simple database that _isn't_ append only like the rest of TagStormDB.

Small DB is completely synchronous. Only one mutable reference can exist at a time, which means reads block writes, only one write at a time, etc.  The database manages this by holding a Mutex of `SmallDb`.

Rows in Small DB are referenced by their position in the file (u64).  This becomes the rows "RowId", and is used when calling SmallDb's methods to delete, or update a row.

During start up the database will read the entire SmallDb into memory.  When a record needs to be added, changed, deleted, locks are engaged on the relavant memory structures and the SmallDb at the same time, changes are written to disk and then to memory, and then locks are released.  This is a simple way to keep things ACID, leave reading fast, and minimize the responsability of the SmallDb code itself.

SmallDb has no concept of columns, data format, etc.  It only stores a single binary blob per row.  Using generics it will serialize and deserialize any fixed structure when rows are read or written.  The database implements this type as an enum so that rows can contain different types of data (right now User, UserToken, or Task).


#### Binary Format

The SmallDb file has no header.  It is simply a sequence of rows.


#### Row Format

* length+active: u32 (len << 1 | active bit)
* data: [u8; length-2]
* checksum: u16

Length does not include the length field itself, but otherwise specifies the length of the entire binary row data up to and including the checksum.  This is such that if you read the length field and then read that many bytes, you are now ready to read the next row's length field.

Checksum is calculated using xxh3_64 and truncated to the least significant 16 bits.  It covers only `data`.

The active bit specifies whether the row is active (1) or deleted (0).  Deleted rows are not removed from the file, but are skipped when reading.  (Their checksums do not necessarily need to be valid).


#### WAL Format

* write position: u64
* write length: u32
* data: [u8; write length]
* ...
* (write position, write length, data) repeated for each write
* ...
* WAL checksum: u16

Checksum is calculated using xxh3_64 and truncated to the least significant 16 bits.
WAL checksum covers everything except the WAL checksum itself.

Whenever a write or set of writes is going to be made to SmallDb's file it is first recorded into the WAL, synced to disk, and then the actual write(s) are made to SmallDb's file, and synced to disk.  After a successful write the WAL is cleared.  On startup SmallDb will look for and replay any existing WAL before loading the database file itself.

The WAL format is kept simple.  It's essentially just a list of writes to make (where, how much, data).


#### Row Manipulation

When inserting a row a free slot is found in the file that will be big enough.  i.e. if there is an existing deleted row that is at least as large as the new row, it will be reused.  If no such row exists the new row is appended to the end of the file.  The planned writes are recorded to the WAL first, as described above.

When deleting a row the active bit is cleared.  i.e. only a single byte is written.  The planned write is recorded to the WAL first, as described above.

When updating a row if the new row is smaller than or equal to the existing row it is simply overwritten in place.  If the new row is larger than the existing row the existing row is marked deleted, and a new row is inserted (as per the insert procedure).  The one or more writes are recorded to the WAL first, as described above, ensure the entire operation is atomic.


#### Serialization Format

Since SmallDb only stores binary blobs, it takes advantage of the serde framework to serialize and deserialize arbitrary (but fixed) data structures.  The data format of this serialization is binary to minimize size and maximize speed.  Below are how different types are serialized.

* u8, u16, u32, u64, i8, i16, i32, i64: little-endian binary
* f32, f64: little-endian binary
* bool: u8 (0 = false, 1 = true)
* String: vli length followed by length UTF-8 bytes
* bytes: vli length followed by length bytes
* Option<T>: u8 (0 = None, 1 = Some) followed by T if Some
* Unit: nothing
* Unit variant: vli variant index
* Newtype struct: serialized inner type
* Newtype variant: vli variant index followed by serialized inner type
* Seq (Vec, arrays): vli length followed by serialized elements
* Map: not implemented
* Struct: serialized fields in declaration order
* Tuple: serialized elements in declaration order


vli (variable length integer): if the unsigned integer is less than or equal to 0xfc, it is written as a u8.  Failing that: if it fits within a u16 then 0xfd is written followed by the u16.  If it fits within a u32 then 0xfe is written followed by the u32.  Otherwise 0xff is written followed by the u64.
