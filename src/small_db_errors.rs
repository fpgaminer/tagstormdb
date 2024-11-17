use std::{backtrace::Backtrace, fmt, io::Error as IoError};


// ============================================================================
// DbError
// ============================================================================
pub enum DbError {
	CorruptDatabase(String, Backtrace),
	IoError(IoError, Backtrace),
}

impl fmt::Display for DbError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			DbError::CorruptDatabase(s, backtrace) => write!(f, "Corrupt database: {}\n{}", s, backtrace),
			DbError::IoError(e, backtrace) => write!(f, "I/O error: {}\n{}", e, backtrace),
		}
	}
}

impl fmt::Debug for DbError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			DbError::CorruptDatabase(s, backtrace) => write!(f, "CorruptDatabase({:?}, {})", s, backtrace),
			DbError::IoError(e, backtrace) => write!(f, "IoError({:?}, {})", e, backtrace),
		}
	}
}

impl std::error::Error for DbError {}

impl From<IoError> for DbError {
	fn from(e: std::io::Error) -> Self {
		DbError::IoError(e, Backtrace::capture())
	}
}

impl From<DeserializeError> for DbError {
	fn from(e: DeserializeError) -> Self {
		let backtrace = Backtrace::capture();
		match e {
			DeserializeError::IoError(e) => DbError::IoError(e, backtrace),
			DeserializeError::Custom(s) => DbError::CorruptDatabase(s, backtrace),
			DeserializeError::InvalidUtf8 => DbError::CorruptDatabase("Invalid UTF-8".to_string(), backtrace),
		}
	}
}


// ============================================================================
// DeserializerError
// ============================================================================
#[derive(Debug)]
pub enum DeserializeError {
	IoError(IoError),
	Custom(String),
	InvalidUtf8,
}

impl std::fmt::Display for DeserializeError {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		match self {
			DeserializeError::IoError(e) => write!(f, "{}", e),
			DeserializeError::Custom(s) => write!(f, "{}", s),
			DeserializeError::InvalidUtf8 => write!(f, "Invalid UTF-8"),
		}
	}
}

impl std::error::Error for DeserializeError {}

impl serde::de::Error for DeserializeError {
	fn custom<T: std::fmt::Display>(msg: T) -> Self {
		DeserializeError::Custom(msg.to_string())
	}
}

impl From<IoError> for DeserializeError {
	fn from(e: IoError) -> Self {
		DeserializeError::IoError(e)
	}
}


// ============================================================================
// SerializerError
// ============================================================================
#[derive(Debug)]
pub enum SerializeError {
	IoError(IoError),
	Custom(String),
}

impl std::fmt::Display for SerializeError {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		match self {
			SerializeError::IoError(e) => write!(f, "{}", e),
			SerializeError::Custom(s) => write!(f, "{}", s),
		}
	}
}

impl std::error::Error for SerializeError {}

impl serde::ser::Error for SerializeError {
	fn custom<T: std::fmt::Display>(msg: T) -> Self {
		SerializeError::Custom(msg.to_string())
	}
}
