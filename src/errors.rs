#[derive(Debug)]
pub enum DatabaseError {
	IoError(std::io::Error),
	FromUtf8Error(std::string::FromUtf8Error),
	ChecksumMismatch { expected: u64, actual: u64 },
	CorruptedDatabase,
	ImageNotFound,
	ScopeParseError(globset::Error),
	UserAlreadyExists,
	UserDoesNotExist,
}

impl From<std::io::Error> for DatabaseError {
	fn from(e: std::io::Error) -> Self {
		Self::IoError(e)
	}
}

impl From<std::string::FromUtf8Error> for DatabaseError {
	fn from(e: std::string::FromUtf8Error) -> Self {
		Self::FromUtf8Error(e)
	}
}

impl std::fmt::Display for DatabaseError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::IoError(e) => write!(f, "IO error: {}", e),
			Self::FromUtf8Error(e) => write!(f, "FromUtf8Error: {}", e),
			Self::ChecksumMismatch { expected, actual } => write!(f, "Checksum mismatch: expected {}, actual {}", expected, actual),
			Self::CorruptedDatabase => write!(f, "Corrupted database"),
			Self::ImageNotFound => write!(f, "Image not found"),
			Self::ScopeParseError(e) => write!(f, "Scope parse error: {}", e),
			Self::UserAlreadyExists => write!(f, "User already exists"),
			Self::UserDoesNotExist => write!(f, "User does not exist"),
		}
	}
}

impl std::error::Error for DatabaseError {}
