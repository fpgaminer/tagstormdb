macro_rules! define_id_type {
	(
		$name:ident
		$(, from $from:ident)*
		$(, into $into:ident)*
		$(, convert $convert:ident)*
	) => {
		#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy, Serialize, Deserialize, PartialOrd, Ord)]
		#[serde(transparent)]
		pub struct $name(pub u64);

		impl From<u64> for $name {
			fn from(id: u64) -> Self {
				Self(id)
			}
		}

		impl From<usize> for $name {
			fn from(id: usize) -> Self {
				Self(id as u64)
			}
		}

		impl From<$name> for usize {
			fn from(id: $name) -> Self {
				id.0 as usize
			}
		}

		impl std::fmt::Display for $name {
			fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
				write!(f, "{}({})", stringify!($name), self.0)
			}
		}

		$(
			impl From<$from> for $name {
				fn from(id: $from) -> Self {
					Self(id.0)
				}
			}
		)*

		$(
			impl From<$name> for $into {
				fn from(id: $name) -> Self {
					Self(id.0)
				}
			}
		)*

		$(
			impl From<$convert> for $name {
				fn from(id: $convert) -> Self {
					Self(id.0)
				}
			}

			impl From<$name> for $convert {
				fn from(id: $name) -> Self {
					Self(id.0)
				}
			}
		)*
	};
}
