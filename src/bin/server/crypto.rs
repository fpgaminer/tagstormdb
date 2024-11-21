use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, seq::SliceRandom};
use sha2::Sha512;
use tagstormdb::LoginKey;


/// Authenticate data using an HMAC-SHA512 construct
/// The data is expected to be a byte array with a 32-byte hmac at the end
/// AAD is additional authenticated data, which can be used to make the authentication context more specific
///
/// Returns the authenticated data if the authentication was successful
/// Otherwise returns None
pub(crate) fn authenticate_data<'a>(aad: &[u8], data: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
	assert!(key.len() >= 32);

	// We expect data to be arbitrary data with a 32-byte hmac at the end
	if data.len() < 32 {
		return None;
	}

	let (data, stored_hmac) = data.split_at(data.len() - 32);
	assert_eq!(stored_hmac.len(), 32);

	// Compute the hmac
	let mut hmac = Hmac::<Sha512>::new_from_slice(key).expect("unexpected");
	hmac.update(aad);
	hmac.update(data);
	hmac.update(&u64::try_from(aad.len()).expect("length did not fit into u64").to_le_bytes());
	hmac.update(&u64::try_from(data.len()).expect("length did not fit into u64").to_le_bytes());

	// Truncate to 256 bits
	let computed_hmac = hmac.finalize().into_bytes();
	assert_eq!(computed_hmac.len(), 64);
	let computed_hmac = &computed_hmac[0..32];

	// Constant time compare
	use ::subtle::ConstantTimeEq;

	if computed_hmac.ct_eq(stored_hmac).into() {
		Some(data)
	} else {
		None
	}
}


/// Derive a key from a master key
pub(crate) fn derive_key(master_key: &[u8], purpose: &[u8]) -> [u8; 64] {
	assert!(master_key.len() >= 32);
	assert!(!purpose.is_empty());

	let mut hmac = Hmac::<Sha512>::new_from_slice(master_key).expect("unexpected");
	hmac.update(purpose);
	let key = hmac.finalize().into_bytes();

	key.into()
}


/// Generate a random 20-character password
pub(crate) fn random_password() -> String {
	const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
	                         abcdefghijklmnopqrstuvwxyz\
	                         0123456789";
	const PASSWORD_LEN: usize = 20;
	let password = (0..PASSWORD_LEN)
		.map(|_| {
			let idx = CHARSET.choose(&mut OsRng).unwrap();
			*idx as char
		})
		.collect();

	password
}


/// Derive the login key from a username and password
pub(crate) fn login_key_from_password(username: &str, password: &str) -> LoginKey {
	let mut login_key = LoginKey([0; 32]);
	let scrypt_params = scrypt::Params::new(16, 8, 1, login_key.0.len()).expect("unexpected");
	scrypt::scrypt(password.as_bytes(), username.as_bytes(), &scrypt_params, &mut login_key.0).expect("unexpected");

	login_key
}
