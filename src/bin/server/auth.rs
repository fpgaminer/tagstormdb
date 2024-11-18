use actix_web::{dev::Payload, error::ErrorUnauthorized, web, Error, FromRequest, HttpRequest};
use futures::Future;
use globset::GlobSet;
use std::{fmt, pin::Pin, sync::Arc};
use tagstormdb::{Database, UserId, UserToken};

use crate::server_error::ServerError;


pub struct AuthenticatedUser {
	pub id: UserId,
	//pub token: UserToken,
	//pub username: String,
	pub scope_matcher: GlobSet,
}

/// All available scopes
/// Formatted as "method/path", mostly
/// The most powerful scope is "post/users/*/scopes", which allows changing the scope of any user, making the user an admin
/// post/users/{id}/tokens let's a user login
pub enum Scope {
	/// Can add tags to the database
	TagsAdd,
	/// Can remove tags from the database
	TagsRemove,
	/// Can add images to the database
	ImagesAdd,
	/// Can remove images from the database
	ImagesRemove,
	/// Can add tags to images
	ImagesTagsAdd,
	/// Can remove tags from images
	ImagesTagsRemove,
	/// Can add attributes to images
	ImagesAttributesAdd,
	/// Can remove attributes from images
	ImagesAttributesRemove,
	/// Can change the login key of the user with the given ID
	UsersLoginKeyChange(UserId),
	/// Can create user tokens
	UsersTokensCreate(UserId),
	/// Can delete user tokens
	UsersTokensDelete(UserId),
	/// Can view user info
	UsersInfo(UserId),
	/// Users list
	UsersList,
	/// Can change user scope
	UsersScopesChange(UserId),
	/// Can use the Imgops API
	ImagesImgops,
	/// Can upload images
	ImagesUpload,
	/// Can list user tokens
	UsersTokensList(UserId),
}

impl Scope {
	pub fn as_string(&self) -> String {
		match self {
			Scope::TagsAdd => "post/tags".to_string(),
			Scope::TagsRemove => "delete/tags".to_string(),
			Scope::ImagesAdd => "post/images".to_string(),
			Scope::ImagesRemove => "delete/images".to_string(),
			Scope::ImagesTagsAdd => "post/images/tags".to_string(),
			Scope::ImagesTagsRemove => "delete/images/tags".to_string(),
			Scope::ImagesAttributesAdd => "post/images/attributes".to_string(),
			Scope::ImagesAttributesRemove => "delete/images/attributes".to_string(),
			Scope::UsersLoginKeyChange(id) => format!("post/users/{}/login_key", id.0),
			Scope::UsersTokensCreate(id) => format!("post/users/{}/tokens", id.0),
			Scope::UsersTokensList(id) => format!("get/users/{}/tokens", id.0),
			Scope::UsersTokensDelete(id) => format!("delete/users/{}/tokens", id.0),
			Scope::UsersInfo(id) => format!("get/users/{}", id.0),
			Scope::UsersList => "get/users".to_string(),
			Scope::UsersScopesChange(id) => format!("post/users/{}/scopes", id.0),
			Scope::ImagesImgops => "post/images/imgops".to_string(),
			Scope::ImagesUpload => "post/upload_image".to_string(),
		}
	}
}

impl fmt::Display for Scope {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "{}", self.as_string())
	}
}

impl AuthenticatedUser {
	pub fn verify_scope(&self, scope: Scope) -> Result<(), ServerError> {
		if self.scope_matcher.is_match(scope.as_string()) {
			Ok(())
		} else {
			Err(ServerError::InvalidPermissions(scope))
		}
	}
}

impl FromRequest for AuthenticatedUser {
	type Error = Error;
	type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;

	fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
		let req = req.clone();
		Box::pin(async move {
			let db = req
				.app_data::<Arc<Database>>()
				.or_else(|| req.app_data::<web::Data<Arc<Database>>>().map(|d| d.as_ref()))
				.expect("Missing Database");

			let token = req
				.headers()
				.get("Authorization")
				.and_then(|auth| auth.to_str().ok())
				// Skip "Bearer"
				.and_then(|auth| auth.split(' ').nth(1))
				// Decode as hex
				.and_then(|auth| {
					let mut user_token = UserToken([0u8; 32]);
					hex::decode_to_slice(auth, &mut user_token.0).ok()?;
					Some(user_token)
				})
				.ok_or_else(|| ErrorUnauthorized("Invalid Authorization Header"))?;

			let user_id = db.get_user_id_by_token(&token).await.ok_or_else(|| ErrorUnauthorized("Invalid Token"))?;

			let lock = db.users.read().await;
			let (_, user) = db.get_user_by_id(user_id, &lock).ok_or_else(|| ErrorUnauthorized("User Not Found"))?;

			Ok(AuthenticatedUser {
				id: user_id,
				//token,
				//username: username.clone(),
				scope_matcher: user.scopes_matcher.clone(),
			})
		})
	}
}
