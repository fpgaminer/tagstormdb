use actix_web::{dev::Payload, error::ErrorUnauthorized, web, Error, FromRequest, HttpRequest};
use futures::Future;
use globset::GlobSet;
use std::{pin::Pin, sync::Arc};
use tagstormdb::{Database, UserId, UserToken};


pub struct AuthenticatedUser {
	pub id: UserId,
	//pub token: UserToken,
	//pub username: String,
	pub scope_matcher: GlobSet,
}

impl AuthenticatedUser {
	pub fn has_scope(&self, scope: &str) -> bool {
		self.scope_matcher.is_match(scope)
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
