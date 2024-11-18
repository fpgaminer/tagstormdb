use actix_web::HttpResponse;
use core::fmt::{self, Debug, Display};

use crate::auth::Scope;

/// This error type is needed so we can control how actix reports our internal errors
pub enum ServerError {
	Anyhow(anyhow::Error),
	InvalidPermissions(Scope),
}

impl actix_web::error::ResponseError for ServerError {
	fn error_response(&self) -> HttpResponse {
		match self {
			ServerError::Anyhow(_) => HttpResponse::InternalServerError().body("Internal Server Error"),
			ServerError::InvalidPermissions(scope) => HttpResponse::Forbidden().body(format!("Insufficient permissions: {}", scope)),
		}
	}
}

impl<E> From<E> for ServerError
where
	E: Into<anyhow::Error>,
{
	fn from(err: E) -> ServerError {
		ServerError::Anyhow(err.into())
	}
}

impl Debug for ServerError {
	fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
		match self {
			ServerError::Anyhow(err) => Debug::fmt(err, formatter),
			ServerError::InvalidPermissions(scope) => write!(formatter, "InvalidPermissions({})", scope),
		}
	}
}

impl Display for ServerError {
	fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
		match self {
			ServerError::Anyhow(err) => Display::fmt(err, formatter),
			ServerError::InvalidPermissions(scope) => Display::fmt(scope, formatter),
		}
	}
}
