mod auth;
mod server_error;
mod tags;

use std::{
	collections::{BTreeMap, BTreeSet, HashMap},
	path::{Path, PathBuf},
	sync::Arc,
};

use actix_cors::Cors;
use actix_files::NamedFile;
use actix_web::{
	body::MessageBody,
	dev::{ServiceFactory, ServiceRequest, ServiceResponse},
	middleware,
	web::{self, Data},
	App, HttpRequest, HttpResponse, HttpServer,
};
use anyhow::Context;
use auth::AuthenticatedUser;
use clap::Parser;
use env_logger::Env;
use image::{imageops, ImageReader};
use rand::{rngs::OsRng, Rng};
use serde::{ser::Serializer, Deserialize, Deserializer, Serialize};
use serde_json::json;
use server_error::ServerError;
use sha2::{Digest, Sha256};
use tags::TagMappings;
use tagstormdb::{
	database::StateUpdateResult, errors::DatabaseError, search::TreeSort, AttributeKeyId, AttributeValueId, Database, ImageHash, ImageId, LoginKey, TagId,
	UserId, UserToken,
};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};


#[derive(Parser, Debug)]
#[command()]
struct Args {
	/// IP address to bind to.
	#[arg(long, default_value = "127.0.0.1")]
	ip: String,

	/// Port to bind to (default: 8086).
	#[arg(long, default_value = "8186")]
	port: u16,

	/// Path to the image directory.
	#[arg(long, default_value = "images")]
	image_dir: PathBuf,

	/// Path to the database directory.
	#[arg(long, default_value = "db")]
	db_dir: PathBuf,
}


#[derive(Clone)]
struct ServerData {
	image_dir: PathBuf,
	server_secret: [u8; 32],
}


#[actix_web::main]
async fn main() -> Result<(), anyhow::Error> {
	// Env logger
	env_logger::Builder::from_env(Env::default().default_filter_or("warn,actix_web=debug,tag_rust_db=debug,actix_server=info,server=info")).init();

	// Parse command line arguments
	let args = Args::parse();

	// Read tag mappings
	let tag_mappings = tags::get_tag_mappings();

	// Load database
	let database = Arc::new(Database::open(&args.db_dir, true).await?);

	// Load server secret
	let server_secret = load_server_secret(&args.db_dir).await?;

	// Setup HTTP server
	let server_data = ServerData {
		image_dir: args.image_dir,
		server_secret,
	};

	let server = HttpServer::new(move || build_app(database.clone(), tag_mappings.clone(), server_data.clone()))
		.bind((args.ip.as_str(), args.port))?
		.run();

	log::info!("Server running at http://{}:{}", args.ip, args.port);

	server.await?;

	Ok(())
}


async fn load_server_secret<P: AsRef<Path>>(path: P) -> Result<[u8; 32], anyhow::Error> {
	let secret_path = path.as_ref().join("server_secret.bin");

	let mut secret_file = match tokio::fs::OpenOptions::new().read(true).open(&secret_path).await {
		Ok(file) => file,
		Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
			// Generate a new secret
			let secret: [u8; 32] = OsRng.gen();
			let mut file = tokio::fs::OpenOptions::new().write(true).create_new(true).open(&secret_path).await?;
			file.write_all(&secret).await?;
			file.sync_all().await?;
			file.seek(std::io::SeekFrom::Start(0)).await?;
			file
		},
		Err(err) => return Err(err.into()),
	};

	let mut secret = [0; 32];
	secret_file.read_exact(&mut secret).await?;

	Ok(secret)
}


fn build_app(
	db: Arc<Database>,
	tag_mappings: TagMappings,
	server_data: ServerData,
) -> App<impl ServiceFactory<ServiceRequest, Config = (), Response = ServiceResponse<impl MessageBody>, Error = actix_web::Error, InitError = ()>> {
	let logger = actix_web::middleware::Logger::default();
	let cors = Cors::default()
		.allowed_origin("http://localhost:1420")
		.allowed_origin("http://localhost:4173")
		.allow_any_method()
		.allow_any_header()
		.max_age(3600);

	let tag_mappings = Data::new(tag_mappings);

	App::new()
		.wrap(logger)
		.wrap(cors)
		.wrap(middleware::Compress::default())
		.app_data(Data::new(db))
		.app_data(tag_mappings)
		.app_data(Data::new(server_data))
		.service(get_tag_mappings)
		.service(list_tags)
		.service(add_tag)
		.service(remove_tag)
		.service(get_image)
		.service(get_image_data)
		.service(add_image)
		.service(remove_image)
		.service(add_image_attribute)
		.service(remove_image_attribute)
		.service(tag_image)
		.service(untag_image)
		.service(login)
		.service(change_login_key)
		.service(user_info)
		.service(create_new_user_token)
		.service(invalidate_user_token)
		.service(list_user_tokens)
		.service(change_user_scopes)
		.service(search_images)
}


#[derive(Serialize)]
struct TagMetadata {
	id: u64,
	name: String,
	active: bool,
}


/// List all tags.
#[actix_web::get("/tags")]
async fn list_tags(db: Data<Arc<Database>>, _user: AuthenticatedUser) -> Result<HttpResponse, ServerError> {
	let tags_lock = db.tags.read().await;
	let mut tags = Vec::new();
	for (id, (name, entry)) in tags_lock.iter().enumerate() {
		tags.push(TagMetadata {
			id: id as u64,
			name: name.clone(),
			active: entry.active,
		});
	}

	Ok(HttpResponse::Ok().json(tags))
}


/// Get tag mappings.
#[actix_web::get("/tag_mappings")]
async fn get_tag_mappings(tag_mappings: Data<TagMappings>, _user: AuthenticatedUser) -> Result<HttpResponse, ServerError> {
	Ok(HttpResponse::Ok().json(tag_mappings.as_ref()))
}


/// Add a tag to the database.
#[actix_web::post("/tags/{name}")]
async fn add_tag(db: Data<Arc<Database>>, path: web::Path<(String,)>, user: AuthenticatedUser) -> Result<HttpResponse, ServerError> {
	// Check permissions
	if !user.has_scope("tags/add") {
		return Ok(HttpResponse::Forbidden().body("Insufficient permissions: tags/add"));
	}

	let (tag_name,) = path.into_inner();

	let added = db.add_tag(tag_name, user.id).await?;

	if added {
		Ok(HttpResponse::Created().finish())
	} else {
		Ok(HttpResponse::Conflict().body("Tag already exists"))
	}
}


/// Remove a tag from the database.
#[actix_web::delete("/tags/{name}")]
async fn remove_tag(db: Data<Arc<Database>>, path: web::Path<(String,)>, user: AuthenticatedUser) -> Result<HttpResponse, ServerError> {
	// Check permissions
	if !user.has_scope("tags/remove") {
		return Ok(HttpResponse::Forbidden().body("Insufficient permissions: tags/remove"));
	}

	let (tag_name,) = path.into_inner();
	let tag_id = match db.get_tag_id(&tag_name).await {
		Some(tag_id) => tag_id,
		None => return Ok(HttpResponse::NotFound().finish()),
	};

	if db.remove_tag(tag_id, user.id).await? {
		// Successfully removed
		Ok(HttpResponse::NoContent().finish())
	} else {
		Ok(HttpResponse::NotFound().finish())
	}
}


#[derive(Serialize)]
struct ImageMetadata<'a> {
	id: ImageId,
	hash: ImageHash,
	active: bool,
	tags: HashMap<TagId, UserId>,
	attributes: HashMap<&'a str, HashMap<&'a str, UserId>>,
}

/// Get image metadata
/// identifier can be either the image hash or the image ID.
#[actix_web::get("/images/{identifier}/metadata")]
async fn get_image(db: Data<Arc<Database>>, path: web::Path<(ImageIdentifier,)>, _user: AuthenticatedUser) -> Result<HttpResponse, ServerError> {
	// Permissions: Any authenticated user can view image metadata

	let (identifier,) = path.into_inner();
	let images_lock = db.images.read().await;

	let image = match identifier {
		ImageIdentifier::Hash(hash) => db.get_image_by_hash(&hash, &images_lock).await,
		ImageIdentifier::Id(id) => db.get_image_by_id(id, &images_lock).await,
	};

	let image = match image {
		Some(image) => image,
		None => return Ok(HttpResponse::NotFound().finish()),
	};

	let strings_lock = db.string_table.read().await;
	let mut attributes = HashMap::new();

	for (key_id, values) in image.attributes.iter() {
		let key = db.get_string_by_id((*key_id).into(), &strings_lock).await.unwrap();
		let entry = attributes.entry(key).or_insert_with(HashMap::new);

		for (value_id, user_id) in values.iter() {
			let value = db.get_string_by_id((*value_id).into(), &strings_lock).await.unwrap();
			entry.insert(value, *user_id);
		}
	}

	Ok(HttpResponse::Ok().json(ImageMetadata {
		id: image.id,
		hash: image.hash,
		active: image.active,
		tags: image.tags.clone(),
		attributes,
	}))
}


#[derive(Deserialize)]
struct GetImageQuery {
	size: Option<u32>,
}

/// Get image data
#[actix_web::get("/images/{identifier}")]
async fn get_image_data(
	req: HttpRequest,
	db: Data<Arc<Database>>,
	server_data: Data<ServerData>,
	path: web::Path<(ImageIdentifier,)>,
	query: web::Query<GetImageQuery>,
	_user: AuthenticatedUser,
) -> Result<HttpResponse, ServerError> {
	// Permissions: Any authenticated user can view images

	let (identifier,) = path.into_inner();
	let images_lock = db.images.read().await;
	let image = match identifier {
		ImageIdentifier::Hash(hash) => db.get_image_by_hash(&hash, &images_lock).await,
		ImageIdentifier::Id(id) => db.get_image_by_id(id, &images_lock).await,
	};

	let image = match image {
		Some(image) => image,
		None => return Ok(HttpResponse::NotFound().finish()),
	};

	// Check if the image is active
	if !image.active {
		return Ok(HttpResponse::NotFound().finish());
	}

	let hash_str = hex::encode(image.hash.0);
	let image_path = server_data.image_dir.join(&hash_str[0..2]).join(&hash_str[2..4]).join(&hash_str);

	// Check if the image exists
	if !image_path.exists() {
		return Err(anyhow::anyhow!("Missing image file {}", image_path.display()).into());
	}

	if let Some(size) = query.size {
		if size > 4096 {
			return Ok(HttpResponse::BadRequest().body("Size too large"));
		}

		let resized_image = resize_image(&image_path, size)?;
		return Ok(HttpResponse::Ok().append_header(("Content-Type", "image/webp")).body(resized_image));
	}

	// Read the first 32 bytes so we can guess the type
	let mut file = tokio::fs::File::open(&image_path).await?;
	let mut buffer = [0; 32];
	file.read_exact(&mut buffer).await?;

	// Guess the image type
	let format = image::guess_format(&buffer).ok().map(|f| f.to_mime_type());
	let mime: mime::Mime = format.unwrap_or("application/octet-stream").parse().unwrap();

	let file = NamedFile::open(image_path)?.set_content_type(mime);

	Ok(file.into_response(&req))
}


/// Add an image to the database
#[actix_web::post("/images/{hash}")]
async fn add_image(
	db: Data<Arc<Database>>,
	server_data: Data<ServerData>,
	path: web::Path<(ImageHash,)>,
	user: AuthenticatedUser,
) -> Result<HttpResponse, ServerError> {
	// Check permissions
	if !user.has_scope("images/add") {
		return Ok(HttpResponse::Forbidden().body("Insufficient permissions: images/add"));
	}

	let (hash,) = path.into_inner();
	let hash_str = hex::encode(hash.0);
	let image_path = server_data.image_dir.join(&hash_str[0..2]).join(&hash_str[2..4]).join(&hash_str);

	// Check if the image exists
	if !image_path.exists() {
		return Ok(HttpResponse::NotFound().body("Image not found"));
	}

	// Check that the hash matches
	let computed_hash = {
		let mut file = tokio::fs::File::open(&image_path).await?;
		let mut buffer = [0; 4096];
		let mut hasher = Sha256::new();
		loop {
			let n = file.read(&mut buffer).await?;
			if n == 0 {
				break;
			}
			hasher.update(&buffer[..n]);
		}

		ImageHash(hasher.finalize().into())
	};

	if computed_hash != hash {
		return Ok(HttpResponse::BadRequest().body("Hash mismatch"));
	}

	if db.add_image(hash, user.id).await? {
		// Successfully added
		Ok(HttpResponse::Created().finish())
	} else {
		Ok(HttpResponse::Conflict().finish())
	}
}


/// Remove an image from the database
#[actix_web::delete("/images/{identifier}")]
async fn remove_image(db: Data<Arc<Database>>, path: web::Path<(ImageIdentifier,)>, user: AuthenticatedUser) -> Result<HttpResponse, ServerError> {
	// Check permissions
	if !user.has_scope("images/remove") {
		return Ok(HttpResponse::Forbidden().body("Insufficient permissions: images/remove"));
	}

	let (identifier,) = path.into_inner();
	let images_lock = db.images.read().await;
	let image = match identifier {
		ImageIdentifier::Hash(hash) => db.get_image_by_hash(&hash, &images_lock).await,
		ImageIdentifier::Id(id) => db.get_image_by_id(id, &images_lock).await,
	};

	let image = match image {
		Some(image) => image,
		None => return Ok(HttpResponse::NotFound().finish()),
	};

	if db.remove_image(image.id, user.id).await? {
		// Successfully removed
		Ok(HttpResponse::NoContent().finish())
	} else {
		Ok(HttpResponse::NotFound().finish())
	}
}


/// Add a tag to an image
#[actix_web::post("/images/{image}/tags/{tag}")]
async fn tag_image(db: Data<Arc<Database>>, path: web::Path<(ImageIdentifier, TagIdentifier)>, user: AuthenticatedUser) -> Result<HttpResponse, ServerError> {
	// Check permissions
	if !user.has_scope("images/tags/add") {
		return Ok(HttpResponse::Forbidden().body("Insufficient permissions: images/tags/add"));
	}

	let (image, tag) = path.into_inner();
	let image_id = match image {
		ImageIdentifier::Hash(hash) => match db.get_image_id(&hash).await {
			Some(id) => id,
			None => return Ok(HttpResponse::NotFound().body("Image not found")),
		},
		ImageIdentifier::Id(id) => id,
	};
	let tag_id = match tag {
		TagIdentifier::Name(name) => match db.get_tag_id(&name).await {
			Some(id) => id,
			None => return Ok(HttpResponse::NotFound().body("Tag not found")),
		},
		TagIdentifier::Id(id) => id,
	};

	match db.add_image_tag(image_id, tag_id, user.id).await? {
		StateUpdateResult::Updated(_) => {
			// Successfully tagged
			Ok(HttpResponse::Created().finish())
		},
		StateUpdateResult::NoOp => {
			// Already tagged
			Ok(HttpResponse::Conflict().finish())
		},
		StateUpdateResult::ErrorImageDoesNotExist => {
			// Image not found
			Ok(HttpResponse::NotFound().body("Image not found"))
		},
		StateUpdateResult::ErrorTagDoesNotExist => {
			// Tag not found
			Ok(HttpResponse::NotFound().body("Tag not found"))
		},
	}
}


/// Remove a tag from an image
#[actix_web::delete("/images/{image}/tags/{tag}")]
async fn untag_image(db: Data<Arc<Database>>, path: web::Path<(ImageIdentifier, TagIdentifier)>, user: AuthenticatedUser) -> Result<HttpResponse, ServerError> {
	// Check permissions
	if !user.has_scope("images/tags/remove") {
		return Ok(HttpResponse::Forbidden().body("Insufficient permissions: images/tags/remove"));
	}

	let (image, tag) = path.into_inner();
	let image_id = match image {
		ImageIdentifier::Hash(hash) => match db.get_image_id(&hash).await {
			Some(id) => id,
			None => return Ok(HttpResponse::NotFound().body("Image not found")),
		},
		ImageIdentifier::Id(id) => id,
	};
	let tag_id = match tag {
		TagIdentifier::Name(name) => match db.get_tag_id(&name).await {
			Some(id) => id,
			None => return Ok(HttpResponse::NotFound().body("Tag not found")),
		},
		TagIdentifier::Id(id) => id,
	};

	match db.remove_image_tag(image_id, tag_id, user.id).await? {
		StateUpdateResult::Updated(_) => {
			// Successfully untagged
			Ok(HttpResponse::NoContent().finish())
		},
		StateUpdateResult::NoOp => {
			// Not tagged
			Ok(HttpResponse::Conflict().finish())
		},
		StateUpdateResult::ErrorImageDoesNotExist => {
			// Image not found
			Ok(HttpResponse::NotFound().body("Image not found"))
		},
		StateUpdateResult::ErrorTagDoesNotExist => {
			// Tag not found
			Ok(HttpResponse::NotFound().body("Tag not found"))
		},
	}
}


/// Add an attribute to an image
#[actix_web::post("/images/{image}/attributes/{key}/{value}/{singular}")]
async fn add_image_attribute(
	db: Data<Arc<Database>>,
	path: web::Path<(ImageIdentifier, String, String, bool)>,
	user: AuthenticatedUser,
) -> Result<HttpResponse, ServerError> {
	// Check permissions
	if !user.has_scope("images/attributes/add") {
		return Ok(HttpResponse::Forbidden().body("Insufficient permissions: images/attributes/add"));
	}

	let (image, key, value, singular) = path.into_inner();
	let image_id = match image {
		ImageIdentifier::Hash(hash) => match db.get_image_id(&hash).await {
			Some(id) => id,
			None => return Ok(HttpResponse::NotFound().body("Image not found")),
		},
		ImageIdentifier::Id(id) => id,
	};

	let result = if singular {
		db.add_image_attribute_singular(image_id, key, value, user.id).await?
	} else {
		db.add_image_attribute(image_id, key, value, user.id).await?
	};

	match result {
		StateUpdateResult::Updated(_) => {
			// Successfully added
			Ok(HttpResponse::Created().finish())
		},
		StateUpdateResult::NoOp => {
			// Already exists
			Ok(HttpResponse::Conflict().finish())
		},
		StateUpdateResult::ErrorImageDoesNotExist => {
			// Image not found
			Ok(HttpResponse::NotFound().body("Image not found"))
		},
		StateUpdateResult::ErrorTagDoesNotExist => unreachable!(),
	}
}


/// Remove an attribute from an image
#[actix_web::delete("/images/{image}/attributes/{key}/{value}")]
async fn remove_image_attribute(
	db: Data<Arc<Database>>,
	path: web::Path<(ImageIdentifier, String, String)>,
	user: AuthenticatedUser,
) -> Result<HttpResponse, ServerError> {
	// Check permissions
	if !user.has_scope("images/attributes/remove") {
		return Ok(HttpResponse::Forbidden().body("Insufficient permissions: images/attributes/remove"));
	}

	let (image, key, value) = path.into_inner();
	let image_id = match image {
		ImageIdentifier::Hash(hash) => match db.get_image_id(&hash).await {
			Some(id) => id,
			None => return Ok(HttpResponse::NotFound().body("Image not found")),
		},
		ImageIdentifier::Id(id) => id,
	};
	let key_id: AttributeKeyId = match db.get_string_id(&key).await {
		Some(id) => id.into(),
		None => return Ok(HttpResponse::NotFound().body("Key not found")),
	};
	let value_id: AttributeValueId = match db.get_string_id(&value).await {
		Some(id) => id.into(),
		None => return Ok(HttpResponse::NotFound().body("Value not found")),
	};

	match db.remove_image_attribute(image_id, key_id, value_id, user.id).await? {
		StateUpdateResult::Updated(_) => {
			// Successfully removed
			Ok(HttpResponse::NoContent().finish())
		},
		StateUpdateResult::NoOp => {
			// Not found
			Ok(HttpResponse::Conflict().finish())
		},
		StateUpdateResult::ErrorImageDoesNotExist => {
			// Image not found
			Ok(HttpResponse::NotFound().body("Image not found"))
		},
		StateUpdateResult::ErrorTagDoesNotExist => unreachable!(),
	}
}


#[derive(Deserialize)]
struct LoginQuery {
	username: String,
	login_key: LoginKey,
}

/// Login
#[actix_web::post("/login")]
async fn login(db: Data<Arc<Database>>, query: web::Json<LoginQuery>) -> Result<HttpResponse, ServerError> {
	let hashed_login_key = query.login_key.hash();
	let user_id = match db.authenticate_login(&query.username, hashed_login_key).await? {
		Some(user_id) => user_id,
		None => return Ok(HttpResponse::Unauthorized().body("Invalid login")),
	};

	// Create a new user token
	let user_token = db.create_user_token(user_id).await?;

	// Return the token
	Ok(HttpResponse::Ok().json(json!({
		"token": hex::encode(user_token.0),
	})))
}


/// Create a new user token
#[actix_web::post("/users/me/tokens")]
async fn create_new_user_token(db: Data<Arc<Database>>, user: AuthenticatedUser) -> Result<HttpResponse, ServerError> {
	let user_token = db.create_user_token(user.id).await?;
	Ok(HttpResponse::Created().json(json!({
		"token": hex::encode(user_token.0),
	})))
}


#[derive(Deserialize)]
struct InvalidateTokenQuery {
	token: UserToken,
}

/// Invalidate a user token
/// It seems to be recommended to use POST for sensitive queries, so we'll use that here instead of DELETE.
#[actix_web::post("/users/me/tokens/invalidate")]
async fn invalidate_user_token(db: Data<Arc<Database>>, query: web::Json<InvalidateTokenQuery>, user: AuthenticatedUser) -> Result<HttpResponse, ServerError> {
	let token_user_id = match db.get_user_id_by_token(&query.token).await {
		Some(user_id) => user_id,
		None => return Ok(HttpResponse::NotFound().body("Token not found")),
	};

	// Make sure the user is invalidating their own token
	if token_user_id != user.id {
		return Ok(HttpResponse::Forbidden().body("Token not found"));
	}

	db.invalidate_user_token(&query.token).await?;

	Ok(HttpResponse::NoContent().finish())
}


#[derive(Deserialize)]
struct ChangeLoginKeyQuery {
	new_login_key: LoginKey,
}

/// Change user login key
#[actix_web::post("/users/{user}/login_key")]
async fn change_login_key(
	db: Data<Arc<Database>>,
	path: web::Path<(String,)>,
	query: web::Json<ChangeLoginKeyQuery>,
	user: AuthenticatedUser,
) -> Result<HttpResponse, ServerError> {
	let (query_user,) = path.into_inner();

	let user_id = match query_user.as_str() {
		"me" => user.id,
		s => match s.parse().map(UserId) {
			Ok(id) => id,
			Err(_) => return Ok(HttpResponse::NotFound().finish()),
		},
	};

	// Check permissions
	let scope = format!("users/{}/login_key/change", user_id);
	if !user.has_scope(&scope) {
		return Ok(HttpResponse::Forbidden().body(format!("Insufficient permissions: {}", scope)));
	}

	let hashed_login_key = query.new_login_key.hash();
	db.change_user_login_key(user_id, hashed_login_key).await?;

	Ok(HttpResponse::NoContent().finish())
}


/// Get user info
#[actix_web::get("/users/{user}")]
async fn user_info(db: Data<Arc<Database>>, path: web::Path<(String,)>, user: AuthenticatedUser) -> Result<HttpResponse, ServerError> {
	let (query_user,) = path.into_inner();

	let user_id = match query_user.as_str() {
		"me" => user.id,
		s => match s.parse().map(UserId) {
			Ok(id) => id,
			Err(_) => return Ok(HttpResponse::NotFound().finish()),
		},
	};

	// Check permissions
	let scope = format!("users/{}/info", user_id);
	if !user.has_scope(&scope) {
		return Ok(HttpResponse::Forbidden().body(format!("Insufficient permissions: {}", scope)));
	}

	let lock = db.users.read().await;
	let (username, user) = db
		.get_user_by_id(user_id, &lock)
		.ok_or_else(|| anyhow::anyhow!("User not found after authentication"))?;

	Ok(HttpResponse::Ok().json(json!({
		"id": user_id,
		"username": username,
		"scopes": user.scopes.clone(),
	})))
}


/// List user's tokens
#[actix_web::get("/users/me/tokens")]
async fn list_user_tokens(db: Data<Arc<Database>>, user: AuthenticatedUser) -> Result<HttpResponse, ServerError> {
	let tokens = db.list_user_tokens_by_user_id(user.id).await;
	Ok(HttpResponse::Ok().json(tokens))
}


#[derive(Deserialize)]
struct ChangeUserScopesQuery {
	new_scopes: String,
}

/// Change user scopes
#[actix_web::post("/users/{user}/scopes")]
async fn change_user_scopes(
	db: Data<Arc<Database>>,
	path: web::Path<(UserId,)>,
	query: web::Json<ChangeUserScopesQuery>,
	user: AuthenticatedUser,
) -> Result<HttpResponse, ServerError> {
	let (target_user_id,) = path.into_inner();
	let new_scopes = query.0.new_scopes;

	// Check permissions
	let scope = format!("users/{}/scopes/change", target_user_id);
	if !user.has_scope(&scope) {
		return Ok(HttpResponse::Forbidden().body(format!("Insufficient permissions: {}", scope)));
	}

	match db.change_user_scopes(target_user_id, new_scopes).await {
		Ok(()) => Ok(HttpResponse::Ok().finish()),
		Err(DatabaseError::ScopeParseError(e)) => Ok(HttpResponse::BadRequest().body(format!("Invalid scope: {}", e))),
		Err(DatabaseError::UserDoesNotExist) => Ok(HttpResponse::NotFound().body("User not found")),
		Err(e) => Err(e.into()),
	}
}


#[derive(Deserialize)]
struct SearchImagesQuery {
	query: String,
}


/// Search images
#[actix_web::get("/search/images")]
async fn search_images(db: Data<Arc<Database>>, query: web::Query<SearchImagesQuery>, _user: AuthenticatedUser) -> Result<HttpResponse, ServerError> {
	// Permissions: Any authenticated user can search images

	if query.query.len() > 4096 {
		return Ok(HttpResponse::BadRequest().body("Query too large"));
	}

	let start_time = std::time::Instant::now();
	let search = match tagstormdb::search::parse_search(&query.query) {
		Ok(search) => search,
		Err(e) => return Ok(HttpResponse::BadRequest().body(format!("Invalid search query: {}", e))),
	};

	let results = match search.expression.execute(&db).await {
		Ok(results) => results,
		Err(e) => return Ok(HttpResponse::InternalServerError().body(format!("Error executing search: {}", e.message))),
	};
	log::warn!("Query \"\"\"{}\"\"\" took {:?}ms", query.query, start_time.elapsed().as_millis());

	let images_lock = db.images.clone();
	let result = tokio::task::spawn_blocking(move || {
		let images_lock = images_lock.blocking_read();
		let mut output = Vec::new();
		let mut serializer = serde_json::Serializer::new(&mut output);

		match search.sort {
			Some(TreeSort::Id) => {
				let results: BTreeSet<ImageId> = results.into_iter().collect();
				serializer.collect_seq(results.iter()).unwrap();
			},
			Some(TreeSort::Hash) => {
				let results: BTreeMap<&ImageHash, ImageId> = results.into_iter().map(|id| (images_lock.get_by_id_full(id).unwrap().0, id)).collect();
				let sorted_ids = results.values();
				serializer.collect_seq(sorted_ids).unwrap();
			},
			None => serializer.collect_seq(results.into_iter()).unwrap(),
		};

		output
	})
	.await
	.unwrap();

	return Ok(HttpResponse::Ok().content_type("application/json").body(result));
}


// TODO: create account
// TODO: imgops_upload
// TODO: upload


enum ImageIdentifier {
	Hash(ImageHash),
	Id(ImageId),
}

impl<'de> Deserialize<'de> for ImageIdentifier {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		let identifier = String::deserialize(deserializer)?;

		// Try to parse as a hash if the length matches
		if identifier.len() == 64 {
			let mut image_hash = [0u8; 32];
			if hex::decode_to_slice(&identifier, &mut image_hash).is_ok() {
				return Ok(Self::Hash(ImageHash(image_hash)));
			}
		}

		// Try to parse as an ID
		match identifier.parse() {
			Ok(id) => Ok(Self::Id(ImageId(id))),
			Err(_) => Err(serde::de::Error::custom("Invalid image identifier. Must be a hash or an ID")),
		}
	}
}


enum TagIdentifier {
	Name(String),
	Id(TagId),
}

impl<'de> Deserialize<'de> for TagIdentifier {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		let identifier = String::deserialize(deserializer)?;

		// Try to parse as an ID
		match identifier.parse() {
			Ok(id) => Ok(Self::Id(TagId(id))),
			Err(_) => Ok(Self::Name(identifier)),
		}
	}
}


fn resize_image(path: &Path, max_side: u32) -> Result<Vec<u8>, anyhow::Error> {
	let img = ImageReader::open(path)?
		.with_guessed_format()
		.context("Error guessing image format")?
		.decode()
		.context("Error decoding image")?;

	let img = img.resize(max_side, max_side, imageops::FilterType::Lanczos3);

	assert!(img.width() <= max_side && img.height() <= max_side && (img.width() == max_side || img.height() == max_side));

	let mut buffer = Vec::new();
	let encoder = image::codecs::webp::WebPEncoder::new_lossless(&mut buffer);
	img.write_with_encoder(encoder).context("Error encoding image")?;

	Ok(buffer)
}
