mod auth;
mod crypto;
#[allow(dead_code, unused_imports)]
#[path = "flatbuffers_generated.rs"]
mod flatbuffers_generated;
mod server_error;
mod tags;
mod task_queue;

use tikv_jemallocator::Jemalloc;

use std::{
	collections::{BTreeMap, BTreeSet, HashMap, HashSet},
	os::unix::fs::PermissionsExt,
	path::{Path, PathBuf},
	str::FromStr,
	sync::Arc,
};

use actix_cors::Cors;
use actix_files::NamedFile;
use actix_multipart::form::{tempfile::TempFileConfig, MultipartForm};
use actix_web::{
	body::MessageBody,
	dev::{ServiceFactory, ServiceRequest, ServiceResponse},
	middleware,
	web::{self, Data},
	App, HttpRequest, HttpResponse, HttpServer, Responder,
};
use anyhow::Context;
use auth::{AuthenticatedUser, Scope};
use clap::Parser;
use crypto::{authenticate_data, derive_key, login_key_from_password, random_password};
use data_encoding::BASE32;
use env_logger::Env;
use flatbuffers::{FlatBufferBuilder, WIPOffset};
use flatbuffers_generated::tag_storm_db as flatbuffer_types;
use image::{imageops, ImageReader};
use reqwest::Url;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::json;
use server_error::ServerError;
use sha2::{Digest, Sha256};
use tags::TagMappings;
use tagstormdb::{
	database::{parse_scopes, ImageEntry, ImagesReadGuard, ImagesRwLock, StateUpdateResult, StringTableRwLock},
	errors::DatabaseError,
	search::TreeSort,
	AttributeKeyId, AttributeValueId, Database, ImageHash, ImageId, LoginKey, TagId, UserId, UserToken,
};
use task_queue::{task_queue_acquire, task_queue_delete, task_queue_finish, task_queue_insert, task_queue_view};
use tokio::io::AsyncReadExt;


#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

const MAX_FILE_SIZE: usize = 32 * 1024 * 1024; // 32 MiB
const TASK_EXPIRATION_TIME: i64 = 10 * 60; // 10 minutes


#[derive(Parser, Debug)]
#[command()]
struct Args {
	/// IP address to bind to.
	#[arg(env, long, default_value = "127.0.0.1")]
	server_ip: String,

	/// Port to bind to (default: 8086).
	#[arg(env, long, default_value = "8186")]
	server_port: u16,

	/// Path to the image directory.
	#[arg(env, long, default_value = "images")]
	image_dir: PathBuf,

	/// Path to the upload directory.
	#[arg(env, long, default_value = "upload")]
	upload_dir: PathBuf,

	/// Path to the database directory.
	#[arg(env, long, default_value = "db")]
	db_dir: PathBuf,

	/// Path to the server secrets file.
	#[arg(env, long, default_value = "db/secrets.json")]
	secrets_path: PathBuf,

	// Can see their own user info, can change their own login key, can use imgops, can list their own user tokens, can invalidate their own user tokens
	// Notably missing: can't create a user token for themselves, i.e. can't log in
	/// Default user scopes.
	#[arg(
		env,
		long,
		default_value = "get/users/{id}, post/users/{id}/login_key, post/images/imgops, get/users/{id}/tokens, delete/users/{id}/tokens"
	)]
	default_user_scopes: String,

	/// If the user table is empty, create a default admin user with the given username.
	#[arg(env, long, default_value = "admin")]
	admin_user: String,

	/// If the user table is empty, create a default admin user with the given scopes.
	#[arg(
		env,
		long,
		default_value = "post/users/*/scopes, get/users/*, */images/tags, */images/attributes, post/images/imgops, post/upload_image, post/users/*/tokens"
	)]
	admin_scopes: String,

	/// Prediction server URL.
	#[arg(env, long)]
	prediction_server: Url,
}


#[derive(Clone)]
struct ServerData {
	image_dir: PathBuf,
	upload_dir: PathBuf,
	server_secrets: ServerSecrets,
	default_user_scopes: String,
	prediction_server: Url,
}

#[derive(Deserialize, Clone)]
struct ServerSecrets {
	#[serde(deserialize_with = "deserialize_hex")]
	server_secret: Vec<u8>,
	cf_turnstile_public: Option<String>,
	cf_turnstile_private: Option<String>,
}


#[actix_web::main]
async fn main() -> Result<(), anyhow::Error> {
	// Env logger
	env_logger::Builder::from_env(Env::default().default_filter_or("warn,actix_web=debug,tagstormdb=debug,actix_server=info,server=info")).init();

	// Parse command line arguments
	let args = Args::parse();

	// Read tag mappings
	let tag_mappings = tags::get_tag_mappings();

	// Load database
	let database = Arc::new(Database::open(&args.db_dir, true).await.context("Failed to open database")?);

	// Load server secrets
	let server_secrets = load_server_secrets(&args.secrets_path).await.context("Failed to load server secrets")?;

	// Make sure default user scopes are valid
	if parse_scopes(&args.default_user_scopes).is_err() {
		return Err(anyhow::anyhow!("Invalid default user scopes"));
	}

	// Make sure admin scopes are valid
	if parse_scopes(&args.admin_scopes).is_err() {
		return Err(anyhow::anyhow!("Invalid admin scopes"));
	}

	// Make an admin user if the user table is empty
	if database.users.read().await.is_empty() {
		let admin_password = random_password();
		let admin_login_key = login_key_from_password(&args.admin_user, &admin_password);
		let admin_hashed_login_key = admin_login_key.hash();
		let admin_user_id = database.add_user(args.admin_user, admin_hashed_login_key, args.admin_scopes).await?;
		log::warn!("Created admin user with ID {} and password {}", admin_user_id, admin_password);
	}

	// Setup HTTP server
	let server_data = ServerData {
		image_dir: args.image_dir,
		upload_dir: args.upload_dir,
		server_secrets,
		default_user_scopes: args.default_user_scopes,
		prediction_server: args.prediction_server,
	};

	let server = HttpServer::new(move || build_app(database.clone(), tag_mappings.clone(), server_data.clone()))
		.bind((args.server_ip.as_str(), args.server_port))?
		.run();

	log::info!("Server running at http://{}:{}", args.server_ip, args.server_port);

	server.await?;

	Ok(())
}


async fn load_server_secrets<P: AsRef<Path>>(path: P) -> Result<ServerSecrets, anyhow::Error> {
	let mut secret_file = tokio::fs::OpenOptions::new().read(true).open(path).await?;
	let mut data = String::new();
	secret_file.read_to_string(&mut data).await?;
	let secrets: ServerSecrets = serde_json::from_str(&data)?;

	Ok(secrets)
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
	// Ensure temporary upload files end up in our upload directory, so we can atomically move them
	let temp_file_config = TempFileConfig::default().directory(&server_data.upload_dir);

	App::new()
		.wrap(logger)
		.wrap(cors)
		.wrap(middleware::Compress::default())
		.app_data(Data::new(db))
		.app_data(tag_mappings)
		.app_data(Data::new(server_data))
		.app_data(temp_file_config)
		.service(get_tag_mappings)
		.service(list_tags)
		.service(add_tag)
		.service(remove_tag)
		.service(get_image)
		.service(get_image_data)
		.service(add_image)
		.service(remove_image)
		.service(add_image_attribute)
		.service(add_image_attribute_json)
		.service(remove_image_attribute)
		.service(remove_image_attribute_json)
		.service(tag_image)
		.service(untag_image)
		.service(login)
		.service(change_login_key)
		.service(user_info)
		.service(invalidate_user_token)
		.service(list_user_tokens)
		.service(change_user_scopes)
		.service(search_images)
		.service(upload_image)
		.service(imgops_upload)
		.service(create_user)
		.service(get_cf_turnstile_key)
		.service(list_users)
		.service(predict_tags)
		.service(predict_caption)
		.service(task_queue_insert)
		.service(task_queue_delete)
		.service(task_queue_view)
		.service(task_queue_acquire)
		.service(task_queue_finish)
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
	user.verify_scope(Scope::TagsAdd)?;

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
	user.verify_scope(Scope::TagsRemove)?;

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

	// The files don't change, so we can cache them for a long time
	let file = NamedFile::open(image_path)?
		.set_content_type(mime)
		.customize()
		.insert_header(("Cache-Control", "max-age=31536000, immutable"));
	Ok(file.respond_to(&req).map_into_boxed_body())
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
	user.verify_scope(Scope::ImagesAdd)?;

	let (hash,) = path.into_inner();
	let hash_str = hex::encode(hash.0);
	let image_path = server_data.image_dir.join(&hash_str[0..2]).join(&hash_str[2..4]).join(&hash_str);

	// Check if the image exists
	if !tokio::fs::try_exists(&image_path).await.context("Failed to check if image exists")? {
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
	user.verify_scope(Scope::ImagesRemove)?;

	let (identifier,) = path.into_inner();
	let image_id = {
		let images_lock = db.images.read().await;
		let image = match identifier {
			ImageIdentifier::Hash(hash) => db.get_image_by_hash(&hash, &images_lock).await,
			ImageIdentifier::Id(id) => db.get_image_by_id(id, &images_lock).await,
		};

		let image = match image {
			Some(image) => image,
			None => return Ok(HttpResponse::NotFound().finish()),
		};

		image.id
	};


	if db.remove_image(image_id, user.id).await? {
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
	user.verify_scope(Scope::ImagesTagsAdd)?;

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
	user.verify_scope(Scope::ImagesTagsRemove)?;

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
	user.verify_scope(Scope::ImagesAttributesAdd)?;

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


#[derive(Deserialize)]
struct AddImageAttributeQuery {
	key: String,
	value: String,
	singular: bool,
}

/// Add an attribute to an image
#[actix_web::post("/images/{image}/attributes")]
async fn add_image_attribute_json(
	db: Data<Arc<Database>>,
	path: web::Path<(ImageIdentifier,)>,
	data: web::Json<AddImageAttributeQuery>,
	user: AuthenticatedUser,
) -> Result<HttpResponse, ServerError> {
	// Check permissions
	user.verify_scope(Scope::ImagesAttributesAdd)?;

	let (image,) = path.into_inner();
	let data = data.into_inner();
	let image_id = match image {
		ImageIdentifier::Hash(hash) => match db.get_image_id(&hash).await {
			Some(id) => id,
			None => return Ok(HttpResponse::NotFound().body("Image not found")),
		},
		ImageIdentifier::Id(id) => id,
	};

	let result = if data.singular {
		db.add_image_attribute_singular(image_id, data.key, data.value, user.id).await?
	} else {
		db.add_image_attribute(image_id, data.key, data.value, user.id).await?
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
	user.verify_scope(Scope::ImagesAttributesRemove)?;

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
struct RemoveImageAttributeQuery {
	key: String,
	value: String,
}

/// Remove an attribute from an image
#[actix_web::delete("/images/{image}/attributes")]
async fn remove_image_attribute_json(
	db: Data<Arc<Database>>,
	path: web::Path<(ImageIdentifier,)>,
	data: web::Json<RemoveImageAttributeQuery>,
	user: AuthenticatedUser,
) -> Result<HttpResponse, ServerError> {
	// Check permissions
	user.verify_scope(Scope::ImagesAttributesRemove)?;

	let (image,) = path.into_inner();
	let data = data.into_inner();
	let image_id = match image {
		ImageIdentifier::Hash(hash) => match db.get_image_id(&hash).await {
			Some(id) => id,
			None => return Ok(HttpResponse::NotFound().body("Image not found")),
		},
		ImageIdentifier::Id(id) => id,
	};
	let key_id: AttributeKeyId = match db.get_string_id(&data.key).await {
		Some(id) => id.into(),
		None => return Ok(HttpResponse::NotFound().body("Key not found")),
	};
	let value_id: AttributeValueId = match db.get_string_id(&data.value).await {
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

	// Check if this user has permissions to create a user token for themselves
	let users = db.users.read().await;
	let (_, user) = db
		.get_user_by_id(user_id, &users)
		.ok_or_else(|| anyhow::anyhow!("User not found after authentication"))?;

	{
		// Need a temporary AuthenticatedUser to check permissions
		// Don't want it to live too long since technically the user isn't "Authenticated" (only user tokens can be Authenticated)
		let user = AuthenticatedUser {
			id: user_id,
			scope_matcher: user.scopes_matcher.clone(),
		};
		user.verify_scope(Scope::UsersTokensCreate(user_id))?;
	}

	// Create a new user token
	let user_token = db.create_user_token(user_id).await?;

	// Return the token
	Ok(HttpResponse::Ok().json(json!({
		"token": hex::encode(user_token.0),
	})))
}


#[derive(Deserialize)]
struct InvalidateTokenQuery {
	token: String,
}

/// Invalidate a user token
/// It seems to be recommended to use POST for sensitive queries, so we'll use that here instead of DELETE.
#[actix_web::post("/users/me/tokens/invalidate")]
async fn invalidate_user_token(db: Data<Arc<Database>>, query: web::Json<InvalidateTokenQuery>, user: AuthenticatedUser) -> Result<HttpResponse, ServerError> {
	let token = {
		let token = match hex::decode(&query.token) {
			Ok(token) => token,
			Err(_) => return Ok(HttpResponse::BadRequest().body("Invalid token")),
		};

		let token: [u8; 32] = match token.try_into() {
			Ok(token) => token,
			Err(_) => return Ok(HttpResponse::BadRequest().body("Invalid token")),
		};

		UserToken(token)
	};
	let token_user_id = match db.get_user_id_by_token(&token).await {
		Some(user_id) => user_id,
		None => return Ok(HttpResponse::NotFound().body("Token not found")),
	};

	// Check permissions
	user.verify_scope(Scope::UsersTokensDelete(token_user_id))?;

	db.invalidate_user_token(&token).await?;

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

	// Parse user ID
	let user_id = match query_user.as_str() {
		"me" => user.id,
		s => match s.parse().map(UserId) {
			Ok(id) => id,
			Err(_) => return Ok(HttpResponse::NotFound().finish()),
		},
	};

	// Check permissions
	user.verify_scope(Scope::UsersLoginKeyChange(user_id))?;

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
	user.verify_scope(Scope::UsersInfo(user_id))?;

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


/// List users
#[actix_web::get("/users")]
async fn list_users(db: Data<Arc<Database>>, user: AuthenticatedUser) -> Result<HttpResponse, ServerError> {
	// Check permissions
	user.verify_scope(Scope::UsersList)?;

	let users_lock = db.users.read().await;
	let users = (0..users_lock.len())
		.map(|id| {
			let (username, user) = db.get_user_by_id(id.into(), &users_lock).unwrap();
			json!({
				"id": id,
				"username": username,
				"scopes": user.scopes.clone(),
			})
		})
		.collect::<Vec<_>>();

	Ok(HttpResponse::Ok().json(users))
}


/// List user's tokens
#[actix_web::get("/users/{user}/tokens")]
async fn list_user_tokens(db: Data<Arc<Database>>, user: AuthenticatedUser, path: web::Path<(String,)>) -> Result<HttpResponse, ServerError> {
	// Parse user ID
	let user_id = match path.into_inner().0.as_str() {
		"me" => user.id,
		s => match s.parse().map(UserId) {
			Ok(id) => id,
			Err(_) => return Ok(HttpResponse::BadRequest().body("Invalid user ID")),
		},
	};

	// Check permissions
	user.verify_scope(Scope::UsersTokensList(user_id))?;

	let tokens = db.list_user_tokens_by_user_id(user_id).await;
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
	user.verify_scope(Scope::UsersScopesChange(target_user_id))?;

	match db.change_user_scopes(target_user_id, new_scopes).await {
		Ok(()) => Ok(HttpResponse::Ok().finish()),
		Err(DatabaseError::ScopeParseError(e)) => Ok(HttpResponse::BadRequest().body(format!("Invalid scope: {}", e))),
		Err(DatabaseError::UserDoesNotExist) => Ok(HttpResponse::NotFound().body("User not found")),
		Err(e) => Err(e.into()),
	}
}


fn deserialize_comma_separated<'de, D>(deserializer: D) -> Result<Vec<SearchSelect>, D::Error>
where
	D: Deserializer<'de>,
{
	let s: String = String::deserialize(deserializer)?;
	s.split(',')
		.map(|item| item.trim().parse::<SearchSelect>())
		.collect::<Result<Vec<_>, _>>()
		.map_err(serde::de::Error::custom)
}


#[derive(Deserialize)]
struct SearchImagesQuery {
	query: String,
	#[serde(deserialize_with = "deserialize_comma_separated")]
	select: Vec<SearchSelect>,
}

#[derive(Deserialize, Copy, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SearchSelect {
	Id,
	Hash,
	Tags,
	Attributes,
}

impl FromStr for SearchSelect {
	type Err = &'static str;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s {
			"id" => Ok(SearchSelect::Id),
			"hash" => Ok(SearchSelect::Hash),
			"tags" => Ok(SearchSelect::Tags),
			"attributes" => Ok(SearchSelect::Attributes),
			_ => Err("invalid search select"),
		}
	}
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

	let results = match search.execute(&db).await {
		Ok(results) => results,
		Err(e) => return Ok(HttpResponse::InternalServerError().body(format!("Error executing search: {}", e.message))),
	};
	log::warn!("Query \"\"\"{}\"\"\" took {:?}ms", query.query, start_time.elapsed().as_millis());

	let images_lock = db.images.clone();

	// For now, we return IDs as u32, since it's more efficient and doesn't require bigint on the client side
	// If we ever have more than 4 billion of something, this will error out to make sure we don't overflow
	if db.images.read().await.len() > u32::MAX as usize {
		return Ok(HttpResponse::InternalServerError().body("Image IDs exceed u32"));
	}

	if db.tags.read().await.len() > u32::MAX as usize {
		return Ok(HttpResponse::InternalServerError().body("Tag IDs exceed u32"));
	}

	let select = query.select.clone();
	let result = tokio::task::spawn_blocking(move || build_search_response(select, search.sort, results, images_lock, db.string_table.clone()))
		.await
		.unwrap();

	return Ok(HttpResponse::Ok().content_type("application/octet-stream").body(result));
}


enum SortedSearchResults<'a> {
	Ids(Box<dyn Iterator<Item = ImageId>>),
	Entries(Box<dyn Iterator<Item = (&'a ImageHash, &'a ImageEntry)> + 'a>),
}

impl<'a> SortedSearchResults<'a> {
	fn new(sort: Option<TreeSort>, results: HashSet<ImageId>, images_lock: &'a ImagesReadGuard) -> Self {
		match sort {
			Some(TreeSort::Id) => {
				let results: BTreeSet<ImageId> = results.into_iter().collect();
				SortedSearchResults::Ids(Box::new(results.into_iter()))
			},
			Some(TreeSort::Hash) => {
				let results: BTreeMap<&ImageHash, &ImageEntry> = results.into_iter().filter_map(|id| images_lock.get_by_id_full(id)).collect();
				SortedSearchResults::Entries(Box::new(results.into_iter()))
			},
			None => SortedSearchResults::Ids(Box::new(results.into_iter())),
		}
	}

	/// If access to the image entries is needed, this method turns the sorted results into an iterator over the entries.
	fn with_images(self, images_lock: &'a ImagesReadGuard) -> Box<dyn Iterator<Item = (ImageId, &'a ImageHash, &'a ImageEntry)> + 'a> {
		match self {
			SortedSearchResults::Ids(ids) => Box::new(
				ids.filter_map(move |id| images_lock.get_by_id_full(id))
					.map(|(hash, entry)| (entry.id, hash, entry)),
			),
			SortedSearchResults::Entries(entries) => Box::new(entries.map(|(hash, entry)| (entry.id, hash, entry))),
		}
	}

	fn without_images(self) -> Box<dyn Iterator<Item = ImageId> + 'a> {
		match self {
			SortedSearchResults::Ids(ids) => ids,
			SortedSearchResults::Entries(entries) => Box::new(entries.map(|(_, entry)| entry.id)),
		}
	}
}


fn build_search_response(
	select: Vec<SearchSelect>,
	sort: Option<TreeSort>,
	results: HashSet<ImageId>,
	images_lock: Arc<ImagesRwLock>,
	strings_lock: Arc<StringTableRwLock>,
) -> Vec<u8> {
	let images_lock = images_lock.blocking_read();
	let mut builder = FlatBufferBuilder::new();
	let n_results = results.len();

	// Sort
	let sorted = SortedSearchResults::new(sort, results, &images_lock);

	// Serialize
	match select.as_slice() {
		// Only IDs
		[SearchSelect::Id] => {
			builder.start_vector::<u32>(n_results);
			sorted.without_images().for_each(|id| {
				builder.push(id.0 as u32);
			});
			let ids_vector = builder.end_vector(n_results);
			let id_response = flatbuffer_types::IDResponse::create(&mut builder, &flatbuffer_types::IDResponseArgs { ids: Some(ids_vector) });
			let search_response = flatbuffer_types::SearchResultResponse::create(
				&mut builder,
				&flatbuffer_types::SearchResultResponseArgs {
					data_type: flatbuffer_types::ResponseType::IDResponse,
					data: Some(id_response.as_union_value()),
				},
			);
			builder.finish(search_response, None);
		},

		// Only hashes
		[SearchSelect::Hash] => {
			builder.start_vector::<WIPOffset<flatbuffer_types::Hash>>(n_results);
			sorted.with_images(&images_lock).for_each(|(_, hash, _)| {
				builder.push(&flatbuffer_types::Hash(hash.0));
			});
			let hashes_vector = builder.end_vector(n_results);
			let hash_response = flatbuffer_types::HashResponse::create(&mut builder, &flatbuffer_types::HashResponseArgs { hashes: Some(hashes_vector) });
			let search_response = flatbuffer_types::SearchResultResponse::create(
				&mut builder,
				&flatbuffer_types::SearchResultResponseArgs {
					data_type: flatbuffer_types::ResponseType::HashResponse,
					data: Some(hash_response.as_union_value()),
				},
			);
			builder.finish(search_response, None);
		},

		// Full objects in all other cases
		_ => {
			let images: Vec<_> = sorted
				.with_images(&images_lock)
				.map(|(_id, hash, image)| {
					// Image hash
					let hash = if select.contains(&SearchSelect::Hash) {
						Some(flatbuffer_types::Hash(hash.0))
					} else {
						None
					};

					// Image tags
					let tags = if select.contains(&SearchSelect::Tags) {
						let mut tags = Vec::new();

						image.tags.iter().for_each(|(tag_id, user_id)| {
							let tag_with_blame = flatbuffer_types::TagWithBlame::create(
								&mut builder,
								&flatbuffer_types::TagWithBlameArgs {
									tag: tag_id.0 as u32,
									blame: user_id.0 as u32,
								},
							);

							tags.push(tag_with_blame);
						});

						Some(builder.create_vector(&tags))
					} else {
						None
					};

					// Image attributes
					let attributes = if select.contains(&SearchSelect::Attributes) {
						let strings_lock = strings_lock.blocking_read();
						let mut attributes = Vec::new();

						image.attributes.iter().for_each(|(key_id, values)| {
							let key_str = strings_lock.get_by_id_full((*key_id).into()).unwrap().0;
							let key_offset = builder.create_string(key_str);

							values.iter().for_each(|(value_id, user_id)| {
								let value_str = strings_lock.get_by_id_full((*value_id).into()).unwrap().0;
								let value_offset = builder.create_string(value_str);
								let attribute_with_blame = flatbuffer_types::AttributeWithBlame::create(
									&mut builder,
									&flatbuffer_types::AttributeWithBlameArgs {
										key: Some(key_offset),
										value: Some(value_offset),
										blame: user_id.0 as u32,
									},
								);

								attributes.push(attribute_with_blame);
							});
						});

						Some(builder.create_vector(&attributes))
					} else {
						None
					};

					let image = flatbuffers_generated::tag_storm_db::Image::create(
						&mut builder,
						&flatbuffers_generated::tag_storm_db::ImageArgs {
							id: image.id.0 as u32,
							hash: hash.as_ref(),
							tags,
							attributes,
						},
					);

					image
				})
				.collect();

			let images_vector = builder.create_vector(&images);

			let image_response = flatbuffer_types::ImageResponse::create(&mut builder, &flatbuffer_types::ImageResponseArgs { images: Some(images_vector) });
			let search_response = flatbuffer_types::SearchResultResponse::create(
				&mut builder,
				&flatbuffer_types::SearchResultResponseArgs {
					data_type: flatbuffer_types::ResponseType::ImageResponse,
					data: Some(image_response.as_union_value()),
				},
			);
			builder.finish(search_response, None);
		},
	}

	builder.finished_data().to_vec()
}


#[derive(Debug, MultipartForm)]
struct UploadImageForm {
	#[multipart(rename = "file")]
	files: Vec<actix_multipart::form::tempfile::TempFile>,
}

#[actix_web::post("/upload_image")]
async fn upload_image(
	db: Data<Arc<Database>>,
	MultipartForm(form): MultipartForm<UploadImageForm>,
	server_data: Data<ServerData>,
	user: AuthenticatedUser,
) -> Result<HttpResponse, ServerError> {
	// Permissions
	user.verify_scope(Scope::ImagesUpload)?;

	let mut files = form.files.into_iter();
	let file = match files.next() {
		Some(file) => file,
		None => return Ok(HttpResponse::BadRequest().body("Expected exactly one file")),
	};

	if files.next().is_some() {
		return Ok(HttpResponse::BadRequest().body("Expected exactly one file"));
	}

	// Check file size
	if file.size > MAX_FILE_SIZE {
		return Ok(HttpResponse::PayloadTooLarge().body("File too large"));
	}

	// Hash the file
	let async_file = tokio::fs::File::from_std(file.file.reopen().context("Failed to reopen temporary file")?);
	let file_hash = hash_async_reader(async_file).await.context("Failed to hash file")?;

	// Format the (potential) image paths
	let hash_str = hex::encode(file_hash.0);
	let image_path_parent = std::path::absolute(server_data.image_dir.join(&hash_str[0..2]).join(&hash_str[2..4])).context("Failed to get absolute path")?;
	let image_path = image_path_parent.join(&hash_str);
	let upload_path_parent = std::path::absolute(server_data.upload_dir.join(&hash_str[0..2]).join(&hash_str[2..4])).context("Failed to get absolute path")?;
	let upload_path = upload_path_parent.join(&hash_str);
	let relative_path = pathdiff::diff_paths(&upload_path, &image_path_parent)
		.ok_or_else(|| anyhow::anyhow!("Failed to get relative path between {:?} and {:?}", upload_path, image_path_parent))?;

	// Create the directories if they don't exist
	tokio::fs::create_dir_all(image_path_parent).await.context("Failed to create directory")?;
	tokio::fs::create_dir_all(upload_path_parent).await.context("Failed to create directory")?;

	// Persist to the upload path if it doesn't exist
	// There's a small race condition here, but worst case it just causes an error and the user has to try again
	if !upload_path.exists() {
		tokio::fs::set_permissions(file.file.path(), std::fs::Permissions::from_mode(0o644))
			.await
			.context("Failed to set file permissions")?;
		file.file.persist_noclobber(&upload_path).context("Failed to persist temporary file")?;
	}

	// Symlink the file to the image directory
	// IIUC this is noclobber, so will fail if the file already exists (which is what we want)
	match tokio::fs::symlink(relative_path, &image_path).await {
		Ok(_) => {},
		Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {},
		Err(err) => return Err(anyhow::Error::new(err).context("Failed to create symlink").into()),
	}

	// Double check that everything is correct before adding the image to the database
	if !tokio::fs::try_exists(&image_path).await.context("Failed to check if image exists")? {
		return Err(anyhow::anyhow!("Symlink does not exist or points to a non-existent file: {:?}", image_path).into());
	}

	// Add the image to the database
	if !db.add_image(file_hash, user.id).await.context("Failed to add image to database")? {
		return Ok(HttpResponse::Conflict().reason("Database conflict").finish());
	}

	Ok(HttpResponse::Created().finish())
}


#[actix_web::post("/images/{image}/imgops")]
async fn imgops_upload(
	user: AuthenticatedUser,
	server_data: Data<ServerData>,
	db: Data<Arc<Database>>,
	path: web::Path<(ImageIdentifier,)>,
) -> Result<HttpResponse, ServerError> {
	// Check permissions
	user.verify_scope(Scope::ImagesImgops)?;

	// Get image
	let (image,) = path.into_inner();
	let images_lock = db.images.read().await;
	let image = match image {
		ImageIdentifier::Hash(hash) => db.get_image_by_hash(&hash, &images_lock).await,
		ImageIdentifier::Id(id) => db.get_image_by_id(id, &images_lock).await,
	};
	let image = match image {
		Some(image) => image,
		None => return Ok(HttpResponse::NotFound().body("Image not found")),
	};

	// Check if image is active and exists
	let hash_str = hex::encode(image.hash.0);
	let image_path = server_data.image_dir.join(&hash_str[0..2]).join(&hash_str[2..4]).join(&hash_str);

	if !image.active || !image_path.exists() {
		return Ok(HttpResponse::NotFound().body("Image not found"));
	}

	// Read file
	let file_bytes = tokio::fs::read(&image_path).await?;

	// Guess the image type
	let format = image::guess_format(&file_bytes).ok().map(|f| f.to_mime_type());
	let mime: mime::Mime = format.unwrap_or("application/octet-stream").parse().unwrap();

	let file_part = reqwest::multipart::Part::bytes(file_bytes)
		.file_name("file")
		.mime_str(mime.to_string().as_str())
		.unwrap();
	let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build()?;
	let form = reqwest::multipart::Form::new().part("photo", file_part);

	// Upload the image to imgops
	let response = client.post("https://imgops.com/store").multipart(form).send().await?;
	let headers = response.headers();
	let redirect_url = headers
		.get("Location")
		.ok_or_else(|| anyhow::anyhow!("No Location header in imgops' response"))?
		.to_str()?;

	Ok(HttpResponse::Ok().body(redirect_url.to_string()))
}


#[derive(Deserialize)]
struct CreateUserQuery {
	username: String,
	login_key: LoginKey,
	birthdate: i64,
	cf_turnstile_token: String,
	invite_code: String,
}

#[actix_web::post("/users")]
async fn create_user(
	db: Data<Arc<Database>>,
	query: web::Json<CreateUserQuery>,
	server_data: Data<ServerData>,
	req: HttpRequest,
) -> Result<HttpResponse, ServerError> {
	// TODO: Do optional user authentication so that users with the "users/create" scope can create users
	// with arbitrary scopes and such.

	// Get ip
	let ip = req
		.headers()
		.get("x-real-ip")
		.and_then(|v| v.to_str().ok())
		.ok_or_else(|| anyhow::anyhow!("Failed to get IP of client using the x-real-ip header"))?;

	// Verify Cloudflare Turnstile
	if !verify_cf_turnstile(&server_data, &query.cf_turnstile_token, ip).await? {
		return Ok(HttpResponse::Forbidden().body("Cloudflare Turnstile failed"));
	}

	// Verify invitation code
	if let Err(err) = verify_invitation_code(&server_data, &query.invite_code) {
		return Ok(HttpResponse::Forbidden().body(err));
	}

	// Verify that user is 18+
	let now = chrono::Utc::now().timestamp();
	if now - query.birthdate < 18 * 365 * 24 * 60 * 60 {
		return Ok(HttpResponse::Forbidden().body("User is not 18+"));
	}

	// Hash the login key
	let hashed_login_key = query.login_key.hash();

	// TODO: Encrypt login key

	// Create the user
	let user_id = match db.add_user(query.username.clone(), hashed_login_key, "".to_string()).await {
		Ok(user_id) => user_id,
		Err(DatabaseError::UserAlreadyExists) => return Ok(HttpResponse::Conflict().body("User already exists")),
		Err(e) => return Err(anyhow::Error::new(e).context("Failed to create user").into()),
	};

	// Set scopes
	let scopes = server_data.default_user_scopes.replace("{id}", &user_id.0.to_string());
	db.change_user_scopes(user_id, scopes).await.context("Failed to set user scopes")?;

	Ok(HttpResponse::Created().finish())
}


fn verify_invitation_code(server_data: &ServerData, code: &str) -> Result<(), &'static str> {
	// Try to decode from base32
	let code = BASE32
		.decode(code.to_uppercase().as_bytes())
		.map_err(|_| "Invitation code is not valid base32")?;

	// An invitation code should be 8 bytes for the expiration timestamp and 32 bytes for the authentication code
	if code.len() != 8 + 32 {
		return Err("Invalid invitation code format");
	}

	// Derive our key from the server's key
	let key = derive_key(&server_data.server_secrets.server_secret, b"user-invitation-auth");

	// Authenticate
	let timestamp_bytes = match authenticate_data(b"user-invitation-code", &code, &key) {
		Some(timestamp_bytes) => timestamp_bytes,
		None => return Err("Invalid invitation code"),
	};

	// Check expiration
	let expiration = i64::from_le_bytes(timestamp_bytes.try_into().expect("unexpected"));

	if expiration < chrono::Utc::now().timestamp() {
		return Err("Invitation code expired");
	}

	Ok(())
}


async fn verify_cf_turnstile(server_data: &ServerData, token: &str, ip: &str) -> Result<bool, ServerError> {
	#[derive(Deserialize)]
	struct TurnstileResponse {
		success: bool,
		#[serde(rename = "error-codes")]
		error_codes: Vec<String>,
	}

	let cf_turnstile_key = server_data
		.server_secrets
		.cf_turnstile_private
		.as_ref()
		.ok_or_else(|| anyhow::anyhow!("Cloudflare Turnstile secret not set"))?;

	let url = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
	let client = reqwest::Client::new();
	let response = client
		.post(url)
		.header("Content-Type", "application/json")
		.json(&json!({
			"secret": cf_turnstile_key,
			"response": token,
			"remoteip": ip,
		}))
		.send()
		.await
		.context("Failed to send request to Cloudflare Turnstile")?;

	let response: TurnstileResponse = response.json().await.context("Failed to parse Cloudflare Turnstile response")?;

	if !response.success {
		log::info!("Cloudflare Turnstile failed: {:?}", response.error_codes);
	}

	Ok(response.success)
}


/// Get the Cloudflare Turnstile public site key
#[actix_web::get("/cf_turnstile_key")]
async fn get_cf_turnstile_key(server_data: Data<ServerData>) -> HttpResponse {
	match &server_data.server_secrets.cf_turnstile_public {
		Some(key) => HttpResponse::Ok().body(key.clone()),
		None => HttpResponse::NotFound().finish(),
	}
}


async fn get_image_data_by_identifier<'a>(db: &'a Database, image: ImageIdentifier, server_data: &'a ServerData) -> Option<Vec<u8>> {
	let images_lock = db.images.read().await;
	let image = match image {
		ImageIdentifier::Hash(hash) => db.get_image_by_hash(&hash, &images_lock).await,
		ImageIdentifier::Id(id) => db.get_image_by_id(id, &images_lock).await,
	};
	let image = match image {
		Some(image) => image,
		None => return None,
	};

	// Check if image is active and exists
	let hash_str = hex::encode(image.hash.0);
	let image_path = server_data.image_dir.join(&hash_str[0..2]).join(&hash_str[2..4]).join(&hash_str);

	if !image.active || !image_path.exists() {
		return None;
	}

	// Read file
	let file_bytes = match tokio::fs::read(&image_path).await {
		Ok(bytes) => bytes,
		Err(err) => {
			log::error!("Failed to read image file {}: {:?}", image_path.display(), err);
			return None;
		},
	};

	Some(file_bytes)
}


#[derive(Deserialize)]
struct PredictTagsQuery {
	tags: Option<String>,
}

/// Predict tags for an image
/// Forwards to the prediction server
#[actix_web::get("/images/{image}/predict/tags")]
async fn predict_tags(
	db: Data<Arc<Database>>,
	user: AuthenticatedUser,
	path: web::Path<(ImageIdentifier,)>,
	server_data: Data<ServerData>,
	query: web::Query<PredictTagsQuery>,
) -> Result<HttpResponse, ServerError> {
	// Check permissions
	user.verify_scope(Scope::ImagesPredictTags)?;

	// Parse tags as a comma-separated list
	let tags = query.tags.as_ref().map(|s| s.split(',').map(|s| s.trim().to_string()).collect::<Vec<_>>());

	// Get image
	let (image,) = path.into_inner();
	let image_data = match get_image_data_by_identifier(&db, image, &server_data).await {
		Some(data) => data,
		None => return Ok(HttpResponse::NotFound().body("Image not found")),
	};

	// Build request to prediction server
	let file_part = reqwest::multipart::Part::bytes(image_data).file_name("file");
	let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build()?;
	let mut form = reqwest::multipart::Form::new().part("image", file_part);

	let url = if let Some(tags) = tags {
		for tag in tags {
			form = form.text("tags", tag);
		}

		server_data.prediction_server.join("tag_assoc").context("Failed to build URL")?
	} else {
		server_data.prediction_server.join("predict").context("Failed to build URL")?
	};

	// Forward to the prediction server
	let response = match client.post(url).multipart(form).send().await {
		Ok(response) if response.status().is_success() => response,
		Ok(response) => {
			log::warn!("Prediction server failed: {}", response.status());
			return Ok(HttpResponse::BadGateway().body("Prediction server may be offline"));
		},
		Err(err) => {
			log::warn!("Prediction server failed: {:?}", err);
			return Ok(HttpResponse::BadGateway().body("Prediction server may be offline"));
		},
	};

	let body = response.bytes().await?.to_vec();

	Ok(HttpResponse::Ok().content_type("application/json").body(body))
}


#[derive(Deserialize)]
struct PredictCaptionQuery {
	prompt: String,
}

/// Predict caption for an image
/// Forwards to the prediction server
#[actix_web::get("/images/{image}/predict/caption")]
async fn predict_caption(
	db: Data<Arc<Database>>,
	user: AuthenticatedUser,
	query: web::Query<PredictCaptionQuery>,
	path: web::Path<(ImageIdentifier,)>,
	server_data: Data<ServerData>,
) -> Result<HttpResponse, ServerError> {
	// Check permissions
	user.verify_scope(Scope::ImagesPredictCaption)?;

	// Get image
	let (image,) = path.into_inner();
	let image_data = match get_image_data_by_identifier(&db, image, &server_data).await {
		Some(data) => data,
		None => return Ok(HttpResponse::NotFound().body("Image not found")),
	};

	// Build request to prediction server
	let file_part = reqwest::multipart::Part::bytes(image_data).file_name("file");
	let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build()?;
	let form = reqwest::multipart::Form::new().part("image", file_part).text("prompt", query.prompt.clone());

	// Forward to the prediction server
	let url = server_data.prediction_server.join("caption").context("Failed to build URL")?;
	let response = client.post(url).multipart(form).send().await?;

	if !response.status().is_success() {
		return Ok(HttpResponse::InternalServerError().body("Prediction server failed"));
	}

	let body = response.bytes().await?.to_vec();

	Ok(HttpResponse::Ok().content_type("application/json").body(body))
}


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


async fn hash_async_reader<R: tokio::io::AsyncRead + Unpin>(mut reader: R) -> Result<ImageHash, std::io::Error> {
	let mut hasher = Sha256::new();
	let mut buffer = vec![0; 64 * 1024];

	loop {
		match reader.read(&mut buffer).await {
			Ok(0) => break,
			Ok(bytes_read) => hasher.update(&buffer[0..bytes_read]),
			Err(err) => return Err(err),
		};
	}

	let hash = hasher.finalize();

	Ok(ImageHash(hash.into()))
}


fn deserialize_hex<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
	D: Deserializer<'de>,
{
	let s: String = String::deserialize(deserializer)?;
	hex::decode(&s).map_err(serde::de::Error::custom)
}
