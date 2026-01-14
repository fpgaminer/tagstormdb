/// We redid our Danbooru dataset and discovered that many images did not match with their hashes, likely due to jpeg/png optimization, etc.
/// For consistency and such I wanted to make sure they matched their hash specified by Danbooru.
/// But now many of the SHA-256 hashes are different.
/// This program works in three stages.
///
/// Stage one:
/// Goes through the tag-machine's symlinks to find any broken ones that point to old danbooru paths.
/// It then determines if we have an updated hash for that image, and double checks that the file matches the expected hash from danbooru.
/// That mapping is saved out to a file as a paper trail (danbooru_broken_symlink_mapping.json).
///
/// Stage two:
/// * Reads the mapping file from stage 1.
/// * Adds any new hashes to the image_hashes table (append).
/// * Creates any missing symlinks.
/// * For each broken image, determines the old image id and new image id and merges the old image's tags and attributes onto the new image.
/// * Will NOT remove any tags from the new images.  Instead saves out a danbooru_tags_to_remove.json file listing tags that could be removed if desired.
/// * Will NOT remove any attributes from the new images.
/// * For each broken image will update the smalldb task queue to reference the new image ids.
///
/// This stage is idempotent and can be run multiple times safely.
///
/// Stage three:
/// * Reads the mapping file from stage 1.
/// * For each broken image removes the old image from the database.
/// * Removes the old symlinks from the tag-machine images directory.
///
/// This stage is _NOT_ idempotent and should be run last, without running any of the other stages later.
///
use std::{
	collections::{HashMap, HashSet},
	fs::File,
	io::{BufReader, BufWriter},
	path::{Path, PathBuf},
};

use anyhow::Context as _;
use clap::Parser;
use env_logger::Env;
use futures::StreamExt as _;
use ignore::WalkBuilder;
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use log::{error, info, warn};
use md5::Digest;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use tagstormdb::{database::StateUpdateResult, default_progress_style, progress_bar_with_default_style, AttributeKeyId, Database, ImageHash, ImageId, UserId};


const OLD_DANBOORU_PATH: &str = "/home/night/datasets/danbooru2021/originals";
const BOORUS_PATH: &str = "/home/night/datasets/boorus/originals";


#[derive(Parser, Debug)]
#[command()]
struct Args {
	/// Path to the source database.
	#[arg(long)]
	source_database: PathBuf,

	/// Path to the tag-machine symlink directory
	#[arg(long, default_value = "/home/night/tag-machine/rust-api/images")]
	symlink_directory: PathBuf,

	/// What action to perform
	#[arg(long)]
	action: ArgsAction,
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum ArgsAction {
	Stage1,
	CreateSymlinks,
	AddNewImages,
	IdMapping,
	FixTags,
	FixAttributes,
	FixSmalldbTaskQueue,
	RemoveOldImages,
	ListAllBrokenSymlinks, // Just a helpful last pass
}


#[derive(Debug)]
struct BrokenSymlink {
	symlink_path: PathBuf,
	target_path: PathBuf,
	danbooru_id: u64,
	old_filehash: ImageHash,
}


#[derive(Serialize, Deserialize, Debug)]
struct BrokenSymlinkMapping {
	symlink_path: PathBuf,
	target_path: PathBuf,
	danbooru_id: u64,
	old_filehash: ImageHash,
	new_filehash: ImageHash,
}


#[actix_web::main]
async fn main() -> Result<(), anyhow::Error> {
	// Env logger
	env_logger::Builder::from_env(Env::default().default_filter_or("warn,tagstormdb=debug,fix_danbooru=info")).init();

	// Parse command line arguments
	let args = Args::parse();

	match args.action {
		ArgsAction::Stage1 => {
			// Find broken symlinks to danbooru files
			let broken_symlinks = find_broken_symlinks(&args.symlink_directory).await?;

			// Find the new filehashes using the booru database
			let mappings = find_new_filehashes(broken_symlinks).await?;

			// Verify that the files are what we expect using the booru hashes
			let mappings = verify_booru_hashes(mappings).await?;

			// Save mapping to file
			info!("Saving {} broken symlink mappings to danbooru_broken_symlink_mapping.json", mappings.len());
			let mapping_file = File::create("danbooru_broken_symlink_mapping.json")?;
			let writer = BufWriter::new(mapping_file);
			serde_json::to_writer_pretty(writer, &mappings)?;
		},
		ArgsAction::CreateSymlinks => {
			// Load mapping from file
			let (_old_filehash_to_new_filehash, mappings) = read_mappings(Path::new("danbooru_broken_symlink_mapping.json"))?;

			// Create new symlinks
			add_new_symlinks(&mappings, &args.symlink_directory).await?;
		},
		ArgsAction::AddNewImages => {
			// Load mapping from file
			let (old_filehash_to_new_filehash, _mappings) = read_mappings(Path::new("danbooru_broken_symlink_mapping.json"))?;

			// Open database
			let database = Database::open(&args.source_database, true).await?;

			// Add new images
			add_new_images(&old_filehash_to_new_filehash, &database).await?;
		},
		ArgsAction::IdMapping => {
			// Load mapping from file
			let (old_filehash_to_new_filehash, _mappings) = read_mappings(Path::new("danbooru_broken_symlink_mapping.json"))?;

			// Open database
			let database = Database::open(&args.source_database, true).await?;

			// Map old ids to new ids
			let _old_ids_to_new_ids = create_id_mapping(&old_filehash_to_new_filehash, &database).await?;
		},
		ArgsAction::FixTags => {
			// Open database
			let database = Database::open(&args.source_database, true).await?;

			// Map id mapping
			let old_ids_to_new_ids = read_id_mapping().await?;

			// Fix tags
			fix_tags(&old_ids_to_new_ids, &database).await?;
		},
		ArgsAction::FixAttributes => {
			// Open database
			let database = Database::open(&args.source_database, true).await?;

			// Read id mapping
			let old_ids_to_new_ids = read_id_mapping().await?;

			// Fix attributes
			fix_attributes(&old_ids_to_new_ids, &database).await?;
		},
		ArgsAction::FixSmalldbTaskQueue => {
			// Open database
			let database = Database::open(&args.source_database, true).await?;

			// Read id mapping
			let old_ids_to_new_ids = read_id_mapping().await?;

			// Fix smalldb task queue
			fix_smalldb_task_queue(&old_ids_to_new_ids, &database).await?;
		},
		ArgsAction::RemoveOldImages => {
			// Load mapping from file
			let (old_filehash_to_new_filehash, mappings) = read_mappings(Path::new("danbooru_broken_symlink_mapping.json"))?;

			// Open database
			let database = Database::open(&args.source_database, true).await?;

			// Map old ids to new ids
			let old_ids_to_new_ids = create_id_mapping(&old_filehash_to_new_filehash, &database).await?;

			// Remove old images
			remove_old_images(old_ids_to_new_ids, mappings, &database).await?;
		},
		ArgsAction::ListAllBrokenSymlinks => {
			// Find all broken symlinks
			find_all_broken_symlinks(&args.symlink_directory).await?;
		},
	}

	Ok(())
}


/// Scan the rust-api images directory for all broken symlinks that point to the old danbooru path.
async fn find_broken_symlinks(images_directory: &Path) -> Result<Vec<BrokenSymlink>, anyhow::Error> {
	info!("Finding broken symlinks in {:?}", images_directory);

	let pb_target = ProgressDrawTarget::stderr();
	let pb = ProgressBar::with_draw_target(None, pb_target)
		.with_style(
			ProgressStyle::with_template("{spinner:.cyan} {msg}  [{elapsed_precise}]  scanned:{pos} ({per_sec:.2} it/s)")
				.unwrap()
				.tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏ "),
		)
		.with_message("Scanning for broken symlinks");
	pb.enable_steady_tick(std::time::Duration::from_millis(100));

	let (tx, rx) = std::sync::mpsc::channel();
	let walker = WalkBuilder::new(images_directory)
		.ignore(false)
		.git_ignore(false)
		.git_exclude(false)
		.follow_links(false)
		.build_parallel();

	walker.run(|| {
		let tx = tx.clone();
		let pb = pb.clone();

		Box::new(move |result| {
			pb.inc(1);

			let entry = match result {
				Ok(e) => e,
				Err(err) => {
					log::warn!("Error reading directory entry: {}", err);
					return ignore::WalkState::Continue;
				},
			};

			// Determine if it's a symlink
			let path = entry.path();
			let Some(ft) = entry.file_type() else {
				return ignore::WalkState::Continue;
			};

			if !ft.is_symlink() {
				return ignore::WalkState::Continue;
			}

			// If metadata succeeds, the symlink resolves -> not broken
			if std::fs::metadata(path).is_ok() {
				return ignore::WalkState::Continue;
			}

			// Find out what it points to
			let target_path = match std::fs::read_link(path) {
				Ok(t) => t,
				Err(err) => {
					log::warn!("Error reading symlink {:?}: {}", path, err);
					return ignore::WalkState::Continue;
				},
			};

			// NOTE: All of the symlinks we care about should be absolute, so we don't need to resolve relative paths here
			// Check if it points to the old danbooru path
			if !target_path.starts_with(OLD_DANBOORU_PATH) {
				return ignore::WalkState::Continue;
			}

			// Verify that we can extract the danbooru id from the filename
			let Some(filestem) = target_path.file_stem().and_then(|f| f.to_str()) else {
				log::warn!("Invalid filename for symlink: {:?}", path);
				return ignore::WalkState::Continue;
			};

			let Ok(danbooru_id) = filestem.parse::<u64>() else {
				log::warn!("Failed to parse danbooru id from filename: {:?}", path);
				return ignore::WalkState::Continue;
			};

			// Extract the hash from the filename
			let Some(filename) = path.file_name().and_then(|f| f.to_str()) else {
				log::warn!("Invalid symlink filename: {:?}", path);
				return ignore::WalkState::Continue;
			};

			let mut old_filehash = [0u8; 32];
			if filename.len() != 64 {
				log::warn!("Invalid symlink filename (expected 64 hex chars): {:?}", path);
				return ignore::WalkState::Continue;
			}

			if let Err(err) = hex::decode_to_slice(filename, &mut old_filehash) {
				log::warn!("Failed to decode hash from symlink filename {:?}: {}", path, err);
				return ignore::WalkState::Continue;
			}

			//log::info!("Broken symlink found: {:?} -> {:?}", path, target_path);
			tx.send(BrokenSymlink {
				symlink_path: path.to_path_buf(),
				target_path,
				danbooru_id,
				old_filehash: ImageHash(old_filehash),
			})
			.expect("Failed to send broken symlink info");

			ignore::WalkState::Continue
		})
	});

	drop(tx);
	let broken_symlinks: Vec<_> = rx.iter().collect();

	log::info!("Found {} broken symlinks in {:?}.", broken_symlinks.len(), pb.elapsed());

	Ok(broken_symlinks)
}


/// Scan the rust-api images directory for all broken symlinks that point to the old danbooru path.
async fn find_all_broken_symlinks(images_directory: &Path) -> Result<(), anyhow::Error> {
	info!("Finding all broken symlinks in {:?}", images_directory);

	let pb = progress_bar_with_default_style(None::<u64>, Some("Scanning for broken symlinks"));

	let (tx, rx) = std::sync::mpsc::channel();
	let walker = WalkBuilder::new(images_directory)
		.ignore(false)
		.git_ignore(false)
		.git_exclude(false)
		.follow_links(false)
		.build_parallel();

	walker.run(|| {
		let tx = tx.clone();
		let pb = pb.clone();

		Box::new(move |result| {
			pb.inc(1);

			let entry = match result {
				Ok(e) => e,
				Err(err) => {
					log::warn!("Error reading directory entry: {}", err);
					return ignore::WalkState::Continue;
				},
			};

			// Determine if it's a symlink
			let path = entry.path();
			let Some(ft) = entry.file_type() else {
				return ignore::WalkState::Continue;
			};

			if !ft.is_symlink() {
				return ignore::WalkState::Continue;
			}

			// If metadata succeeds, the symlink resolves -> not broken
			if std::fs::metadata(path).is_ok() {
				return ignore::WalkState::Continue;
			}

			// Find out what it points to
			let target_path = match std::fs::read_link(path) {
				Ok(t) => t,
				Err(err) => {
					log::warn!("Error reading symlink {:?}: {}", path, err);
					return ignore::WalkState::Continue;
				},
			};

			tx.send((path.to_string_lossy().to_string(), target_path.to_string_lossy().to_string()))
				.expect("Failed to send broken symlink info");

			ignore::WalkState::Continue
		})
	});

	drop(tx);
	let broken_symlinks: Vec<_> = rx.iter().collect();

	log::info!("Found {} broken symlinks in {:?}.", broken_symlinks.len(), pb.elapsed());

	// Write out all broken symlinks to a file
	serde_json::to_writer_pretty(
		BufWriter::new(File::create("all_broken_symlinks.json")?),
		&json!({
			"broken_symlinks": broken_symlinks.iter().map(|(symlink, target)| {
				json!({
					"symlink": symlink,
					"target": target,
				})
			}).collect::<Vec<_>>(),
		}),
	)?;
	info!("Wrote all broken symlinks to all_broken_symlinks.json");

	Ok(())
}


/// Uses the boorus database to find the new filehashes for the given broken symlinks, using the danbooru post ids.
async fn find_new_filehashes(broken_symlinks: Vec<BrokenSymlink>) -> Result<Vec<(BrokenSymlink, [u8; 16], [u8; 32])>, anyhow::Error> {
	info!("Finding new filehashes for broken symlinks");

	// Connect to booru database
	let opts = PgConnectOptions::new()
		.username("postgres")
		.database("postgres")
		.host("/home/night/datasets/boorus/pg-socket");
	let pool = PgPoolOptions::new()
		.max_connections(5)
		.connect_with(opts)
		.await
		.context("failed to connect to PostgreSQL")?;

	let pb = ProgressBar::new(broken_symlinks.len() as u64)
		.with_style(default_progress_style())
		.with_message("Finding new filehashes");
	pb.enable_steady_tick(std::time::Duration::from_millis(100));

	let mut post_id_to_filehash = HashMap::new();

	// Query in batches
	for batch in broken_symlinks.chunks(1000) {
		// Prepare danbooru ids for query
		let danbooru_ids: Vec<i64> = batch.iter().map(|b| b.danbooru_id.try_into().unwrap()).collect();

		// Query for filehashes
		let mut rows = sqlx::query_as::<_, (i64, Vec<u8>, Vec<u8>)>(
			"SELECT p.post_id, p.md5_hash, h.file_hash FROM posts AS p JOIN hash_to_filehash AS h ON h.booru_hash = p.md5_hash WHERE p.booru = 'danbooru' AND p.post_id = ANY($1)")
			.bind(&danbooru_ids)
			.fetch(&pool);

		while let Some(row) = rows.next().await {
			let (post_id, md5_hash, filehash) = row.context("failed to fetch row from database")?;
			let md5_hash: [u8; 16] = md5_hash.try_into().expect("md5_hash length mismatch");
			let filehash: [u8; 32] = filehash.try_into().expect("filehash length mismatch");

			post_id_to_filehash.insert(post_id as u64, (md5_hash, filehash));
			pb.inc(1);
		}
	}

	pb.finish_and_clear();
	info!("Found new filehashes for {} broken symlinks in {:?}", post_id_to_filehash.len(), pb.elapsed());

	Ok(broken_symlinks
		.into_iter()
		.filter_map(|b| {
			let Some((md5_hash, filehash)) = post_id_to_filehash.get(&b.danbooru_id) else {
				warn!("No filehash found for {:?}", b);
				return None;
			};
			Some((b, *md5_hash, *filehash))
		})
		.collect())
}


/// For all the broken symlinks with new filehashes, verify that the booru file matches the expected md5 hash. Just to double check and make sure we didn't mess anything up.
async fn verify_booru_hashes(broken_symlinks: Vec<(BrokenSymlink, [u8; 16], [u8; 32])>) -> Result<Vec<BrokenSymlinkMapping>, anyhow::Error> {
	info!("Verifying booru hashes for broken symlinks");

	let pb = ProgressBar::new(broken_symlinks.len() as u64)
		.with_style(default_progress_style())
		.with_message("Verifying booru hashes");
	pb.enable_steady_tick(std::time::Duration::from_millis(100));

	// Stream the data to validation, doing blocking work on the blocking thread pool.
	let mappings: Vec<BrokenSymlinkMapping> = futures_util::stream::iter(broken_symlinks.into_iter())
		.map(move |(broken_symlink, md5_hash, filehash)| {
			async move {
				// Read file
				let filehash_hex = hex::encode(filehash);
				let booru_path = PathBuf::from(&BOORUS_PATH)
					.join(&filehash_hex[0..2])
					.join(&filehash_hex[2..4])
					.join(&filehash_hex);
				let filedata = match tokio::fs::read(&booru_path).await {
					Ok(data) => data,
					Err(err) => {
						warn!("Failed to read booru file ({:?}): {:?}", broken_symlink, err);
						return None;
					},
				};

				// Verify md5 hash matches
				let ok = tokio::task::spawn_blocking(move || {
					let mut hasher = md5::Md5::new();
					hasher.update(&filedata);
					let computed_md5 = hasher.finalize();
					computed_md5.as_slice() == md5_hash
				})
				.await
				.expect("blocking task panicked");

				if !ok {
					warn!("MD5 hash mismatch for booru file ({:?})", broken_symlink);
					return None;
				}

				Some(BrokenSymlinkMapping {
					symlink_path: broken_symlink.symlink_path.clone(),
					target_path: broken_symlink.target_path.clone(),
					danbooru_id: broken_symlink.danbooru_id,
					old_filehash: broken_symlink.old_filehash,
					new_filehash: ImageHash(filehash),
				})
			}
		})
		.buffer_unordered(16)
		.filter_map(|mapping| {
			let pb = pb.clone();
			async move {
				pb.inc(1);
				mapping
			}
		})
		.collect()
		.await;

	pb.finish_and_clear();
	info!("Verified {} booru hashes for broken symlinks in {:?}", mappings.len(), pb.elapsed());

	Ok(mappings)
}


/// Read the mapping file from disk.
fn read_mappings(path: &Path) -> Result<(HashMap<ImageHash, ImageHash>, Vec<BrokenSymlinkMapping>), anyhow::Error> {
	info!("Reading broken symlink mappings from {:?}", path);
	let file = File::open(path)?;
	let reader = BufReader::new(file);
	let mappings_json: Vec<BrokenSymlinkMapping> = serde_json::from_reader(reader)?;
	let mappings = mappings_json
		.iter()
		.map(|m| {
			let old_hash = ImageHash(m.old_filehash.0);
			let new_hash = ImageHash(m.new_filehash.0);
			(old_hash, new_hash)
		})
		.collect();

	Ok((mappings, mappings_json))
}


/// Adds any new images we need to the database.  This includes images that are currently in the inactive state.
async fn add_new_images(mappings: &HashMap<ImageHash, ImageHash>, db: &Database) -> Result<(), anyhow::Error> {
	info!("Adding new images.");
	let mut n_added = 0;
	let pb = progress_bar_with_default_style(Some(mappings.len()), Some("Adding new images to db"));

	for (_old_filehash, new_filehash) in pb.wrap_iter(mappings.iter()) {
		n_added += if db.add_image(*new_filehash, UserId(0x1234feed)).await? { 1 } else { 0 };
	}

	info!("Added {} new hashes to hash table", n_added);

	Ok(())
}


/// Adds any new symlinks that will be needed for the new images.
async fn add_new_symlinks(mappings: &[BrokenSymlinkMapping], symlink_dir: &Path) -> Result<(), anyhow::Error> {
	info!("Adding new symlinks.");
	let pb = progress_bar_with_default_style(Some(mappings.len()), Some("Adding new symlinks"));
	let mut symlinks_added = 0;

	for mapping in pb.wrap_iter(mappings.iter()) {
		// Create new symlink
		let filehash_hex = hex::encode(mapping.new_filehash.0);
		let parent_path = symlink_dir.join(&filehash_hex[0..2]).join(&filehash_hex[2..4]);
		let path = parent_path.join(&filehash_hex);
		let target = PathBuf::from(BOORUS_PATH)
			.join(&filehash_hex[0..2])
			.join(&filehash_hex[2..4])
			.join(&filehash_hex);

		if path.exists() {
			// Symlink already exists
			continue;
		}

		if !target.exists() {
			error!("Target file for new symlink does not exist: {:?}", target);
			continue;
		}

		// Resolve target path
		let target = tokio::fs::canonicalize(target).await?;

		// Create parent directories if needed
		tokio::fs::create_dir_all(&parent_path).await?;

		// Create a temporary file first
		let temp_file = tempfile::NamedTempFile::new_in(&parent_path)?;
		let temp_path = temp_file.path().to_path_buf();
		drop(temp_file); // Close the file so we can create a symlink at that path
		tokio::fs::symlink(&target, &temp_path).await?;

		// Rename to final path (atomic operation)
		tokio::fs::rename(&temp_path, &path).await?;

		symlinks_added += 1;
	}

	info!("Added {} new symlinks out of {}", symlinks_added, mappings.len());

	Ok(())
}


/// Creates a mapping from old image ids to new image ids based on the given broken symlink mappings and the database.
/// Ensures that there is _no_ overlap between old and new image ids.  If there is, something went wrong, and further processing will cause issues.
async fn create_id_mapping(mappings: &HashMap<ImageHash, ImageHash>, db: &Database) -> Result<HashMap<ImageId, ImageId>, anyhow::Error> {
	info!("Creating old image id to new image id mapping.");
	let mut id_mapping = HashMap::new();
	let pb = progress_bar_with_default_style(Some(mappings.len()), Some("Creating id mapping"));

	for (old_filehash, new_filehash) in pb.wrap_iter(mappings.iter()) {
		let Some(old_image_id) = db.get_image_id(old_filehash).await else {
			warn!("Old filehash {:?} not found in database", old_filehash);
			continue;
		};

		let Some(new_image_id) = db.get_image_id(new_filehash).await else {
			warn!("New filehash {:?} not found in database", new_filehash);
			continue;
		};

		id_mapping.insert(old_image_id, new_image_id);
	}

	// Verify no overlap
	let old_ids = id_mapping.keys().collect::<HashSet<_>>();
	let new_ids = id_mapping.values().collect::<HashSet<_>>();
	assert!(old_ids.is_disjoint(&new_ids), "Old and new image ids overlap!");

	info!("Created id mapping for {} images", id_mapping.len());

	// Write out id mapping for reference
	info!("Writing out old to new image id mapping to danbooru_old_id_to_new_id_mapping.json");
	let mut writer = BufWriter::new(File::create("danbooru_old_id_to_new_id_mapping.json")?);
	serde_json::to_writer_pretty(&mut writer, &id_mapping)?;
	info!("Wrote out id mapping for {} images", id_mapping.len());

	Ok(id_mapping)
}


async fn read_id_mapping() -> Result<HashMap<ImageId, ImageId>, anyhow::Error> {
	// Load mapping from file
	let id_mapping: HashMap<ImageId, ImageId> = {
		let file = File::open("danbooru_old_id_to_new_id_mapping.json")?;
		let reader = BufReader::new(file);
		serde_json::from_reader(reader)?
	};

	Ok(id_mapping)
}


/// For each of the broken images we want to port its tag state over to the new image, sometimes having to merge if the new image already existed.
/// NOTE: Will _NOT_ remove tags from the new image that were not present on the old image, to avoid data loss. Instead a log is written out
/// listing tags that should be removed if desired.
async fn fix_tags(old_ids_to_new_ids: &HashMap<ImageId, ImageId>, db: &Database) -> Result<(), anyhow::Error> {
	// Get the old log ready to read
	info!("Mending image tags");
	let pb = progress_bar_with_default_style(Some(old_ids_to_new_ids.len()), Some("Mending tags"));
	let mut tags_to_remove = HashMap::new();

	for (old_image_id, new_image_id) in pb.wrap_iter(old_ids_to_new_ids.iter()) {
		assert_ne!(*old_image_id, *new_image_id);
		let images_lock = db.images.read().await;
		let old_image = db.get_image_by_id(*old_image_id, &images_lock).await.expect("failed to get old image");
		let new_image = db.get_image_by_id(*new_image_id, &images_lock).await.expect("failed to get new image");

		// Merge tags from old image to new image
		// NOTE: If a tag already exists on the new image we don't check the blame id, so those might not match up perfectly on the new images.
		// NOTE: Otherwise we use the blame id from the old image.
		let tags_to_add: Vec<_> = old_image
			.tags
			.iter()
			.filter_map(|(tag_id, user_id)| {
				if new_image.tags.contains_key(tag_id) {
					None
				} else {
					Some((*tag_id, *user_id))
				}
			})
			.collect();

		for tag_id in new_image.tags.keys() {
			if !old_image.tags.contains_key(tag_id) {
				tags_to_remove.entry(*new_image_id).or_insert_with(Vec::new).push(*tag_id);
			}
		}
		drop(images_lock);

		for (tag_id, user_id) in tags_to_add {
			match db.add_image_tag(*new_image_id, tag_id, user_id).await? {
				StateUpdateResult::ErrorImageDoesNotExist | StateUpdateResult::ErrorTagDoesNotExist => panic!("Image or tag does not exist when adding tag!"),
				_ => {},
			}
		}
	}

	// Write out tags to remove
	info!("Writing out tags to remove for new images");
	let mut writer = BufWriter::new(File::create("danbooru_tags_to_remove.json")?);
	serde_json::to_writer_pretty(&mut writer, &tags_to_remove)?;

	Ok(())
}


/// For each of the broken images we want to port its attribute state over to the new image, sometimes having to merge if the new image already existed.
/// NOTE: Will _NOT_ remove existing attributes except in the case of singular attributes where it might overwrite.
async fn fix_attributes(old_ids_to_new_ids: &HashMap<ImageId, ImageId>, db: &Database) -> Result<(), anyhow::Error> {
	let singular_attribute_keys_str = [
		"gelbooru_score",
		"gelbooru_tags",
		"gelbooru_post_id",
		"e621_post_id",
		"e621_score",
		"e621_rating",
		"e621_tags",
		"e621_untranslated_tags",
		"rule34_score",
		"rule34_post_id",
		"rule34_tags",
		"danbooru_post_id",
		"danbooru_score",
		"danbooru_rating",
		"danbooru_tags",
		"realbooru_tags",
		"realbooru_score",
		"realbooru_post_id",
		"alltags",
		"alltags_type",
		"rng_tags",
		"caption",
		"watermark_detections",
		"caption_prompt",
		"caption_prompt_key",
		"vqa_category",
		"training_prompt",
		"questionAnswer",
	];
	let mut singular_attribute_keys: HashSet<AttributeKeyId> = HashSet::new();
	for s in singular_attribute_keys_str.iter() {
		singular_attribute_keys.insert(db.get_string_id(s).await.unwrap().0.into());
	}

	// These get automatically refreshed, so it's fine if we mess with them
	let dont_care_keys_str = [
		"gelbooru_score",
		"gelbooru_tags",
		"gelbooru_post_id",
		"e621_post_id",
		"e621_score",
		"e621_rating",
		"e621_tags",
		"e621_untranslated_tags",
		"rule34_score",
		"rule34_post_id",
		"rule34_tags",
		"danbooru_post_id",
		"danbooru_score",
		"danbooru_rating",
		"danbooru_tags",
		"realbooru_tags",
		"realbooru_score",
		"realbooru_post_id",
		"watermark_detections",
	];
	let mut dont_care_keys: HashSet<AttributeKeyId> = HashSet::new();
	for s in dont_care_keys_str.iter() {
		dont_care_keys.insert(db.get_string_id(s).await.unwrap().0.into());
	}

	info!("Mending image attributes");
	let pb = progress_bar_with_default_style(Some(old_ids_to_new_ids.len()), Some("Mending attributes"));
	let mut attributes_added = 0;
	let mut conflicts = Vec::new();

	for (old_image_id, new_image_id) in pb.wrap_iter(old_ids_to_new_ids.iter()) {
		assert_ne!(*old_image_id, *new_image_id);
		let images_lock = db.images.read().await;
		let old_image = db.get_image_by_id(*old_image_id, &images_lock).await.expect("failed to get old image");
		let old_image_attributes = old_image.attributes.clone();
		let new_image = db.get_image_by_id(*new_image_id, &images_lock).await.expect("failed to get new image");
		let new_image_attributes = new_image.attributes.clone();
		drop(images_lock);

		// Merge attributes from old image to new image
		for (attr_key, attr_values) in &old_image_attributes {
			let is_singular = singular_attribute_keys.contains(attr_key);

			if is_singular {
				assert_eq!(
					attr_values.len(),
					1,
					"Singular attribute {} has multiple values on old image id {:?}",
					attr_key,
					old_image_id
				);
				let (attr_value, attr_user) = attr_values.iter().next().unwrap();
				if let Some((new_image_value, _)) = new_image_attributes.get(attr_key).and_then(|vals| vals.iter().next()) {
					// If it's a singular attribute, which means we'll end up overwriting it, and the value is different, log a conflict
					// Unless it's something we don't care about in which case we'll just overwrite it
					if new_image_value != attr_value && !dont_care_keys.contains(attr_key) {
						conflicts.push(json!({
							"old_image_id": old_image_id.0,
							"new_image_id": new_image_id.0,
							"attribute_key": attr_key.0,
							"old_attribute_value": attr_value.0,
							"new_attribute_value": new_image_value.0,
						}));
						continue;
					}
				}

				match db._add_image_attribute_singular(*new_image_id, *attr_key, *attr_value, *attr_user).await? {
					StateUpdateResult::Updated(_) => attributes_added += 1,
					StateUpdateResult::ErrorImageDoesNotExist | StateUpdateResult::ErrorTagDoesNotExist => {
						panic!("Image or attribute does not exist when adding singular attribute!")
					},
					_ => {},
				}
			} else {
				for (attr_value, attr_user) in attr_values {
					match db._add_image_attribute(*new_image_id, *attr_key, *attr_value, *attr_user).await? {
						StateUpdateResult::Updated(_) => attributes_added += 1,
						StateUpdateResult::ErrorImageDoesNotExist | StateUpdateResult::ErrorTagDoesNotExist => {
							panic!("Image or attribute does not exist when adding attribute!")
						},
						_ => {},
					}
				}
			}
		}
	}

	info!("Added {} attributes to new images", attributes_added);

	info!("Writing {} attribute conflicts to danbooru_attribute_conflicts.json", conflicts.len());
	let mut writer = BufWriter::new(File::create("danbooru_attribute_conflicts.json")?);
	serde_json::to_writer_pretty(&mut writer, &conflicts)?;
	info!("Wrote attribute conflicts to danbooru_attribute_conflicts.json");

	Ok(())
}


async fn fix_smalldb_task_queue(old_ids_to_new_ids: &HashMap<ImageId, ImageId>, db: &Database) -> Result<(), anyhow::Error> {
	info!("Fixing smalldb task queue");
	let updates = {
		let task_queue = db.task_queue.read().await;
		let pb = progress_bar_with_default_style(Some(task_queue.len()), Some("Scanning smalldb task queue"));
		let mut updates = Vec::new();

		for (task_id, (task_entry, _row_id)) in pb.wrap_iter(task_queue.iter()) {
			// Parse task data
			let task_data = match serde_json::from_str::<serde_json::Value>(&task_entry.data) {
				Ok(d) => d,
				Err(err) => {
					warn!("Failed to parse task data for task id {:?}: {}", task_id, err);
					continue;
				},
			};

			// Look for a field named "image_id" and see if it needs to be updated
			let Some(old_image_id_value) = task_data.get("image_id") else {
				continue;
			};

			let Some(old_image_id_u64) = old_image_id_value.as_u64() else {
				continue;
			};

			let old_image_id = ImageId(old_image_id_u64);
			let Some(new_image_id) = old_ids_to_new_ids.get(&old_image_id) else {
				continue;
			};

			// Inject new image id into task data
			let mut new_task_data = task_data.clone();
			new_task_data["image_id"] = serde_json::Value::Number(serde_json::Number::from(new_image_id.0));

			// Serialize back to a string
			let new_task_data = serde_json::to_string(&new_task_data).context("failed to serialize updated task data")?;

			updates.push((*task_id, new_task_data));
		}
		info!("Found {} tasks to update in smalldb task queue", updates.len());
		updates
	};

	// Apply updates
	let pb = progress_bar_with_default_style(Some(updates.len()), Some("Updating smalldb task queue"));

	for (task_id, new_task_data) in pb.wrap_iter(updates.into_iter()) {
		let task_queue = db.task_queue.write().await;
		db.update_task(task_id, Some(new_task_data), None, None, None, task_queue).await?;
	}

	info!("Updated tasks in smalldb task queue");

	Ok(())
}


/// Removes the old images from the database
async fn remove_old_images(old_ids_to_new_ids: HashMap<ImageId, ImageId>, mappings: Vec<BrokenSymlinkMapping>, db: &Database) -> Result<(), anyhow::Error> {
	assert_eq!(old_ids_to_new_ids.len(), mappings.len(), "Old to new id mapping length mismatch");

	info!("Removing old images from database");
	let mut n_removed = 0;
	let pb = progress_bar_with_default_style(Some(old_ids_to_new_ids.len()), Some("Removing old images"));

	for (old_image_id, _new_image_id) in pb.wrap_iter(old_ids_to_new_ids.into_iter()) {
		if db.remove_image(old_image_id, UserId(0x1234feed)).await? {
			n_removed += 1;
		}
	}

	info!("Removed {} old images from database", n_removed);

	info!("Removing old symlinks from tag-machine images directory");
	let mut n_removed = 0;
	let pb = progress_bar_with_default_style(Some(mappings.len()), Some("Removing old symlinks"));

	for mapping in pb.wrap_iter(mappings.into_iter()) {
		if std::fs::remove_file(&mapping.symlink_path).is_ok() {
			n_removed += 1;
		}
	}

	info!("Removed {} old symlinks from tag-machine images directory", n_removed);

	Ok(())
}
