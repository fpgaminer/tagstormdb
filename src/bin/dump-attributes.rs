/// This program reads and dumps all of the image attributes to JSON on stdout.
/// For debugging and such.
use std::{collections::HashMap, io::BufWriter, path::PathBuf};

use clap::Parser;
use env_logger::Env;
use tagstormdb::Database;


#[derive(Parser, Debug)]
#[command()]
struct Args {
	/// Path to the source database.
	#[arg(long, default_value = "/home/night/tag-rust-db/db")]
	source_database: PathBuf,
}


#[actix_web::main]
async fn main() -> Result<(), anyhow::Error> {
	// Env logger
	env_logger::Builder::from_env(Env::default().default_filter_or("warn,tagstormdb=debug,dump_small_db=info")).init();

	// Parse command line arguments
	let args = Args::parse();

	// Load database
	let db = Database::open(&args.source_database, true).await?;

	// Iterate over all images and dump attributes
	let mut images = HashMap::new();
	let lock = db.images.read().await;
	for (key, image) in lock.iter() {
		images.insert(key, &image.attributes);
	}

	// Dump as JSON to stdout
	let writer = BufWriter::new(std::io::stdout());
	serde_json::to_writer_pretty(writer, &images)?;

	Ok(())
}
