/// This program reads the SmallDB part of the database and dumps everything to JSON.
/// For debugging and such.
use std::{io::BufWriter, path::PathBuf};

use clap::Parser;
use env_logger::Env;
use tagstormdb::{database::SmallDbEntry, small_db::SmallDb};


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

	let mut entries = Vec::new();
	SmallDb::open(&args.source_database.join("small_db.bin"), |_row_id, row: SmallDbEntry| {
		entries.push(row);
	})?;

	// Dump as JSON to stdout
	let writer = BufWriter::new(std::io::stdout());
	serde_json::to_writer_pretty(writer, &entries)?;

	Ok(())
}
