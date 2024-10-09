use clap::Parser;
use std::env;
use std::path::{Path, PathBuf};
use std::fs;
use dirs;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    crs_directory: Option<String>,
    #[arg(short, long)]
    tm_rpc: Option<String>,
}

pub fn get_crs_directory() -> Result<PathBuf, String> {
    let dir = {
        // Check CLI argument
        let args = Args::parse();
        if let Some(dir) = args.crs_directory {
            PathBuf::from(dir)
        }
        // Check environment variable
        else if let Ok(dir) = env::var("CRS_DIR") {
            PathBuf::from(dir)
        }
        // Use home directory
        else if let Some(home_dir) = dirs::home_dir() {
            home_dir.join(".crs")
        }
        else {
            return Err("Unable to determine directory".to_string());
        }
    };

    // Create the directory if it doesn't exist
    if !dir.exists() {
        fs::create_dir_all(&dir)
            .map_err(|e| format!("Failed to create directory: {}", e))?;
    }

    Ok(dir)
}

pub fn get_tendermint_rpc_url() -> Result<String, String> {
    Args::parse().tm_rpc
        .or_else(|| env::var("TM_RPC").ok())
        .ok_or_else(|| "TM_RPC is not set".to_string())
}