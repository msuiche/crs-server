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
    ln_url: Option<String>,
    #[arg(long)]
    ln_auth: Option<String>,
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

pub fn get_ln_url() -> String {
    Args::parse().ln_url
        .or_else(|| env::var("LN_URL").ok())
        .unwrap_or_else(|| "ws://localhost:26658".to_string())
}

pub fn get_celestia_node_auth_token() -> Result<String, String> {
    Args::parse().ln_auth
        .or_else(|| env::var("CELESTIA_NODE_AUTH_TOKEN").ok())
        .ok_or_else(|| "CELESTIA_NODE_AUTH_TOKEN is not set".to_string())
}