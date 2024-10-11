use clap::Parser;
use std::env;
use std::path::{Path, PathBuf};
use std::fs;
use dirs;
use tendermint_light_client_verifier::{
    options::Options, types::LightBlock, ProdVerifier, Verdict, Verifier,
};
use hex;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    crs_directory: Option<String>,
    #[arg(short, long)]
    tm_rpc: Option<String>,
    #[arg(short, long)]
    server_url: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct BasicHeaderResponse {
    hash: String,
    height: u64,
}

pub fn strip_header(header: &LightBlock) -> BasicHeaderResponse {
    let hash = header.signed_header.header().hash().as_bytes().to_vec();
    BasicHeaderResponse {
        hash: hex::encode(hash),
        height: header.height().value(),
    }
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

pub fn get_server_url() -> String {
    let args = Args::parse();
    if let Some(server_url) = args.server_url {
        server_url
    }
    // Check environment variable
    else if let Ok(server_url) = env::var("SERVER_URL") {
        server_url
    }
    else {
        "0.0.0.0:8000".to_string()
    }
}

pub fn get_tendermint_rpc_url() -> Result<String, String> {
    Args::parse().tm_rpc
        .or_else(|| env::var("TM_RPC").ok())
        .ok_or_else(|| "TM_RPC is not set".to_string())
}