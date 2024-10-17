mod utils;
use tm_rpc_utils::TendermintRPCClient;
use utils::{get_crs_directory, get_tendermint_rpc_url, get_server_url, strip_header};
use celestia_rpc::{
    HeaderClient,
    ShareClient,
    Client,
};

use tendermint_light_client_verifier::{
    options::Options, types::LightBlock, ProdVerifier, Verdict, Verifier,
};

use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    fs,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use sp1_sdk::{HashableKey};
use sp1_sdk::{SP1Proof, SP1ProofWithPublicValues};
use sp1_sdk::{ProverClient, SP1Stdin};
use actix_web::{App, HttpServer, web, Responder, HttpResponse};
use actix_cors::Cors;
mod tm_rpc_utils;
mod tm_rpc_types;

use std::path::Path;
// use tokio::signal;

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const ELF: &[u8] = include_bytes!("../riscv32im-succinct-zkvm-elf");

pub async fn stark_proof_worker(app_state: web::Data<AppState>) {
    println!("Started STARK proof worker");
    loop {
        match stark_proof_iteration(&app_state).await {
            Ok(_) => println!("STARK proof iteration completed successfully"),
            Err(e) => eprintln!("Error in STARK proof worker: {}", e),
        }

        // Sleep for 5 minutes before the next iteration
        tokio::time::sleep(std::time::Duration::from_secs(5 * 60)).await;
    }
}

async fn stark_proof_iteration(app_state: &web::Data<AppState>) -> Result<(), Box<dyn std::error::Error>> {
    let proof_public_values = app_state.latest_proof.lock()
        .map_err(|e| format!("Failed to lock latest_proof: {}", e))?
        .as_ref()
        .ok_or_else(|| "No latest proof available")?
        .public_values.to_vec();
    let latest_proof_inner = match app_state.latest_proof.lock()
        .map_err(|e| format!("Failed to lock latest_proof: {}", e))?
        .as_ref()
        .ok_or_else(|| "No latest proof available")?
        .proof.clone()
    {
        SP1Proof::Compressed(c) => *c,
        _ => return Err("Not the right kind of SP1 proof".into()),
    };

    // Get the network head
    let latest_height = app_state.client.get_latest_block_height().await;
    let peer_id = app_state.client.fetch_peer_id().await?;
    let net_head = app_state.client.fetch_light_block(latest_height, peer_id).await?;

    let header_to_try = find_valid_header(app_state, net_head).await?;

    let prover_client = ProverClient::new();
    let (pk, vk) = prover_client.setup(ELF);
    let mut stdin = SP1Stdin::new();
    stdin.write(&vk.hash_u32());
    stdin.write(&proof_public_values);
    stdin.write_vec(app_state.genesis_header.signed_header.header.hash().as_bytes().to_vec());
    let encoded1 = serde_cbor::to_vec(&app_state.newest_header.lock()
        .map_err(|e| format!("Failed to lock newest_header: {}", e))?
        .as_ref()
        .ok_or_else(|| "No newest header available")?)
        .map_err(|e| format!("Failed to cbor encode newest_header: {}", e))?;
    stdin.write_vec(encoded1);
    let encoded2 = serde_cbor::to_vec(&header_to_try)
        .map_err(|e| format!("Failed to cbor encode net_head: {}", e))?;
    stdin.write_vec(encoded2);
    stdin.write_proof(latest_proof_inner, vk.vk);

    let start_time = std::time::Instant::now();
    let resultant_proof = prover_client.prove(&pk, stdin).compressed().run()
        .map_err(|e| format!("Failed to generate CompressedSTARK proof: {}", e))?;
    let elapsed_time = start_time.elapsed();
    println!("Elapsed time for CompressedSTARK proof generation: {:?}", elapsed_time);

    // Write the updated net head to the newest_header_file
    std::fs::write(
        app_state.app_dir.join("newest_header.json"),
        serde_json::to_string(&header_to_try)?
    ).map_err(|e| format!("Failed to write newest_header.json: {}", e))?;

    // Write the new proof to the proof_file
    std::fs::write(
        app_state.app_dir.join("newest_proof.json"),
        serde_json::to_string(&resultant_proof)?
    ).map_err(|e| format!("Failed to write newest_proof.json: {}", e))?;

    // update the values in the server state
    *app_state.newest_header.lock()
        .map_err(|e| format!("Failed to lock newest_header: {}", e))? = Some(header_to_try);
    *app_state.latest_proof.lock()
        .map_err(|e| format!("Failed to lock latest_proof: {}", e))? = Some(resultant_proof);
    println!("Proved header height {:?}", app_state.newest_header.lock()
        .map_err(|e| format!("Failed to lock newest_header: {}", e))?
        .as_ref()
        .ok_or_else(|| "No newest header available")?
        .height());

    Ok(())
}

async fn find_valid_header(app_state: &web::Data<AppState>, mut header_to_try: LightBlock) -> Result<LightBlock, Box<dyn std::error::Error>> {
    loop {
        let vp = ProdVerifier::default();
        let opt = Options {
            trust_threshold: Default::default(),
            trusting_period: Duration::from_secs(14 * 24 * 60 * 60),
            clock_drift: Default::default(),
        };
        let verify_time = header_to_try.time() + Duration::from_secs(20);
        let verdict = vp.verify_update_header(
            header_to_try.clone().as_untrusted_state(),
            app_state.newest_header.lock().unwrap().as_ref().unwrap().as_trusted_state(),
            &opt,
            verify_time.map_err(|_| "Invalid header time")?,
        );
        match verdict {
            Verdict::Success => return Ok(header_to_try),
            _ => {
                let highest_proved_height = app_state.newest_header.lock().unwrap().as_ref().unwrap().height().value();
                let height_to_try = highest_proved_height + ((header_to_try.height().value() - highest_proved_height) / 2);
                println!("backing up by half to height: {}", height_to_try);
                let peer_id = app_state.client.fetch_peer_id().await?;
                header_to_try = app_state.client.fetch_light_block(height_to_try, peer_id).await?;
            },
        }
    }
}

// This is a copy-paste of the stark_proof_worker, that will call ".groth16()" instead of ".compressed()"
// Unfortunately, Succinct has not allowed us to obtain ComrpessedStark + Groth16 from a single call,
// so we have to waste resources :(
// To minimize wasted resources, we will limit this worker to run once every 10 minutes or so.
pub async fn groth_proof_worker(app_state: web::Data<AppState>) {
    println!("Started Groth16 proof worker");
    loop {
        match groth_proof_iteration(&app_state).await {
            Ok(_) => println!("Groth16 proof iteration completed successfully"),
            Err(e) => eprintln!("Error in Groth16 proof worker: {}", e),
        }

        tokio::time::sleep(std::time::Duration::from_secs(10 * 60)).await;
    }
}

async fn groth_proof_iteration(app_state: &web::Data<AppState>) -> Result<(), Box<dyn std::error::Error>> {
    let proof_public_values = app_state.latest_proof.lock().unwrap().as_ref().unwrap().public_values.to_vec();
    let latest_proof_inner = *match app_state.latest_proof.lock().unwrap().as_ref().unwrap().proof.clone() {
        SP1Proof::Compressed(c) => c,
        _ => panic!("Not the right kind of SP1 proof")
    };

    // Get the network head
    let latest_height = app_state.client.get_latest_block_height().await;
    let peer_id = app_state.client.fetch_peer_id().await.expect("could not fetch peer ID");
    let net_head = app_state.client.fetch_light_block(latest_height, peer_id).await.expect("could not fetch latest head");

    let mut header_to_try = net_head.clone();
    let mut keep_trying = true;
    while keep_trying {
        let vp = ProdVerifier::default();
        let opt = Options {
            trust_threshold: Default::default(),
            // 2 week trusting period.
            trusting_period: Duration::from_secs(14 * 24 * 60 * 60),
            clock_drift: Default::default(),
        };
        let verify_time = header_to_try.time() + Duration::from_secs(20);
        let verdict = vp.verify_update_header(
            header_to_try.clone().as_untrusted_state(),
            app_state.newest_header.lock().unwrap().as_ref().unwrap().as_trusted_state(),
            &opt,
            verify_time.unwrap(),
        );
        match verdict {
            Verdict::Success => {
                println!("this height worked.");
                keep_trying = false;
            },
            _ => {
                let highest_proved_height = app_state.newest_header.lock().unwrap().as_ref().unwrap().height().value();
                let height_to_try = highest_proved_height + ((header_to_try.height().value() - highest_proved_height) / 2);
                println!("backing up by half to height: {}", height_to_try);
                header_to_try = app_state.client.fetch_light_block(height_to_try, peer_id).await.expect("could not fetch height_to_try"); 
            },
        }
    }

    let prover_client = ProverClient::new();
    let (pk, vk) = prover_client.setup(ELF);
    let mut stdin = SP1Stdin::new();
    stdin.write(&vk.hash_u32());
    stdin.write(&proof_public_values);
    stdin.write_vec(app_state.genesis_header.signed_header.header.hash().as_bytes().to_vec());
    let encoded1 = serde_cbor::to_vec(&app_state.newest_header.lock().unwrap().as_ref().unwrap()).expect("Failed to cbor encode newest_header");
    stdin.write_vec(encoded1);
    let encoded2 = serde_cbor::to_vec(&header_to_try).expect("Failed to cbor encode net_head");
    stdin.write_vec(encoded2);
    stdin.write_proof(latest_proof_inner, vk.vk);

    let start_time = std::time::Instant::now();
    let resultant_groth16_proof = match prover_client.prove(&pk, stdin).groth16().run() {
        Ok(proof) => proof,
        Err(e) => {
            eprintln!("Failed to generate Groth16 proof: {:?}", e);
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Groth16 proof generation failed: {}", e)
            )));
        }
    };
    let elapsed_time = start_time.elapsed();
    println!("Elapsed time for Groth16 proof generation: {:?}", elapsed_time);
    // Write the updated net head to the newest_header_file
    match std::fs::write(app_state.app_dir.join("newest_groth16_proved_header.json"), serde_json::to_string(&header_to_try).expect("could not serialize")) {
        Ok(_) => println!("Successfully wrote newest_groth16_proved_header.json"),
        Err(e) => eprintln!("Failed to write newest_groth16_proved_header.json: {}", e),
    }

    match std::fs::write(app_state.app_dir.join("newest_groth16_proof.json"), serde_json::to_string(&resultant_groth16_proof).expect("could not json serialize new groth16 proof")) {
        Ok(_) => println!("Successfully wrote newest_groth16_proof.json"),
        Err(e) => eprintln!("Failed to write newest_groth16_proof.json: {}", e),
    }
    let groth_inner = resultant_groth16_proof.clone().proof.try_as_groth_16().expect("not a groth16 proof");
    // Write the new proof to the proof_file
    match std::fs::write(app_state.app_dir.join("newest_groth16_proof_inner.json"), serde_json::to_string(&groth_inner).expect("could not json serialize new groth16 proof")) {
        Ok(_) => println!("Successfully wrote newest_groth16_proof_inner.json"),
        Err(e) => eprintln!("Failed to write newest_groth16_proof_inner.json: {}", e),
    }
    // Write a bincode version as well
    match std::fs::write(app_state.app_dir.join("newest_groth16_proof_inner.bin"), bincode::serialize(&groth_inner).expect("could not json serialize new groth16 proof")) {
        Ok(_) => println!("Successfully wrote newest_groth16_proof_inner.bin"),
        Err(e) => eprintln!("Failed to write newest_groth16_proof_inner.bin: {}", e),
    }
    // update the values in the server state
    *app_state.latest_groth16_header.lock().unwrap() = Some(header_to_try);
    *app_state.latest_groth16_proof.lock().unwrap() = Some(resultant_groth16_proof);
    println!("Groth16 proved header height {:?}", app_state.newest_header.lock().unwrap().as_ref().unwrap().height());
    let ten_mins = std::time::Duration::from_secs(10 * 60);
    let sleep_duration = ten_mins.saturating_sub(elapsed_time);
    std::thread::sleep(sleep_duration);

    Ok(())
}

async fn get_latest_header(app_state: web::Data<AppState>) -> impl Responder {
    match app_state.newest_header.lock().unwrap().clone() {
        Some(header) => HttpResponse::Ok().json(header),
        None => HttpResponse::NotFound().body("No latest header available"),
    }
}

/*async fn get_latest_groth16_proved_stripped_header(app_state: web::Data<AppState>) -> impl Responder {
    let stripped = app_state.latest_groth16_header.lock().unwrap().clone()
}

async fn get_net_stripped_header(app_state: web::Data<AppState>) -> impl Responder {
    HttpResponse::Ok().json(app_state.latest_groth16_header.lock().unwrap().clone())
}*/

async fn get_latest_groth16_proved_header(app_state: web::Data<AppState>) -> impl Responder {
    HttpResponse::Ok().json(app_state.latest_groth16_header.lock().unwrap().clone())
}

async fn get_latest_groth16_proved_stripped_header(app_state: web::Data<AppState>) -> impl Responder {
    let h = app_state.latest_groth16_header.lock().unwrap().clone().map_or(None, |h| {Some(strip_header(&h))});
    HttpResponse::Ok().json(h)
}

async fn get_net_head_stripped(app_state: web::Data<AppState>) -> impl Responder {
    let peer_id = match app_state.client.fetch_peer_id().await {
        Ok(id) => id,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Failed to fetch peer ID: {}", e)),
    };
    let net_height = app_state.client.get_latest_block_height().await;
    let head = match app_state.client.fetch_light_block(net_height, peer_id).await {
        Ok(lb) => strip_header(&lb),
        Err(e) => return HttpResponse::InternalServerError().body(format!("Failed to fetch net head: {}", e)),
    };
    HttpResponse::Ok().json(head)
}

async fn get_latest_proof(app_state: web::Data<AppState>) -> impl Responder {
    match app_state.latest_proof.lock().unwrap().clone() {
        Some(proof) => HttpResponse::Ok().json(proof),
        None => HttpResponse::NotFound().body("No latest proof available"),
    }
}

async fn get_latest_groth16_proof(app_state: web::Data<AppState>) -> impl Responder {
    let r = app_state.latest_groth16_proof.lock().unwrap().clone();
    let proof = r.map_or_else(|| None, |p| p.proof.try_as_groth_16());
    HttpResponse::Ok().json(proof)
}

#[derive(Clone)]
pub struct AppState {
    pub app_dir: PathBuf,
    pub client: Arc<TendermintRPCClient>,
    pub newest_header: Arc<Mutex<Option<LightBlock>>>,
    pub latest_proof: Arc<Mutex<Option<SP1ProofWithPublicValues>>>,
    pub latest_groth16_header: Arc<Mutex<Option<LightBlock>>>,
    pub latest_groth16_proof: Arc<Mutex<Option<SP1ProofWithPublicValues>>>,
    pub genesis_header: LightBlock,
    pub celestia_client: Arc<Client>,
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    
    let app_dir = get_crs_directory()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("Could not open directory: {}", e)))?;

    let tm_rpc_url = get_tendermint_rpc_url()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("TM_RPC not set: {}", e)))?;

    let tm_client = tm_rpc_utils::TendermintRPCClient::new(tm_rpc_url);
    let peer_id = tm_client.fetch_peer_id().await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to fetch peer ID: {}", e)))?;

    // Load the "zk genesis" header
    let genesis_header: LightBlock = match std::fs::File::open(app_dir.join("genesis.json")) {
        Ok(file) => {
            serde_json::from_reader(file)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("Failed to parse genesis.json: {}", e)))?
        },
        Err(_) => {
            println!("Genesis file not found, getting it from the tendermint RPC.");
            let genesis = tm_client.fetch_light_block(1, peer_id).await
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("Could not fetch genesis from tendermint RPC: {}", e)))?;
            
            let file = std::fs::File::create(app_dir.join("genesis.json"))
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to create genesis.json: {}", e)))?;
            
            serde_json::to_writer(&file, &genesis)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to write genesis to genesis.json: {}", e)))?;
            
            genesis
        }
    };
    let newest_header: Arc<Mutex<Option<LightBlock>>> = match std::fs::File::open(app_dir.join("newest_header.json")) {
        Ok(file) => {
            match serde_json::from_reader(file) {
                Ok(header) => Arc::new(Mutex::new(Some(header))),
                Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("Failed to parse newest_header.json: {}", e))),
            }
        },
        Err(_) => Arc::new(Mutex::new(Some(genesis_header.clone()))), // Initialize with genesis header if file doesn't exist
    };

    let latest_proof: Arc<Mutex<Option<SP1ProofWithPublicValues>>> = match std::fs::File::open(app_dir.join("newest_proof.json")) {
        Ok(file) => {
            match serde_json::from_reader(file) {
                Ok(proof) => Arc::new(Mutex::new(Some(proof))),
                Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("Failed to deserialize proof: {}", e))),
            }
        },
        Err(_) => Arc::new(Mutex::new(None)), // Initialize with None if file doesn't exist
    };

    let latest_groth16_proof: Arc<Mutex<Option<SP1ProofWithPublicValues>>> = Arc::new(Mutex::new(
        match std::fs::File::open(app_dir.join("newest_groth16_proof.json")) {
            Ok(file) => {
                match serde_json::from_reader(file) {
                    Ok(proof) => Some(proof),
                    Err(_) => None,
                }
            },
            Err(_) => None,
        }
    ));

    let latest_groth16_proved_header: Arc<Mutex<Option<LightBlock>>> = Arc::new(Mutex::new(
        match std::fs::File::open(app_dir.join("newest_groth16_proved_header.json")) {
            Ok(file) => {
                match serde_json::from_reader(file) {
                    Ok(header) => Some(header),
                    Err(e) => {
                        eprintln!("Failed to deserialize newest_groth16_proved_header: {}", e);
                        None
                    },
                }
            },
            Err(_) => None,
        }
    ));

    let app_state = web::Data::new(AppState {
        app_dir: app_dir.clone(),
        client: Arc::new(tm_client),
        newest_header: newest_header.clone(),
        latest_proof: latest_proof.clone(),
        latest_groth16_proof: latest_groth16_proof.clone(),
        latest_groth16_header: latest_groth16_proved_header.clone(),
        genesis_header: genesis_header.clone(),
        celestia_client: Arc::new(
            Client::new("ws://localhost:26658", Some(&std::env::var("CELESTIA_TOKEN").expect("CELESTIA_TOKEN not set")))
                .await
                .expect("Failed creating Celestia RPC client"),
        ),
    });

    // Check if we need to run stark_proof_iteration once
    let newest_header_exists = std::path::Path::new(&app_dir).join("newest_header.json").exists();
    let newest_proof_exists = std::path::Path::new(&app_dir).join("newest_proof.json").exists();

    if !newest_header_exists || !newest_proof_exists {
        println!("Running initial stark_proof_iteration...");
        match stark_proof_iteration(&app_state).await {
            Ok(_) => println!("Initial stark_proof_iteration completed successfully"),
            Err(e) => eprintln!("Error in initial stark_proof_iteration: {}", e),
        }
    }

    let _stark_handle = tokio::spawn(stark_proof_worker(app_state.clone()));
    let _groth16_handle = tokio::spawn(groth_proof_worker(app_state.clone()));
    let _da_sync_handle = tokio::spawn(da_sync_worker(app_state.clone()));

    println!("Starting HTTP server on {}", get_server_url());
    let _server_handle = HttpServer::new(move || {

        let cors = Cors::permissive();

        App::new()
            .wrap(cors)
            .app_data(app_state.clone())
            .route("/header", web::get().to(get_latest_header))
            .route("/proof", web::get().to(get_latest_proof))
            .route("/groth16_proof", web::get().to(get_latest_groth16_proof))
            .route("/groth16_header", web::get().to(get_latest_groth16_proved_stripped_header))
            .route("/net_head", web::get().to(get_net_head_stripped))
            // Do we want this one?
            .route("/groth16_full_header", web::get().to(get_latest_groth16_proved_header))
        })
        .bind(get_server_url())?
        .run()
        .await;
        
        /*signal::ctrl_c().await?;
        println!("Shutting down gracefully");
        stark_handle.abort();
        groth16_handle.abort();
        server_handle.handle().stop(true).await;*/
        /* .handle()
        .into_future();*/
    // let (_, _, _, _) = tokio::join!(stark_handle, groth16_handle, server_handle, da_sync_handle);
    Ok(())
}

pub async fn da_sync_worker(app_state: web::Data<AppState>) {
    println!("Started DA sync worker");
    let eds_dir = app_state.app_dir.join("eds");
    fs::create_dir_all(&eds_dir).expect("Failed to create eds directory");

    loop {
        let celestia_client = app_state.celestia_client.clone();

        let network_head = celestia_client
            .header_network_head()
            .await
            .expect("Could not get network head");

        // Calculate the height from 3 weeks ago
        let three_weeks_ago = SystemTime::now() - Duration::from_secs(3 * 7 * 24 * 60 * 60);
        let three_weeks_ago_timestamp = three_weeks_ago
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        let mut current_height = get_last_synced_height(&eds_dir).unwrap_or(1);
        while current_height <= network_head.height().into() {
            let header = celestia_client
                .header_get_by_height(current_height)
                .await
                .expect("Could not get header");

            if header.time().unix_timestamp() as u64 >= three_weeks_ago_timestamp {
                sync_da_height(&app_state, &celestia_client, current_height, &eds_dir).await;
            } else {
                // Remove old EDS files
                let eds_file = eds_dir.join(format!("eds_{}.bin", current_height));
                if eds_file.exists() {
                    fs::remove_file(eds_file).expect("Failed to remove old EDS file");
                }
            }

            current_height += 1;
        }

        // Sleep for a short duration before the next sync attempt
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

async fn sync_da_height(_app_state: &web::Data<AppState>, client: &Client, da_height: u64, eds_dir: &Path) {
    let header = client
        .header_get_by_height(da_height)
        .await
        .expect("Could not get header");

    let eds = client.share_get_eds(&header).await.expect("Failed to get EDS");

    // Save EDS to file
    let eds_file = eds_dir.join(format!("eds_{}.bin", da_height));
    let eds_bytes = bincode::serialize(&eds).expect("Failed to serialize EDS");
    fs::write(eds_file, eds_bytes).expect("Failed to write EDS file");

    println!("Synced EDS for height {}", da_height);
}

fn get_last_synced_height(eds_dir: &Path) -> Option<u64> {
    fs::read_dir(eds_dir)
        .ok()?
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let file_name = entry.file_name().into_string().ok()?;
            if file_name.starts_with("eds_") && file_name.ends_with(".bin") {
                file_name[4..file_name.len() - 4].parse::<u64>().ok()
            } else {
                None
            }
        })
        .max()
}