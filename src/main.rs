mod utils;
use tm_rpc_utils::TendermintRPCClient;
use utils::{get_crs_directory, get_tendermint_rpc_url, get_server_url, strip_header};
use celestia_rpc::{
    HeaderClient,
    ShareClient,
    Client,
};
use celestia_types::{ExtendedHeader, Height, nmt::Namespace};
use celestia_rpc::BlobClient;

use tendermint_light_client_verifier::{
    options::Options, types::LightBlock, ProdVerifier, Verdict, Verifier,
};

use std::future::IntoFuture;
use std::io::Write;
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
    fs,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use sp1_sdk::{HashableKey, Prover, SP1VerifyingKey};
use sp1_sdk::{SP1Proof, SP1ProofWithPublicValues};
use sp1_sdk::{ProverClient, SP1Stdin};
use actix_web::{App, HttpServer, web, Responder, HttpResponse};
use actix_cors::Cors;
mod tm_rpc_utils;
mod tm_rpc_types;
// use tokio::signal;

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const ELF: &[u8] = include_bytes!("../riscv32im-succinct-zkvm-elf");

pub async fn stark_proof_worker(app_state: web::Data<AppState>) {
    println!("started stark worker");
    loop {

        /* Not sure, but I think it's best if we lock the mutex in-line like this,
           so it returns the lock after it's done. 
         */
        let proof_public_values = app_state.latest_proof.lock().unwrap().public_values.to_vec();
        let latest_proof_inner = *match app_state.latest_proof.lock().unwrap().proof.clone() {
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
                app_state.newest_header.lock().unwrap().as_trusted_state(),
                &opt,
                verify_time.unwrap(),
            );
            match verdict {
                Verdict::Success => {
                    println!("this height worked.");
                    keep_trying = false;
                },
                _ => {
                    let highest_proved_height = app_state.newest_header.lock().unwrap().height().value();
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
        let encoded1 = serde_cbor::to_vec(&app_state.newest_header).expect("Failed to cbor encode newest_header");
        stdin.write_vec(encoded1);
        let encoded2 = serde_cbor::to_vec(&header_to_try).expect("Failed to cbor encode net_head");
        stdin.write_vec(encoded2);
        stdin.write_proof(latest_proof_inner, vk.vk);

        let start_time = std::time::Instant::now();
        let resultant_proof = prover_client.prove(&pk, stdin).compressed().run().expect("could not prove");
        let elapsed_time = start_time.elapsed();
        println!("Elapsed time for CompressedSTARK proof generation: {:?}", elapsed_time);
        // Write the updated net head to the newest_header_file
        std::fs::write(app_state.app_dir.join("newest_header.json"), serde_json::to_string(&header_to_try).expect("could not json serialize net head after proving")).expect("Failed to write newest_header.json");
        // Write the new proof to the proof_file
        std::fs::write(app_state.app_dir.join("newest_proof.json"), serde_json::to_string(&resultant_proof).expect("could not json serialize new proof")).expect("Failed to write newest_proof.json");
        // update the values in the server state
        *app_state.newest_header.lock().unwrap() = header_to_try;
        *app_state.latest_proof.lock().unwrap() = resultant_proof;
        println!("proved header height {:?}", app_state.newest_header.lock().unwrap().height());
        let five_minute = std::time::Duration::from_secs(5 * 60);
        let sleep_duration = five_minute.saturating_sub(elapsed_time);
        std::thread::sleep(sleep_duration);

    }
}

// This is a copy-paste of the stark_proof_worker, that will call ".groth16()" instead of ".compressed()"
// Unfortunately, Succinct has not allowed us to obtain ComrpessedStark + Groth16 from a single call,
// so we have to waste resources :(
// To minimize wasted resources, we will limit this worker to run once every 10 minutes or so.
pub async fn groth_proof_worker(app_state: web::Data<AppState>) {
    println!("started groth16 worker");
    loop {

        /* Not sure, but I think it's best if we lock the mutex in-line like this,
           so it returns the lock after it's done. 
         */
        let proof_public_values = app_state.latest_proof.lock().unwrap().public_values.to_vec();
        let latest_proof_inner = *match app_state.latest_proof.lock().unwrap().proof.clone() {
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
                app_state.newest_header.lock().unwrap().as_trusted_state(),
                &opt,
                verify_time.unwrap(),
            );
            match verdict {
                Verdict::Success => {
                    println!("this height worked.");
                    keep_trying = false;
                },
                _ => {
                    let highest_proved_height = app_state.newest_header.lock().unwrap().height().value();
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
        let encoded1 = serde_cbor::to_vec(&app_state.newest_header).expect("Failed to cbor encode newest_header");
        stdin.write_vec(encoded1);
        let encoded2 = serde_cbor::to_vec(&header_to_try).expect("Failed to cbor encode net_head");
        stdin.write_vec(encoded2);
        stdin.write_proof(latest_proof_inner, vk.vk);

        let start_time = std::time::Instant::now();
        let resultant_groth16_proof = prover_client.prove(&pk, stdin).groth16().run().expect("could not prove");
        let elapsed_time = start_time.elapsed();
        println!("Elapsed time for groth16 proof generation: {:?}", elapsed_time);
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
        println!("groth16 proved header height {:?}", app_state.newest_header.lock().unwrap().height());
        let ten_mins = std::time::Duration::from_secs(10 * 60);
        let sleep_duration = ten_mins.saturating_sub(elapsed_time);
        std::thread::sleep(sleep_duration);

    }
}

async fn get_latest_header(app_state: web::Data<AppState>) -> impl Responder {
    HttpResponse::Ok().json(app_state.newest_header.lock().unwrap().clone())
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
    HttpResponse::Ok().json(app_state.latest_proof.lock().unwrap().clone())
}

async fn get_latest_groth16_proof(app_state: web::Data<AppState>) -> impl Responder {
    let r = app_state.latest_groth16_proof.lock().unwrap().clone();
    let proof = r.map_or_else(|| None, |p| p.proof.try_as_groth_16());
    HttpResponse::Ok().json(proof)
}

struct RollupState {
    sync_height: u64,
    block_height: u64,
    namespace: Namespace,
}

#[derive(Clone)]
pub struct AppState {
    pub app_dir: PathBuf,
    pub client: Arc<TendermintRPCClient>,
    pub newest_header: Arc<Mutex<LightBlock>>,
    pub latest_proof: Arc<Mutex<SP1ProofWithPublicValues>>,
    pub latest_groth16_header: Arc<Mutex<Option<LightBlock>>>,
    pub latest_groth16_proof: Arc<Mutex<Option<SP1ProofWithPublicValues>>>,
    pub genesis_header: LightBlock,
    pub rollup_state: Arc<Mutex<RollupState>>,
    pub celestia_client: Arc<Client>,
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let app_dir = get_crs_directory().expect("Could not open directory");
    let tm_rpc_url = get_tendermint_rpc_url().expect("TM_RPC not set");

    let tm_client = tm_rpc_utils::TendermintRPCClient::new(tm_rpc_url);
    let peer_id = tm_client.fetch_peer_id().await.unwrap();

    // Load the "zk genesis" header
    let genesis_file = std::fs::File::open(app_dir.join("genesis.json"));
    let genesis_header: LightBlock = if let Ok(file) = genesis_file {
        serde_json::from_reader(file).expect("Failed to parse genesis.json")
    } else {
        println!("Genesis file not found, getting it from the tendermint RPC.");
        let genesis = tm_client.fetch_light_block(1, peer_id).await.expect("could not fetch genesis from tendermint RPC");
        serde_json::to_writer(&mut std::fs::File::create(app_dir.join("genesis.json")).expect("Failed to create genesis.json"), &genesis).expect("Failed to write genesis to genesis.json");
        genesis
    };

    let newest_header_file = std::fs::File::open(app_dir.join("newest_header.json"))
        .expect("Failed to read newest_header.json");
    let newest_header: Arc<Mutex<LightBlock>> = Arc::new(Mutex::new(serde_json::from_reader(newest_header_file).expect("Failed to parse newest_header.json")));

    let proof_file = std::fs::File::open(app_dir.join("newest_proof.json")).expect("could not open newest_proof.json");
    let latest_proof: Arc<Mutex<SP1ProofWithPublicValues>> = Arc::new(Mutex::new(serde_json::from_reader(proof_file).expect("could not deserialize proof")));

    let groth16_proof_file = std::fs::File::open(app_dir.join("newest_groth16_proof.json"));
    let latest_groth16_proof: Arc<Mutex<Option<SP1ProofWithPublicValues>>> = Arc::new(Mutex::new(groth16_proof_file.map_err(|_| ()).map_or_else(|_| None, |file| {
        serde_json::from_reader(file).ok()
    })));

    let newest_groth16_proved_header_file = std::fs::File::open(app_dir.join("newest_groth16_proved_header.json"));
    let latest_groth16_proved_header: Arc<Mutex<Option<LightBlock>>> = Arc::new(Mutex::new(newest_groth16_proved_header_file.map_err(|_| ()).map_or_else(|_| None, |file| {
        serde_json::from_reader(file).expect("could not deserialize newest_groth16_proved_header")
    })));

    let app_state = web::Data::new(AppState {
        app_dir: app_dir,
        client: Arc::new(tm_client),
        newest_header: newest_header.clone(),
        latest_proof: latest_proof.clone(),
        latest_groth16_proof: latest_groth16_proof.clone(),
        latest_groth16_header: latest_groth16_proved_header.clone(),
        genesis_header: genesis_header,
        rollup_state: Arc::new(Mutex::new(RollupState {
            sync_height: std::env::var("START_HEIGHT")
                .expect("Start height not provided")
                .parse()
                .expect("Could not parse start height"),
            block_height: 1,
            namespace: Namespace::new(
                0,
                &std::env::var("ROLLUP_NAMESPACE")
                    .expect("Rollup namespace not provided")
                    .into_bytes(),
            )
            .expect("Invalid namespace"),
        })),
        celestia_client: Arc::new(
            Client::new("ws://localhost:26658", Some(&std::env::var("CELESTIA_TOKEN").expect("CELESTIA_TOKEN not set")))
                .await
                .expect("Failed creating Celestia RPC client"),
        ),
    });

    let stark_handle = tokio::spawn(stark_proof_worker(app_state.clone()));
    let groth16_handle = tokio::spawn(groth_proof_worker(app_state.clone()));
    let da_sync_handle = tokio::spawn(da_sync_worker(app_state.clone()));

    let server_handle = HttpServer::new(move || {

        let cors = Cors::permissive();

        App::new()
            .wrap(cors)
            .app_data(app_state.clone())
            .route("/header", web::get().to(get_latest_header))
            .route("/proof", web::get().to(get_latest_proof))
            .route("/groth16_proof", web::get().to(get_latest_groth16_proof))
            .route("/groth16_header", web::get().to(get_latest_groth16_proved_stripped_header))
            .route("/net_head", web::get().to(get_net_head_stripped))
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

        let mut current_height = app_state.rollup_state.lock().unwrap().sync_height;
        while current_height <= network_head.height().into() {
            let header = celestia_client
                .header_get_by_height(current_height)
                .await
                .expect("Could not get header");

            if header.time().unix_timestamp() as u64 >= three_weeks_ago_timestamp {
                sync_da_height(&app_state, &celestia_client, current_height).await;
            }

            current_height += 1;
        }

        // Update the sync height
        {
            let mut rollup_state = app_state.rollup_state.lock().unwrap();
            rollup_state.sync_height = network_head.height().value();
        }

        // Sleep for a short duration before the next sync attempt
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

async fn sync_da_height(app_state: &web::Data<AppState>, client: &Client, da_height: u64) {

    let namespace = app_state.rollup_state.lock().unwrap().namespace;
    let blobs = match client
            .blob_get_all(da_height, &[namespace])
            .await
    {
        Ok(Some(blobs)) => blobs,
        Ok(None) => Vec::new(),
        Err(e) => {
            eprintln!("Error getting blobs at height {}: {}", da_height, e);
            Vec::new()
        }
    };

    for blob in &blobs {
        // Assuming you have a Block struct and a deserialize method
        // let block = Block::deserialize(&blob.data);
        // Process the block...
        println!("Processing blob at height {}", da_height);
    }

    // Update the block height
    let mut rollup_state = app_state.rollup_state.lock().unwrap();
    rollup_state.block_height += blobs.len() as u64;
    println!("Synced {} blobs at height {}", blobs.len(), da_height);
}