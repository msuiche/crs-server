#![feature(duration_constructors)]

mod utils;
use utils::{get_crs_directory, get_ln_url, get_celestia_node_auth_token};
use celestia_rpc::{
    HeaderClient,
    ShareClient,
    Client,
};
use celestia_types::{ExtendedHeader};
use std::io::Write;
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
    fs,
};
use sp1_sdk::{HashableKey, Prover, SP1VerifyingKey};
use sp1_sdk::{SP1Proof, SP1ProofWithPublicValues};
use sp1_sdk::{ProverClient, SP1Stdin};
use actix_web::{App, HttpServer, web, Responder, HttpResponse};

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const ELF: &[u8] = include_bytes!("../riscv32im-succinct-zkvm-elf");

pub async fn stark_proof_worker(app_state: web::Data<AppState>) {
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
        let net_head = app_state.client.header_network_head().await.expect("Could not get latest head");

        let prover_client = ProverClient::new();
        let (pk, vk) = prover_client.setup(ELF);
        let mut stdin = SP1Stdin::new();
        stdin.write(&vk.hash_u32());
        stdin.write(&proof_public_values);
        stdin.write_vec(app_state.zk_genesis_header.header.hash().as_bytes().to_vec());
        let encoded1 = serde_cbor::to_vec(&app_state.newest_header).expect("Failed to cbor encode newest_header");
        stdin.write_vec(encoded1);
        let encoded2 = serde_cbor::to_vec(&net_head).expect("Failed to cbor encode net_head");
        stdin.write_vec(encoded2);
        stdin.write_proof(latest_proof_inner, vk.vk);

        let start_time = std::time::Instant::now();
        let resultant_proof = prover_client.prove(&pk, stdin).compressed().run().expect("could not prove");
        let elapsed_time = start_time.elapsed();
        println!("Elapsed time for proof generation: {:?}", elapsed_time);
        let one_minute = std::time::Duration::from_mins(1);
        let sleep_duration = one_minute.saturating_sub(elapsed_time);
        std::thread::sleep(sleep_duration);

        // Write the updated net head to the newest_header_file
        std::fs::write(app_state.app_dir.join("newest_header.json"), serde_json::to_string(&net_head).expect("could not json serialize net head after proving")).expect("Failed to write newest_header.json");
        // Write the new proof to the proof_file
        std::fs::write(app_state.app_dir.join("newest_proof.json"), serde_json::to_string(&resultant_proof).expect("could not json serialize new proof")).expect("Failed to write newest_proof.json");
        // update the values in the server state
        *app_state.newest_header.lock().unwrap() = net_head;
        *app_state.latest_proof.lock().unwrap() = resultant_proof;
        println!("ANOTHA 1!!!");
        println!("proved header height {:?}", app_state.newest_header.lock().unwrap().height());
    }
}

async fn get_latest_header(app_state: web::Data<AppState>) -> impl Responder {
    HttpResponse::Ok().json(app_state.newest_header.lock().unwrap().clone())
}

async fn get_latest_proof(app_state: web::Data<AppState>) -> impl Responder {
    HttpResponse::Ok().json(app_state.latest_proof.lock().unwrap().clone())
}

#[derive(Clone)]
pub struct AppState {
    pub app_dir: PathBuf,
    pub client: Arc<Client>,
    pub newest_header: Arc<Mutex<ExtendedHeader>>,
    pub latest_proof: Arc<Mutex<SP1ProofWithPublicValues>>,
    pub zk_genesis_header: ExtendedHeader,
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let app_dir = get_crs_directory().expect("Could not open directory");
    let ln_url = get_ln_url();
    let auth_token = get_celestia_node_auth_token().expect("light node auth token not set");

    // Load the "zk genesis" header
    let zk_genesis_file = std::fs::File::open(app_dir.join("zk_genesis.json"))
        .expect("Failed to read zk_genesis.json");
    let zk_genesis_header: ExtendedHeader = serde_json::from_reader(zk_genesis_file).expect("Failed to parse zk_genesis.json");

    let newest_header_file = std::fs::File::open(app_dir.join("newest_header.json"))
        .expect("Failed to read newest_header.json");
    let newest_header: Arc<Mutex<ExtendedHeader>> = Arc::new(Mutex::new(serde_json::from_reader(newest_header_file).expect("Failed to parse newest_header.json")));

    let proof_file = std::fs::File::open(app_dir.join("newest_proof.json")).expect("could not open newest_proof.json");
    let latest_proof: Arc<Mutex<SP1ProofWithPublicValues>> = Arc::new(Mutex::new(serde_json::from_reader(proof_file).expect("could not deserialize proof")));

    let app_state = web::Data::new(AppState {
        app_dir: app_dir,
        client: Arc::new(Client::new(&ln_url, Some(&auth_token))
            .await
            .expect("Failed creating rpc client")),
        newest_header: newest_header.clone(),
        latest_proof: latest_proof.clone(),
        zk_genesis_header: zk_genesis_header,
    });

    let stark_handle = tokio::spawn(stark_proof_worker(app_state.clone()));

    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .route("/header", web::get().to(get_latest_header))
            .route("/proof", web::get().to(get_latest_proof))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}