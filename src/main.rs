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
    sync::Arc,
    fs,
};
use sp1_sdk::{HashableKey, Prover, SP1VerifyingKey};
use sp1_sdk::{SP1Proof, SP1ProofWithPublicValues};
use sp1_sdk::{ProverClient, SP1Stdin};

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const ELF: &[u8] = include_bytes!("../riscv32im-succinct-zkvm-elf");

#[tokio::main]
async fn main() {
    let app_dir = get_crs_directory().expect("Could not open directory");
    let ln_url = get_ln_url();
    let auth_token = get_celestia_node_auth_token().expect("light node auth token not set");
    let client = Arc::new(Client::new(&ln_url, Some(&auth_token))
        .await
        .expect("Failed creating rpc client"));

    // Load the "zk genesis" header
    let zk_genesis_file = std::fs::File::open(app_dir.join("zk_genesis.json"))
        .expect("Failed to read zk_genesis.json");
    let zk_genesis_header: ExtendedHeader = serde_json::from_reader(zk_genesis_file).expect("Failed to parse zk_genesis.json");

    loop {
        // Load the newest proof and header
        let newest_header_file = std::fs::File::open(app_dir.join("newest_header.json"))
            .expect("Failed to read newest_header.json");
        let newest_header: ExtendedHeader = serde_json::from_reader(newest_header_file).expect("Failed to parse newest_header.json");

        let proof_file = std::fs::File::open(app_dir.join("newest_proof.json")).expect("could not open newest_proof.json");
        let proof: SP1ProofWithPublicValues = serde_json::from_reader(proof_file).expect("could not deserialize proof");
        let proof_public_values = proof.public_values.to_vec();
        let proof_inner = match proof.proof {
            SP1Proof::Compressed(c) => c,
            _ => panic!("Not the right kind of SP1 proof")
        };

        // Get the network head
        let net_head = client.header_network_head().await.expect("Could not get latest head");

        let prover_client = ProverClient::new();
        let (pk, vk) = prover_client.setup(ELF);
        let mut stdin = SP1Stdin::new();
        stdin.write(&vk.hash_u32());
        stdin.write(&proof_public_values);
        stdin.write_vec(zk_genesis_header.header.hash().as_bytes().to_vec());
        let encoded1 = serde_cbor::to_vec(&newest_header).expect("Failed to cbor encode newest_header");
        stdin.write_vec(encoded1);
        let encoded2 = serde_cbor::to_vec(&net_head).expect("Failed to cbor encode net_head");
        stdin.write_vec(encoded2);
        stdin.write_proof(*proof_inner, vk.vk);

        let resultant_proof = prover_client.prove(&pk, stdin).compressed().run().expect("could not prove");

        // Write the updated net head to the newest_header_file
        std::fs::write(app_dir.join("newest_header.json"), serde_json::to_string(&net_head).expect("could not json serialize net head after proving")).expect("Failed to write newest_header.json");
        // Write the new proof to the proof_file
        std::fs::write(app_dir.join("newest_proof.json"), serde_json::to_string(&resultant_proof).expect("could not json serialize new proof")).expect("Failed to write newest_proof.json");
        println!("ANOTHA 1!!!");
        println!("proved header height {:?}", newest_header.height());
    }

}