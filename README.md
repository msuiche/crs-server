# Celestia Recursive Sync - Server

This server will create recursive proofs of Celestia consensus history, allowing _ultra light nodes_ to synchronize consensus instantly.

## How to run
1. Build:
```
cargo build --release
```
2. Start and sync a celestia light node 
3. obtain and auth token for your celestia light node
4. Run crs-server with
```
./target/release/crs-server --ln-auth [YOUR_LIGHT_NODE_AUTH_TOKEN]
```

## How to use
Get the latest header with
```
curl localhost:8080/header
```
Get the latest recursive STARK proof with
```
curl localhost:8080/proof
```
