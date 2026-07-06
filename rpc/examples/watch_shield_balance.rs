//! Watch a shielded address using only its viewing key.
//! Usage: PIVX_RPC_USER=u PIVX_RPC_PASS=p cargo run --example watch_shield_balance -- <viewing-key>

use pivx_rpc::{Auth, PivxClient, ShieldEvent, ShieldWatcher, WatchOptions};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let vkey = std::env::args()
        .nth(1)
        .expect("usage: watch_shield_balance <viewing-key>");
    let client = PivxClient::new(
        "http://127.0.0.1:51473", // testnet: 51475
        Auth::UserPass {
            user: std::env::var("PIVX_RPC_USER")?,
            pass: std::env::var("PIVX_RPC_PASS")?,
        },
    )?;

    let imported = client
        .import_sapling_viewing_key(&vkey, Some("whenkeyisnew"), None)
        .await?;
    println!("watching {}", imported.address);

    let mut watcher = ShieldWatcher::new(
        &client,
        WatchOptions {
            addresses: vec![imported.address],
            ..Default::default()
        },
    );
    loop {
        for event in watcher.poll().await? {
            match event {
                ShieldEvent::Note(n) => println!("+{} PIV in {}:{}", n.amount, n.txid, n.outindex),
                ShieldEvent::Spent(n) => {
                    println!("-{} PIV ({}:{} spent)", n.amount, n.txid, n.outindex)
                }
                ShieldEvent::Balance { current, previous } => {
                    println!("shield balance: {previous} -> {current} PIV")
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(15)).await;
    }
}
