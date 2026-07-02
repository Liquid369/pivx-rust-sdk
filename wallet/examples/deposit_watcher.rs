//! Exchange deposit flow: watch-only wallet from a viewing key detects
//! incoming shielded payments; keys never touch this process.
//! Usage: PIVX_RPC_USER=u PIVX_RPC_PASS=p cargo run --example deposit_watcher -- <viewing-key> <birth-height>

use pivx_rpc::{Auth, PivxClient};
use pivx_wallet::{Network, ShieldWallet};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let viewing_key = args.next().expect("usage: deposit_watcher <viewing-key> <birth-height>");
    let birth_height: i64 = args.next().expect("missing birth height").parse()?;

    let client = PivxClient::new(
        "http://127.0.0.1:51473",
        Auth::UserPass {
            user: std::env::var("PIVX_RPC_USER")?,
            pass: std::env::var("PIVX_RPC_PASS")?,
        },
    )?;

    let mut wallet = ShieldWallet::from_viewing_key(&viewing_key, Network::MainNetwork, birth_height)?;
    println!("deposit address: {}", wallet.new_address()?);

    wallet.sync(&client, 100).await?;
    println!("balance: {} PIV", wallet.balance() as f64 / 1e8);

    loop {
        let before: std::collections::HashSet<String> =
            wallet.notes().iter().map(|n| n.nullifier.clone()).collect();
        wallet.sync(&client, 100).await?;
        for n in wallet.notes().iter().filter(|n| !before.contains(&n.nullifier)) {
            println!(
                "deposit: {} PIV{}",
                n.note.value().inner() as f64 / 1e8,
                n.memo.as_deref().map(|m| format!(" memo=\"{m}\"")).unwrap_or_default()
            );
        }
        tokio::time::sleep(std::time::Duration::from_secs(15)).await;
    }
}
