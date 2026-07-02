//! Fully standalone shielded send: keys and proving live in this process;
//! the node only supplies blocks and relays the final transaction.
//! Usage: PIVX_RPC_USER=u PIVX_RPC_PASS=p cargo run --release --example send_standalone -- <spending-key> <birth-height> <to> <piv>

use pivx_rpc::{Auth, PivxClient};
use pivx_wallet::{Inputs, Network, SendOptions, ShieldWallet};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let spending_key = args.next().expect("usage: send_standalone <spending-key> <birth-height> <to> <piv>");
    let birth_height: i64 = args.next().expect("missing birth height").parse()?;
    let to = args.next().expect("missing recipient");
    let piv: f64 = args.next().expect("missing amount").parse()?;

    let client = PivxClient::new(
        "http://127.0.0.1:51473",
        Auth::UserPass {
            user: std::env::var("PIVX_RPC_USER")?,
            pass: std::env::var("PIVX_RPC_PASS")?,
        },
    )?;

    let mut wallet = ShieldWallet::from_spending_key(&spending_key, Network::MainNetwork, birth_height)?;
    wallet.sync(&client, 100).await?;
    println!("balance: {} PIV", wallet.balance() as f64 / 1e8);

    // ~50MB, one-time; or load_prover_from_path("/path/to/params-dir")
    pivx_wallet::load_prover().await?;

    let txid = wallet
        .send(&client, &SendOptions {
            to,
            amount: (piv * 1e8).round() as u64,
            memo: Some("standalone pivx-wallet send".into()),
            inputs: Inputs::Shield,
        })
        .await?;
    println!("sent: {txid}");
    Ok(())
}
