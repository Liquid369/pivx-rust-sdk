//! Fully standalone shielded send: keys and proving live in this process;
//! the node only supplies blocks and relays the final transaction.
//! Usage: PIVX_SPENDING_KEY=<key> PIVX_RPC_USER=u PIVX_RPC_PASS=p \
//!   cargo run --release --example send_standalone -- <birth-height> <to> <piv>
//!
//! SECURITY: the spending key is read from PIVX_SPENDING_KEY and must NEVER be
//! passed on the command line — argv is exposed via shell history, `ps`, and CI
//! logs. This example uses a plain env var for brevity; a real deployment should
//! source the key from a secret manager and scope it to this process only.

use pivx_rpc::{Auth, PivxClient};
use pivx_wallet::{Network, SendOptions, ShieldWallet};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let spending_key = std::env::var("PIVX_SPENDING_KEY")
        .expect("set PIVX_SPENDING_KEY (never pass a spending key in argv)");
    let mut args = std::env::args().skip(1);
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

    let mut wallet =
        ShieldWallet::from_spending_key(&spending_key, Network::MainNetwork, birth_height)?;
    wallet.sync(&client, 100).await?;
    println!("balance: {} PIV", wallet.balance() as f64 / 1e8);

    // ~50MB, one-time; or load_prover_from_path("/path/to/params-dir")
    pivx_wallet::load_prover().await?;

    let txid = wallet
        .send(
            &client,
            &SendOptions {
                memo: Some("standalone pivx-wallet send".into()),
                ..SendOptions::shield(to, (piv * 1e8).round() as u64)
            },
        )
        .await?;
    println!("sent: {txid}");
    Ok(())
}
