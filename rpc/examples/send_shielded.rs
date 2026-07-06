//! Send a shielded transaction with a memo from the node wallet's shield funds.
//! Usage: PIVX_RPC_USER=u PIVX_RPC_PASS=p cargo run --example send_shielded -- <shield-addr> <amount>

use pivx_rpc::{Auth, FromAddress, PivxClient, ShieldRecipient};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let address = args
        .next()
        .expect("usage: send_shielded <shield-addr> <amount>");
    let amount: f64 = args.next().expect("missing amount").parse()?;

    let client = PivxClient::new(
        "http://127.0.0.1:51473",
        Auth::UserPass {
            user: std::env::var("PIVX_RPC_USER")?,
            pass: std::env::var("PIVX_RPC_PASS")?,
        },
    )?;

    // PIVX proves + broadcasts synchronously; this returns the txid.
    let txid = client
        .shield_send_many(
            FromAddress::AnyShield,
            &[ShieldRecipient::new(address, amount).with_memo("paid with pivx-rpc")],
        )
        .await?;
    println!("sent: {txid}");

    let view = client.view_shield_transaction(&txid).await?;
    println!("fee {} PIV", view.fee);
    for output in view.outputs {
        println!(
            "  -> {} {} PIV memo={:?}",
            output.address, output.value, output.memo_str
        );
    }
    Ok(())
}
