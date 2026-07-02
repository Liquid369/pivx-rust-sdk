//! Sapling proving parameters.
//!
//! Adapted from PIVX-Labs/pivx-shield `src/prover.rs` (MIT), plus disk
//! loading. Parameters are ~50MB; load once per process.

use std::error::Error;
use std::path::Path;

use tokio::sync::OnceCell;

#[cfg(not(test))]
use sapling::circuit::{OutputParameters, SpendParameters};
#[cfg(test)]
use sapling::prover::mock::{MockOutputProver, MockSpendProver};

#[cfg(not(test))]
pub type ImplTxProver = (OutputParameters, SpendParameters);
#[cfg(test)]
pub type ImplTxProver = (MockOutputProver, MockSpendProver);

static PROVER: OnceCell<ImplTxProver> = OnceCell::const_new();

// Used by the real prover; the test build swaps in a mock and doesn't read these.
#[cfg_attr(test, allow(dead_code))]
const OUTPUT_SHA256: &str = "2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4";
#[cfg_attr(test, allow(dead_code))]
const SPEND_SHA256: &str = "8e48ffd23abb3a5fd9c5589204f32d9c31285a04b78096ba40a79b75677efc13";
const DEFAULT_URLS: &[&str] = &["https://pivxla.bz", "https://duddino.com"];

pub(crate) fn get_loaded_prover() -> Option<&'static ImplTxProver> {
    PROVER.get()
}

pub fn prover_is_loaded() -> bool {
    PROVER.initialized()
}

/// Download parameters from the default PIVX Labs mirrors (SHA256-pinned).
pub async fn load_prover() -> Result<(), Box<dyn Error>> {
    let mut last_err: Box<dyn Error> = "no prover URLs".into();
    for url in DEFAULT_URLS {
        match load_prover_from_url(url).await {
            Ok(()) => return Ok(()),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

pub async fn load_prover_from_url(url: &str) -> Result<(), Box<dyn Error>> {
    PROVER
        .get_or_try_init(|| async {
            let c = reqwest::Client::new();
            let output = c
                .get(format!("{url}/sapling-output.params"))
                .send()
                .await?
                .bytes()
                .await?;
            let spend = c
                .get(format!("{url}/sapling-spend.params"))
                .send()
                .await?
                .bytes()
                .await?;
            check_and_create_prover(&output, &spend)
        })
        .await?;
    Ok(())
}

/// Load `sapling-output.params` / `sapling-spend.params` from a directory.
pub async fn load_prover_from_path(dir: impl AsRef<Path>) -> Result<(), Box<dyn Error>> {
    let dir = dir.as_ref();
    let output = std::fs::read(dir.join("sapling-output.params"))?;
    let spend = std::fs::read(dir.join("sapling-spend.params"))?;
    load_prover_from_bytes(&output, &spend).await
}

pub async fn load_prover_from_bytes(
    sapling_output_bytes: &[u8],
    sapling_spend_bytes: &[u8],
) -> Result<(), Box<dyn Error>> {
    PROVER
        .get_or_try_init(|| async {
            check_and_create_prover(sapling_output_bytes, sapling_spend_bytes)
        })
        .await?;
    Ok(())
}

#[cfg(not(test))]
fn check_and_create_prover(
    sapling_output_bytes: &[u8],
    sapling_spend_bytes: &[u8],
) -> Result<ImplTxProver, Box<dyn Error>> {
    if sha256::digest(sapling_output_bytes) != OUTPUT_SHA256 {
        Err("Sha256 does not match for sapling output")?;
    }
    if sha256::digest(sapling_spend_bytes) != SPEND_SHA256 {
        Err("Sha256 does not match for sapling spend")?;
    }
    Ok((
        OutputParameters::read(sapling_output_bytes, false)?,
        SpendParameters::read(sapling_spend_bytes, false)?,
    ))
}

#[cfg(test)]
fn check_and_create_prover(
    _sapling_output_bytes: &[u8],
    _sapling_spend_bytes: &[u8],
) -> Result<ImplTxProver, Box<dyn Error>> {
    Ok((MockOutputProver, MockSpendProver))
}
