//! Sync checkpoints: `(height, commitment_tree_hex)` snapshots so new
//! wallets skip scanning history before their birth height.
//!
//! From PIVX-Labs/pivx-shield `src/checkpoint.rs` (MIT).

use pivx_primitives::consensus::Network;

use crate::mainnet_checkpoints::MAINNET_CHECKPOINTS;
use crate::testnet_checkpoints::TESTNET_CHECKPOINTS;

/// The closest checkpoint at or below `block_height` (the first checkpoint
/// when below shield activation).
pub fn get_checkpoint(block_height: i32, network: Network) -> (i32, &'static str) {
    let used_checkpoints = match network {
        Network::TestNetwork => TESTNET_CHECKPOINTS,
        Network::MainNetwork => MAINNET_CHECKPOINTS,
    };

    used_checkpoints
        .iter()
        .rev()
        .find(|x| x.0 <= block_height)
        .copied()
        .unwrap_or(used_checkpoints[0])
}

#[cfg(test)]
mod test {
    use super::get_checkpoint;
    use crate::transaction::DEPTH;
    use incrementalmerkletree::frontier::CommitmentTree;
    use pivx_primitives::consensus::Network::{MainNetwork, TestNetwork};
    use pivx_primitives::merkle_tree::read_commitment_tree;
    use sapling::Node;
    use std::error::Error;
    use std::io::Cursor;

    #[test]
    fn check_testnet_checkpoints() -> Result<(), Box<dyn Error>> {
        assert_eq!(get_checkpoint(1123200 + 30000, TestNetwork).0, 1123200);
        assert_eq!(get_checkpoint(1123200, TestNetwork).0, 1123200);
        assert_eq!(get_checkpoint((907200 + 950400) / 2, TestNetwork).0, 907200);
        let tree = Cursor::new(hex::decode(get_checkpoint(0, TestNetwork).1)?);
        let tree: CommitmentTree<Node, DEPTH> = read_commitment_tree(tree)?;
        assert_eq!(tree, CommitmentTree::empty());
        Ok(())
    }

    #[test]
    fn check_mainnet_checkpoints() -> Result<(), Box<dyn Error>> {
        assert_eq!(get_checkpoint(2700000 - 1, MainNetwork).0, 2700000);
        assert_eq!(get_checkpoint(2700000, MainNetwork).0, 2700000);
        assert_eq!(get_checkpoint(2700001, MainNetwork).0, 2700000);
        assert_eq!(get_checkpoint(3758400 + 1, MainNetwork).0, 3758400);
        assert_eq!(get_checkpoint((3758400 + 3715200) / 2, MainNetwork).0, 3715200);
        assert_eq!(get_checkpoint(4909949, MainNetwork).0, 4909922);
        let buff = Cursor::new(hex::decode(get_checkpoint(2700000, MainNetwork).1)?);
        let tree: CommitmentTree<Node, DEPTH> = read_commitment_tree(buff)?;
        assert_eq!(tree, CommitmentTree::empty());
        Ok(())
    }
}
