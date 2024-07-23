use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::core::channel::{MerkleChannel, Sha256Channel};
use crate::core::fields::m31::BaseField;
use crate::core::utils::bws_num_to_bytes;
use crate::core::vcs::ops::MerkleHasher;
use crate::core::vcs::sha256_hash::{Sha256Hash, Sha256Hasher};

#[derive(Copy, Clone, Debug, PartialEq, Eq, Default, Deserialize, Serialize)]
pub struct Sha256MerkleHasher;
impl MerkleHasher for Sha256MerkleHasher {
    type Hash = Sha256Hash;

    fn hash_node(
        children_hashes: Option<(Self::Hash, Self::Hash)>,
        column_values: &[BaseField],
    ) -> Self::Hash {
        // There are three possibilities:
        // - children only
        // - children and column elements
        // - column elements only
        //
        // They are handled as follows.
        // - left | right (32 bytes | 32 bytes)
        // - left | [column hash] | right (32 bytes | 32 bytes | 32 bytes)
        // - [column hash] (32 bytes)

        let column_hash = if column_values.is_empty() {
            None
        } else {
            let len = column_values.len();

            let mut hash = [0u8; 32];
            let mut sha256 = sha2::Sha256::new();
            Digest::update(&mut sha256, bws_num_to_bytes(column_values[len - 1]));
            hash.copy_from_slice(sha256.finalize().as_slice());

            for i in 1..len {
                let mut sha256 = sha2::Sha256::new();
                Digest::update(&mut sha256, bws_num_to_bytes(column_values[len - 1 - i]));
                Digest::update(&mut sha256, hash);
                hash.copy_from_slice(sha256.finalize().as_slice());
            }

            Some(hash)
        };

        let mut sha256 = sha2::Sha256::new();
        match (children_hashes, column_hash) {
            (Some(children_hashes), Some(column_hash)) => {
                Digest::update(&mut sha256, children_hashes.0);
                Digest::update(&mut sha256, column_hash);
                Digest::update(&mut sha256, children_hashes.1);
            }
            (Some(children_hashes), None) => {
                Digest::update(&mut sha256, children_hashes.0);
                Digest::update(&mut sha256, children_hashes.1);
            }
            (None, Some(column_hash)) => {
                Digest::update(&mut sha256, column_hash);
            }
            (None, None) => {
                // do nothing if both are None
            }
        }

        let mut hash_result = [0u8; 32];
        hash_result.copy_from_slice(sha256.finalize().as_slice());

        hash_result.to_vec().into()
    }
}

#[derive(Default)]
pub struct Sha256MerkleChannel;

impl MerkleChannel for Sha256MerkleChannel {
    type C = Sha256Channel;
    type H = Sha256MerkleHasher;

    fn mix_root(channel: &mut Self::C, root: <Self::H as MerkleHasher>::Hash) {
        channel.update_digest(Sha256Hasher::concat_and_hash(&root, &channel.digest()));
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use itertools::Itertools;
    use num_traits::Zero;
    use rand::rngs::SmallRng;
    use rand::{Rng, SeedableRng};

    use crate::core::backend::CpuBackend;
    use crate::core::fields::m31::BaseField;
    use crate::core::vcs::prover::{MerkleDecommitment, MerkleProver};
    use crate::core::vcs::sha256_hash::Sha256Hash;
    use crate::core::vcs::sha256_merkle::Sha256MerkleHasher;
    use crate::core::vcs::verifier::{MerkleVerificationError, MerkleVerifier};

    type TestData = (
        BTreeMap<u32, Vec<usize>>,
        MerkleDecommitment<Sha256MerkleHasher>,
        Vec<Vec<BaseField>>,
        MerkleVerifier<Sha256MerkleHasher>,
    );
    fn prepare_merkle() -> TestData {
        const N_COLS: usize = 400;
        const N_QUERIES: usize = 7;
        let log_size_range = 6..9;

        let mut rng = SmallRng::seed_from_u64(0);
        let log_sizes = (0..N_COLS)
            .map(|_| rng.gen_range(log_size_range.clone()))
            .collect_vec();
        let cols = log_sizes
            .iter()
            .map(|&log_size| {
                (0..(1 << log_size))
                    .map(|_| BaseField::from(rng.gen_range(0..(1 << 30))))
                    .collect_vec()
            })
            .collect_vec();
        let merkle =
            MerkleProver::<CpuBackend, Sha256MerkleHasher>::commit(cols.iter().collect_vec());

        let mut queries = BTreeMap::<u32, Vec<usize>>::new();
        for log_size in log_size_range.rev() {
            let layer_queries = (0..N_QUERIES)
                .map(|_| rng.gen_range(0..(1 << log_size)))
                .sorted()
                .dedup()
                .collect_vec();
            queries.insert(log_size, layer_queries);
        }

        let (values, decommitment) = merkle.decommit(queries.clone(), cols.iter().collect_vec());

        let verifier = MerkleVerifier {
            root: merkle.root(),
            column_log_sizes: log_sizes,
        };
        (queries, decommitment, values, verifier)
    }

    #[test]
    fn test_merkle_success() {
        let (queries, decommitment, values, verifier) = prepare_merkle();

        verifier.verify(queries, values, decommitment).unwrap();
    }

    #[test]
    fn test_merkle_invalid_witness() {
        let (queries, mut decommitment, values, verifier) = prepare_merkle();
        decommitment.hash_witness[20] = Sha256Hash::default();

        assert_eq!(
            verifier.verify(queries, values, decommitment).unwrap_err(),
            MerkleVerificationError::RootMismatch
        );
    }

    #[test]
    fn test_merkle_invalid_value() {
        let (queries, decommitment, mut values, verifier) = prepare_merkle();
        values[3][6] = BaseField::zero();

        assert_eq!(
            verifier.verify(queries, values, decommitment).unwrap_err(),
            MerkleVerificationError::RootMismatch
        );
    }

    #[test]
    fn test_merkle_witness_too_short() {
        let (queries, mut decommitment, values, verifier) = prepare_merkle();
        decommitment.hash_witness.pop();

        assert_eq!(
            verifier.verify(queries, values, decommitment).unwrap_err(),
            MerkleVerificationError::WitnessTooShort
        );
    }

    #[test]
    fn test_merkle_column_values_too_long() {
        let (queries, decommitment, mut values, verifier) = prepare_merkle();
        values[3].push(BaseField::zero());

        assert_eq!(
            verifier.verify(queries, values, decommitment).unwrap_err(),
            MerkleVerificationError::ColumnValuesTooLong
        );
    }

    #[test]
    fn test_merkle_column_values_too_short() {
        let (queries, decommitment, mut values, verifier) = prepare_merkle();
        values[3].pop();

        assert_eq!(
            verifier.verify(queries, values, decommitment).unwrap_err(),
            MerkleVerificationError::ColumnValuesTooShort
        );
    }

    #[test]
    fn test_merkle_witness_too_long() {
        let (queries, mut decommitment, values, verifier) = prepare_merkle();
        decommitment.hash_witness.push(Sha256Hash::default());

        assert_eq!(
            verifier.verify(queries, values, decommitment).unwrap_err(),
            MerkleVerificationError::WitnessTooLong
        );
    }
}
