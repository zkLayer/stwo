use itertools::Itertools;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::core::backend::simd::column::BaseColumn;
use crate::core::backend::simd::SimdBackend;
use crate::core::backend::{Column, ColumnOps};
use crate::core::vcs::ops::{MerkleHasher, MerkleOps};
use crate::core::vcs::sha256_hash::Sha256Hash;
use crate::core::vcs::sha256_merkle::Sha256MerkleHasher;

impl ColumnOps<Sha256Hash> for SimdBackend {
    type Column = Vec<Sha256Hash>;

    fn bit_reverse_column(_column: &mut Self::Column) {
        unimplemented!()
    }
}

// TODO(BWS): not simd at all
impl MerkleOps<Sha256MerkleHasher> for SimdBackend {
    fn commit_on_layer(
        log_size: u32,
        prev_layer: Option<&Vec<Sha256Hash>>,
        columns: &[&BaseColumn],
    ) -> Vec<Sha256Hash> {
        #[cfg(not(feature = "parallel"))]
        let iter = 0..1 << log_size;

        #[cfg(feature = "parallel")]
        let iter = (0..1 << log_size).into_par_iter();

        iter.map(|i| {
            Sha256MerkleHasher::hash_node(
                prev_layer.map(|prev_layer| (prev_layer[2 * i], prev_layer[2 * i + 1])),
                &columns.iter().map(|column| column.at(i)).collect_vec(),
            )
        })
        .collect()
    }
}
