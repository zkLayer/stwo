use itertools::{izip, zip_eq};
use num_traits::{One, Zero};

use super::CpuBackend;
use crate::core::backend::Col;
use crate::core::circle::CirclePoint;
use crate::core::constraints::complex_conjugate_line_coeffs_normalized;
use crate::core::fields::cm31::CM31;
use crate::core::fields::m31::BaseField;
use crate::core::fields::qm31::{SecureField, QM31};
use crate::core::fields::secure_column::SecureColumnByCoords;
use crate::core::fields::{ComplexOf, FieldExpOps};
use crate::core::pcs::quotients::{ColumnSampleBatch, PointSample, QuotientOps};
use crate::core::poly::circle::{CircleDomain, CircleEvaluation, SecureEvaluation};
use crate::core::poly::BitReversedOrder;
use crate::core::utils::{bit_reverse, bit_reverse_index};

/// Line coefficients for each quotient numerator term.
/// Specifically, for the i-th (in a sample batch) column's numerator term
/// `alpha^i * (c * F(p) - (a * p.y + b))`, we precompute and return the constants:
/// (`alpha^i * a`, `alpha^i * b`, `alpha^i * c`)
/// scheme:  [number of quotients, number of quotient terms]
pub type LineCoeffs = Vec<Vec<(CM31, CM31)>>;
/// Random coefficients used to linearly combine the batched quotients.
/// Specifically, for each sample batch we compute random_coeff^(number of columns in the batch),
/// scheme: [number of quotients]
pub type BatchCoeff = Vec<SecureField>;

impl QuotientOps for CpuBackend {
    fn accumulate_quotients(
        domain: CircleDomain,
        columns: &[&CircleEvaluation<Self, BaseField, BitReversedOrder>],
        random_coeff: SecureField,
        sample_batches: &[ColumnSampleBatch],
        _log_blowup_factor: u32,
    ) -> SecureEvaluation<Self> {
        let mut values = unsafe { SecureColumnByCoords::uninitialized(domain.size()) };
        let (line_coeffs, batch_random_coeffs) =
            line_batch_random_coeffs(sample_batches, random_coeff);
        let denominator_inverses = denominator_inverses(sample_batches, domain);

        for row in 0..domain.size() {
            let domain_point = domain.at(bit_reverse_index(row, domain.log_size()));
            let row_value = accumulate_row_quotients(
                sample_batches,
                columns,
                (&line_coeffs, &batch_random_coeffs),
                &denominator_inverses,
                row,
                domain_point,
                random_coeff,
            );
            values.set(row, row_value);
        }
        SecureEvaluation { domain, values }
    }
}
// TODO(Ohad): no longer using pair_vanishing, remove domain_point_vec and line_coeffs, or write a
// function that deals with quotients over pair_vanishing polynomials.
pub fn accumulate_row_quotients(
    sample_batches: &[ColumnSampleBatch],
    columns: &[&CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>],
    line_and_batch_coeffs: (&LineCoeffs, &BatchCoeff),
    denominator_inverses: &Vec<Col<CpuBackend, CM31>>,
    row: usize,
    domain_point: CirclePoint<BaseField>,
    random_coeff: SecureField,
) -> SecureField {
    let mut row_accumulator = SecureField::zero();
    for (sample_batch, line_coeffs, batch_coeff, denominator_inverses) in izip!(
        sample_batches,
        line_and_batch_coeffs.0,
        line_and_batch_coeffs.1,
        denominator_inverses
    ) {
        if sample_batch.columns_and_values.len() != 1 {
            let mut numerator = SecureField::zero();

            for ((column_index, _), (a, b)) in zip_eq(&sample_batch.columns_and_values, line_coeffs)
            {
                let column = &columns[*column_index];
                let value = column[row];
                let linear_term = *a * domain_point.y + *b;
                numerator *= random_coeff;
                numerator += SecureField::from(value - linear_term);
            }

            row_accumulator = row_accumulator * *batch_coeff
                + numerator * SecureField::from(denominator_inverses[row]);
        } else {
            let column_index = sample_batch.columns_and_values[0].0;
            let (a, b) = line_coeffs[0];

            let column = &columns[column_index];
            let value = column[row];
            let linear_term = a * domain_point.y + b;

            let numerator = (value - linear_term) * denominator_inverses[row];
            row_accumulator = row_accumulator * *batch_coeff + QM31::from(numerator);
        }
    }
    row_accumulator
}

/// Precompute the complex conjugate line coefficients for each column in each sample batch.
/// Specifically, for the i-th (in a sample batch) column's numerator term
/// `alpha^i * (c * F(p) - (a * p.y + b))`, we precompute and return the constants:
/// (`alpha^i * a`, `alpha^i * b`, `alpha^i * c`).
pub fn column_line_coeffs(
    sample_batches: &[ColumnSampleBatch],
    random_coeff: SecureField,
) -> Vec<Vec<(CM31, CM31)>> {
    sample_batches
        .iter()
        .map(|sample_batch| {
            let mut alpha = SecureField::one();
            sample_batch
                .columns_and_values
                .iter()
                .map(|(_, sampled_value)| {
                    let sample = PointSample {
                        point: sample_batch.point,
                        value: *sampled_value,
                    };
                    let coeffs = complex_conjugate_line_coeffs_normalized(&sample);
                    alpha *= random_coeff;
                    coeffs
                })
                .collect()
        })
        .collect()
}

/// Precompute the random coefficients used to linearly combine the batched quotients.
/// Specifically, for each sample batch we compute random_coeff^(number of columns in the batch),
/// which is used to linearly combine the batch with the next one.
pub fn batch_random_coeffs(
    sample_batches: &[ColumnSampleBatch],
    random_coeff: SecureField,
) -> Vec<SecureField> {
    sample_batches
        .iter()
        .map(|sb| random_coeff.pow(sb.columns_and_values.len() as u128))
        .collect()
}

pub fn denominator_inverses(
    sample_batches: &[ColumnSampleBatch],
    domain: CircleDomain,
) -> Vec<Vec<CM31>> {
    let mut flat_denominators = Vec::with_capacity(sample_batches.len() * domain.size());
    for sample_batch in sample_batches {
        let d = sample_batch.point.x.get_imag() * sample_batch.point.y.get_imag().inverse();
        let cross_term = d * sample_batch.point.y.get_real() - sample_batch.point.x.get_real();

        for row in 0..domain.size() {
            let domain_point = domain.at(row);
            let denominator =
                CM31::from(domain_point.x) - CM31::from(domain_point.y) * d + cross_term;
            flat_denominators.push(denominator);
        }
    }

    let mut flat_denominator_inverses = vec![CM31::zero(); flat_denominators.len()];
    CM31::batch_inverse(&flat_denominators, &mut flat_denominator_inverses);

    flat_denominator_inverses
        .chunks_mut(domain.size())
        .map(|denominator_inverses| {
            bit_reverse(denominator_inverses);
            denominator_inverses.to_vec()
        })
        .collect()
}

pub fn line_batch_random_coeffs(
    sample_batches: &[ColumnSampleBatch],
    random_coeff: SecureField,
) -> (LineCoeffs, BatchCoeff) {
    (
        column_line_coeffs(sample_batches, random_coeff),
        batch_random_coeffs(sample_batches, random_coeff),
    )
}

#[cfg(test)]
mod tests {
    use crate::core::backend::cpu::{CpuCircleEvaluation, CpuCirclePoly};
    use crate::core::backend::CpuBackend;
    use crate::core::circle::SECURE_FIELD_CIRCLE_GEN;
    use crate::core::pcs::quotients::{ColumnSampleBatch, QuotientOps};
    use crate::core::poly::circle::CanonicCoset;
    use crate::{m31, qm31};

    #[test]
    fn test_quotients_are_low_degree() {
        const LOG_SIZE: u32 = 7;
        const LOG_BLOWUP_FACTOR: u32 = 1;
        let polynomial = CpuCirclePoly::new((0..1 << LOG_SIZE).map(|i| m31!(i)).collect());
        let eval_domain = CanonicCoset::new(LOG_SIZE + 1).circle_domain();
        let eval = polynomial.evaluate(eval_domain);
        let point = SECURE_FIELD_CIRCLE_GEN;
        let value = polynomial.eval_at_point(point);
        let coeff = qm31!(1, 2, 3, 4);
        let quot_eval = CpuBackend::accumulate_quotients(
            eval_domain,
            &[&eval],
            coeff,
            &[ColumnSampleBatch {
                point,
                columns_and_values: vec![(0, value)],
            }],
            LOG_BLOWUP_FACTOR,
        );
        let quot_poly_base_field =
            CpuCircleEvaluation::new(eval_domain, quot_eval.columns[0].clone()).interpolate();
        assert!(quot_poly_base_field.is_in_fri_space(LOG_SIZE));
    }
}
