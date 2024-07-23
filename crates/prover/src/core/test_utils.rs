use super::backend::cpu::CpuCircleEvaluation;
use super::fields::m31::BaseField;
use super::fields::qm31::SecureField;
use crate::core::channel::sha256::Sha256Channel;

pub fn secure_eval_to_base_eval<EvalOrder>(
    eval: &CpuCircleEvaluation<SecureField, EvalOrder>,
) -> CpuCircleEvaluation<BaseField, EvalOrder> {
    CpuCircleEvaluation::new(
        eval.domain,
        eval.values.iter().map(|x| x.to_m31_array()[0]).collect(),
    )
}

pub fn test_channel() -> Sha256Channel {
    Sha256Channel::default()
}
