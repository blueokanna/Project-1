use log::{info, LevelFilter};
use HuangProject::{aggregate, audit, issue_credential, keygen_parties, lhe, payment, prove, revoke, setup, trace, update_credential, verify, CryptoError};

// ====================== 主函数 ======================
fn main() -> Result<(), CryptoError> {
    // 初始化日志
    env_logger::Builder::new()
        .filter_level(LevelFilter::Info)
        .init();
    info!("Starting anonymous credential system...");

    // 系统初始化与密钥生成
    let mut sys_params = setup(128);
    let (issuer_keys, user_keys, _auditor_keys) = keygen_parties();

    // (Issue) 凭证发行
    let uid = 1001;
    let mut credential = issue_credential(
        &sys_params,
        &issuer_keys,
        &user_keys,
        &[10, 20, 30],
        100,
        uid,
    )?;

    // (Payment) 支付处理
    payment(&mut sys_params, &mut credential, 20)?;

    // (Update) 凭证更新
    update_credential(&sys_params, &mut credential, &[15, 25, 40])?;

    // (Verify) 校验凭证有效性
    credential.verify(&sys_params.bp)?;

    // (Prove) 用户生成零知识证明（基于 RSA 累加器非成员证明）
    let zk_proof = prove(&credential, &sys_params.accumulator)?;

    // (Verify) 验证零知识证明
    verify(&credential, &zk_proof, &sys_params.accumulator)?;

    // (Aggregate) 聚合停车费用（示例费用记录）
    let agg_cipher = aggregate(&sys_params, &[10, 20, 30])?;
    info!("Aggregated ciphertext: {:?}", agg_cipher);

    // (Revoke) 撤销凭证（将 uid 加入黑名单）
    revoke(&mut sys_params, uid)?;

    // (Audit) 公开审计：打印公告板记录
    for log in audit(&sys_params) {
        println!("{}", log);
    }

    // (Trace) 违规追踪：使用 EC-ElGamal 解密恢复 uid
    let ct_uid = lhe::encrypt(&sys_params.lhe_pk, &sys_params.lhe_g, uid);
    let traced_uid = trace(&sys_params, &ct_uid)?;
    info!("Trace result: uid {}", traced_uid);

    Ok(())
}
