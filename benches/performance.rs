use criterion::{black_box, Criterion, criterion_group, criterion_main, Bencher};
use num_bigint::BigUint;
use HuangProject::{audit, issue_credential, keygen_parties, prove, revoke, setup, verify};

// 1) 测试「凭证发行」的开销
fn bench_issue_credential(c: &mut Criterion) {
    // 先做一次系统初始化
    let sys_params = setup(128);
    let (issuer_keys, user_keys, _auditor_keys) = keygen_parties();

    c.bench_function("issue_credential", |b| {
        b.iter(|| {
            let uid = 1001;
            // 只关注发行操作本身
            let _cred = black_box(
                issue_credential(
                    &sys_params,
                    &issuer_keys,
                    &user_keys,
                    &[10, 20, 30],
                    100,
                    uid,
                )
            ).unwrap();
        });
    });
}

// 2) 测试「生成零知识证明」的开销
fn bench_prove(c: &mut Criterion) {
    let sys_params = setup(128);
    let (issuer_keys, user_keys, _auditor_keys) = keygen_parties();

    // 先发行一个凭证
    let cred = issue_credential(&sys_params, &issuer_keys, &user_keys, &[10, 20, 30], 100, 999)
        .unwrap();

    c.bench_function("prove_zk", |b| {
        b.iter(|| {
            let _zk_proof = black_box(
                prove(&cred, &sys_params.accumulator)
            ).unwrap();
        });
    });
}

// 3) 测试「验证零知识证明」(verify) 和「身份验证」的开销
fn bench_verify(c: &mut Criterion) {
    let sys_params = setup(128);
    let (issuer_keys, user_keys, _auditor_keys) = keygen_parties();

    // 先发行一个凭证并生成证明
    let cred = issue_credential(&sys_params, &issuer_keys, &user_keys, &[10, 20, 30], 100, 999)
        .unwrap();
    let zk_proof = prove(&cred, &sys_params.accumulator).unwrap();

    c.bench_function("verify_zk", |b| {
        b.iter(|| {
            let _ = black_box(
                verify(&cred, &zk_proof, &sys_params.accumulator)
            ).unwrap();
        });
    });
}

// 4) 测试「凭证撤销」(revoke) 或者黑名单更新
fn bench_revoke(c: &mut Criterion) {
    // 需要一个可变的 sys_params
    let mut sys_params = setup(128);

    c.bench_function("revoke_credential", |b| {
        b.iter(|| {
            // 模拟撤销某个 uid
            let _ = black_box(
                revoke(&mut sys_params, 1234)
            ).unwrap();
        });
    });
}

// 5) 测试「审计信息上传 / 公告板广播」(audit)
fn bench_audit(c: &mut Criterion) {
    // 先构造一些黑名单数据
    let mut sys_params = setup(128);
    for i in 0..10 {
        sys_params.accumulator.add(BigUint::from(i as u64));
        sys_params.bulletin_board.push(format!("Blacklisted uid {}", i));
    }

    c.bench_function("audit_bulletin_board", |b| {
        b.iter(|| {
            let logs = black_box(audit(&sys_params));
            // 如果想强制用一下 logs 防止优化，可在此输出或计数
            assert!(logs.len() >= 10);
        });
    });
}

// Criterion 需要的组装宏
criterion_group!(
    name = anon_cred_benches;
    config = Criterion::default().sample_size(10);
    targets =
        bench_issue_credential,
        bench_prove,
        bench_verify,
        bench_revoke,
        bench_audit
);

// 入口
criterion_main!(anon_cred_benches);


// -------------------------------------
// 2) 使用 benchmark-rs 做基准测试
//    这里有两种方法：
//    A) 直接用 #[bench] 宏 (需要 nightly)
//    B) 或者用 benchmark-rs 的自定义方法
// -------------------------------------

// A) 如果要用 #[bench] 宏，需要 nightly + feature(test)
#[cfg(feature = "nightly_bench")]
#[bench]
fn bench_issue_credential_benchrs(bencher: &mut Bencher) {
    let sys_params = setup(128);
    let (issuer_keys, user_keys, _auditor_keys) = keygen_parties();

    bencher.iter(|| {
        let uid = 1001;
        let _cred = issue_credential(
            &sys_params,
            &issuer_keys,
            &user_keys,
            &[10, 20, 30],
            100,
            uid,
        ).unwrap();
    });
}

// B) 或者使用 benchmark-rs 的 `Bencher` 结构（不用 #[bench] 宏）
#[cfg(feature = "nightly_bench")]
#[bench]
fn bench_issue_credential_benchrs_2(bencher: &mut Bencher) {
    let sys_params = setup(128);
    let (issuer_keys, user_keys, _auditor_keys) = keygen_parties();

    bencher.iter(|| {
        let uid = 1001;
        let _cred = issue_credential(
            &sys_params,
            &issuer_keys,
            &user_keys,
            &[10, 20, 30],
            100,
            uid,
        ).unwrap();
    });
}