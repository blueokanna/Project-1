use blake3;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use chrono::{Duration, Utc};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use digest::{FixedOutput, HashMarker, OutputSizeUser, Reset, Update};
use env_logger;
use generic_array::{typenum::U64, GenericArray};
use log::{error, info, LevelFilter};
use merlin::Transcript;
use num_bigint::{BigInt, BigUint, RandBigInt, ToBigInt};
use num_integer::Integer;
use num_traits::{One, Zero};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ====================== 自定义错误 ======================
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Proof verification failed")]
    VerificationError,
    #[error("Serialization error")]
    SerializationError,
    #[error("Credential not found")]
    CredentialNotFound,
    #[error("Attribute relationship verification failed")]
    AttributeRelationshipError,
    #[error("Non-membership proof generation failed")]
    NonMembershipError,
    #[error("RSA accumulator error")]
    RsaAccumulatorError,
    #[error("Paillier encryption error")]
    PaillierError,
    #[error("Decryption error")]
    DecryptionError,
}

// ====================== Blake3 适配器 ======================
#[derive(Clone)]
pub struct Blake3Adapter {
    hasher: blake3::Hasher,
}

impl Blake3Adapter {
    pub fn new() -> Self {
        Self {
            hasher: blake3::Hasher::new(),
        }
    }
}

impl Default for Blake3Adapter {
    fn default() -> Self {
        Self::new()
    }
}

impl OutputSizeUser for Blake3Adapter {
    type OutputSize = U64;
}

impl Update for Blake3Adapter {
    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }
}

impl FixedOutput for Blake3Adapter {
    fn finalize_into(self, out: &mut GenericArray<u8, Self::OutputSize>) {
        let result = self.finalize_fixed();
        out.copy_from_slice(result.as_slice());
    }
    fn finalize_fixed(self) -> GenericArray<u8, Self::OutputSize> {
        let mut buf = [0u8; 64];
        self.hasher.finalize_xof().fill(&mut buf);
        GenericArray::clone_from_slice(&buf)
    }
}

impl Reset for Blake3Adapter {
    fn reset(&mut self) {
        *self = Self::new();
    }
}

impl HashMarker for Blake3Adapter {}

// ====================== 素数生成及 RSA 模数 ======================
fn is_probably_prime(n: &BigUint, iterations: usize) -> bool {
    if *n < BigUint::from(2u32) {
        return false;
    }
    if *n == BigUint::from(2u32) || *n == BigUint::from(3u32) {
        return true;
    }
    if n.is_even() {
        return false;
    }
    let one = BigUint::one();
    let two = &one + &one;
    let n_minus_one = n - &one;
    let mut d = n_minus_one.clone();
    let mut s = 0;
    while d.is_even() {
        d /= &two;
        s += 1;
    }
    let mut rng = OsRng;
    for _ in 0..iterations {
        let a = rng.gen_biguint_range(&two, &(n - &two));
        let mut x = a.modpow(&d, n);
        if x == one || x == n_minus_one {
            continue;
        }
        let mut cont = false;
        for _ in 0..(s - 1) {
            x = x.modpow(&two, n);
            if x == n_minus_one {
                cont = true;
                break;
            }
            if x == one {
                return false;
            }
        }
        if !cont {
            return false;
        }
    }
    true
}

fn generate_prime(bit_size: usize, iterations: usize) -> BigUint {
    let mut rng = OsRng;
    loop {
        let mut candidate = rng.gen_biguint(bit_size as u64);
        candidate.set_bit((bit_size - 1) as u64, true);
        candidate.set_bit(0, true);
        if is_probably_prime(&candidate, iterations) {
            return candidate;
        }
    }
}

fn generate_rsa_modulus(bit_size: usize, iterations: usize) -> BigUint {
    let prime_bits = bit_size / 2;
    let p = generate_prime(prime_bits, iterations);
    let q = generate_prime(prime_bits, iterations);
    p * q
}

// ====================== 同态加密模块（EC-ElGamal，仅支持小整数） ======================
pub mod lhe {
    use super::*;
    use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
    use curve25519_dalek::scalar::Scalar;
    use curve25519_dalek::traits::Identity;
    use rand::rngs::OsRng;
    use std::collections::HashMap;

    #[derive(Clone, Debug)]
    pub struct LheCiphertext {
        pub c1: CompressedRistretto, // g^m
        pub c2: CompressedRistretto, // y^r
    }

    pub type LhePublicKey = RistrettoPoint; // y = g^x (public key)
    pub type LhePrivateKey = Scalar; // x (private key)

    // EC-ElGamal 密钥生成
    pub fn keygen() -> (LhePublicKey, LhePrivateKey, RistrettoPoint) {
        let mut rng = OsRng;
        let sk = Scalar::random(&mut rng);
        // 固定基点 g，使用 Dalek 内置常量可提高安全性
        let g = RistrettoPoint::default()
            + RistrettoPoint::hash_from_bytes::<Blake3Adapter>(b"fixed_basepoint");
        let pk = g * sk;
        (pk, sk, g)
    }

    // 加密：m -> E(m) = (g^m, y^r)
    // 限制 m 为 u64 范围内的小整数
    pub fn encrypt(pk: &LhePublicKey, g: &RistrettoPoint, m: u64) -> LheCiphertext {
        let mut rng = OsRng;
        let r = Scalar::random(&mut rng);
        let m_scalar = Scalar::from(m);
        let c1 = g * m_scalar;
        let c2 = pk * r;
        LheCiphertext {
            c1: c1.compress(),
            c2: c2.compress(),
        }
    }

    // 使用 Baby-Step Giant-Step 算法计算离散对数
    // 设定搜索上界 MAX_M（生产环境中需要保证该范围覆盖所有合法 m）
    pub fn discrete_log(g: &RistrettoPoint, target: &RistrettoPoint, max_m: u64) -> Option<u64> {
        let m = (max_m as f64).sqrt().ceil() as u64;
        let mut baby_steps: HashMap<CompressedRistretto, u64> = HashMap::new();
        let mut current = RistrettoPoint::identity();
        for j in 0..m {
            baby_steps.insert(current.compress(), j);
            current = current + g;
        }
        let factor = g * Scalar::from(m);
        let mut giant = *target;
        for i in 0..m {
            if let Some(&j) = baby_steps.get(&giant.compress()) {
                let candidate = i * m + j;
                if candidate <= max_m {
                    return Some(candidate);
                }
            }
            giant = giant - factor;
        }
        None
    }

    // 解密：E(m) -> m = discrete_log(c1)
    // 为避免暴力搜索过慢，这里使用 baby-step giant-step 算法，搜索上界为 MAX_DECRYPT_RANGE
    pub fn decrypt(g: &RistrettoPoint, ct: &LheCiphertext) -> Result<u64, CryptoError> {
        let c1 = ct.c1.decompress().ok_or(CryptoError::DecryptionError)?;
        // 当加密的 m 较小时，可以用离散对数算法求解（此处设定最大搜索范围）
        const MAX_DECRYPT_RANGE: u64 = 10_000_000;
        discrete_log(g, &c1, MAX_DECRYPT_RANGE).ok_or(CryptoError::DecryptionError)
    }

    // 同态加法：E(m1) ⊕ E(m2) = E(m1+m2)
    pub fn add(ct1: &LheCiphertext, ct2: &LheCiphertext) -> LheCiphertext {
        let c1_new = ct1.c1.decompress().expect("Failed to decompress c1")
            + ct2.c1.decompress().expect("Failed to decompress c1");
        let c2_new = ct1.c2.decompress().expect("Failed to decompress c2")
            + ct2.c2.decompress().expect("Failed to decompress c2");
        LheCiphertext {
            c1: c1_new.compress(),
            c2: c2_new.compress(),
        }
    }
}

// ====================== Bulletproofs 封装 ======================
pub struct BulletproofWrapper {
    bp_gens: BulletproofGens,
    pc_gens: PedersenGens,
}

impl BulletproofWrapper {
    pub fn new() -> Self {
        Self {
            bp_gens: BulletproofGens::new(64, 1),
            pc_gens: PedersenGens::default(),
        }
    }

    pub fn prove_range(
        &self,
        secret: u64,
        blinding: Scalar,
    ) -> Result<(RangeProof, CompressedRistretto), CryptoError> {
        let mut transcript = Transcript::new(b"RangeProof");
        let mut rng = OsRng;
        let (proof, commitments) = RangeProof::prove_multiple_with_rng(
            &self.bp_gens,
            &self.pc_gens,
            &mut transcript,
            &[secret],
            &[blinding],
            64,
            &mut rng,
        )
        .map_err(|_| CryptoError::VerificationError)?;
        Ok((proof, commitments[0]))
    }

    pub fn verify_range(
        &self,
        proof: &RangeProof,
        commitment: CompressedRistretto,
    ) -> Result<(), CryptoError> {
        let mut transcript = Transcript::new(b"RangeProof");
        let mut rng = OsRng;
        proof
            .verify_multiple_with_rng(
                &self.bp_gens,
                &self.pc_gens,
                &mut transcript,
                &[commitment],
                64,
                &mut rng,
            )
            .map_err(|_| CryptoError::VerificationError)
    }

    pub fn prove_blinded_attributes(
        &self,
        attributes: &[u64],
    ) -> Result<Vec<BlindedAttribute>, CryptoError> {
        Ok(attributes
            .iter()
            .map(|&attr| BlindedAttribute::new(attr, &self.pc_gens))
            .collect())
    }
}

// ====================== RSA 累加器模块 ======================
mod rsa_accumulator {
    use super::*;
    use num_traits::Signed;
    #[derive(Clone)]
    pub struct RSAAccumulator {
        pub modulus: BigUint,
        pub generator: BigUint,
        pub accumulated: BigUint, // A = g^(∏elements) mod N
        pub product: BigUint,     // ∏(elements)
        revoked: Vec<BigUint>,
    }

    impl RSAAccumulator {
        pub fn new(modulus: BigUint, generator: BigUint) -> Self {
            Self {
                modulus: modulus.clone(),
                generator: generator.clone(),
                accumulated: generator.clone(),
                product: BigUint::one(),
                revoked: Vec::new(),
            }
        }

        pub fn add(&mut self, elem: BigUint) {
            self.revoked.push(elem.clone());
            self.product *= &elem;
            self.accumulated = self.generator.modpow(&self.product, &self.modulus);
        }

        pub fn rebuild(&mut self) {
            self.product = BigUint::one();
            for elem in &self.revoked {
                self.product *= elem;
            }
            self.accumulated = self.generator.modpow(&self.product, &self.modulus);
        }

        pub fn generate_non_membership_proof(
            &self,
            uid: &BigUint,
        ) -> Result<(BigUint, BigUint), CryptoError> {
            if self.revoked.iter().any(|e| e == uid) {
                return Err(CryptoError::NonMembershipError);
            }
            let prod = self.product.clone();
            let uid_int = uid.to_bigint().ok_or(CryptoError::NonMembershipError)?;
            let prod_int = prod.to_bigint().ok_or(CryptoError::NonMembershipError)?;

            let (gcd, a, b) = extended_gcd(&uid_int, &prod_int);
            if gcd != BigInt::one() {
                return Err(CryptoError::NonMembershipError);
            }
            let a = if a < BigInt::zero() {
                (a % &uid_int).abs()
            } else {
                a
            };
            let witness = self.generator.modpow(
                &a.to_biguint().ok_or(CryptoError::NonMembershipError)?,
                &self.modulus,
            );
            let b = b
                .mod_floor(&uid_int)
                .abs()
                .to_biguint()
                .ok_or(CryptoError::NonMembershipError)?;
            Ok((witness, b))
        }

        pub fn verify_non_membership_proof(
            &self,
            uid: &BigUint,
            witness: &BigUint,
            remainder: &BigUint,
        ) -> bool {
            let lhs = (witness.modpow(uid, &self.modulus)
                * self.accumulated.modpow(remainder, &self.modulus))
                % &self.modulus;
            lhs == self.generator
        }
    }

    fn extended_gcd(x: &BigInt, y: &BigInt) -> (BigInt, BigInt, BigInt) {
        if y.is_zero() {
            (x.clone(), BigInt::one(), BigInt::zero())
        } else {
            let (gcd, a1, b1) = extended_gcd(y, &(x % y));
            (gcd, b1.clone(), a1 - (x / y) * b1)
        }
    }
}

use rsa_accumulator::RSAAccumulator;

// ====================== Blinded Attribute ======================
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlindedAttribute {
    pub value: u64,
    pub blind: Scalar,
    pub commitment: CompressedRistretto,
}

impl BlindedAttribute {
    pub fn new(value: u64, pc_gens: &PedersenGens) -> Self {
        let mut rng = OsRng;
        let blind = Scalar::random(&mut rng);
        let commitment = pc_gens.commit(Scalar::from(value), blind).compress();
        Self {
            value,
            blind,
            commitment,
        }
    }
}

// ====================== 匿名凭证结构 ======================
#[derive(Debug, Serialize, Deserialize)]
pub struct AnonymousCredential {
    pub range_commitment: CompressedRistretto,
    pub range_proof: RangeProof,
    pub blinded_attributes: Vec<BlindedAttribute>,
    pub counter: u64,
    pub valid_from: i64,
    pub valid_until: i64,
    pub uid: u64, // 用于撤销及证明的唯一标识符
}

impl AnonymousCredential {
    pub fn issue(
        bp: &BulletproofWrapper,
        attributes: &[u64],
        counter: u64,
        uid: u64,
    ) -> Result<Self, CryptoError> {
        let mut rng = OsRng;
        let blind = Scalar::random(&mut rng);
        let (range_proof, range_commitment) = bp.prove_range(counter, blind)?;
        let blinded_attributes = bp.prove_blinded_attributes(attributes)?;
        let now = Utc::now().timestamp();
        info!(
            "Issued credential: uid {}, counter {}, attributes {:?}",
            uid, counter, attributes
        );
        Ok(Self {
            range_commitment,
            range_proof,
            blinded_attributes,
            counter,
            valid_from: now,
            valid_until: now + Duration::hours(24).num_seconds(),
            uid,
        })
    }

    pub fn update(
        &mut self,
        bp: &BulletproofWrapper,
        new_attributes: &[u64],
    ) -> Result<(), CryptoError> {
        let mut rng = OsRng;
        let blind = Scalar::random(&mut rng);
        let (range_proof, range_commitment) = bp.prove_range(self.counter, blind)?;
        self.range_proof = range_proof;
        self.range_commitment = range_commitment;
        self.blinded_attributes = bp.prove_blinded_attributes(new_attributes)?;
        let now = Utc::now().timestamp();
        self.valid_from = now;
        self.valid_until = now + Duration::hours(24).num_seconds();
        info!(
            "Updated credential uid {} with new attributes {:?}",
            self.uid, new_attributes
        );
        Ok(())
    }

    pub fn verify(&self, bp: &BulletproofWrapper) -> Result<(), CryptoError> {
        bp.verify_range(&self.range_proof, self.range_commitment)?;
        let now = Utc::now().timestamp();
        if now < self.valid_from || now > self.valid_until {
            error!(
                "Credential uid {} expired: valid_from {}, valid_until {}, now {}",
                self.uid, self.valid_from, self.valid_until, now
            );
            return Err(CryptoError::VerificationError);
        }
        Ok(())
    }
}

// ====================== 系统参与方密钥 ======================
#[derive(Clone)]
pub struct IssuerKeys {
    pub sk_blind: Scalar,
    pub pk_blind: RistrettoPoint,
    pub sk_group: Scalar,
    pub pk_group: RistrettoPoint,
    pub pk_eq: RistrettoPoint,
}

#[derive(Clone)]
pub struct UserKeys {
    pub sk: Scalar,
    pub pk: RistrettoPoint,
}

#[derive(Clone)]
pub struct AuditorKeys {
    pub sk: Scalar,
    pub pk: RistrettoPoint,
}

// ====================== 系统初始化与密钥生成 ======================
pub struct SystemParameters {
    pub lambda: usize,
    pub bp: BulletproofWrapper,
    pub rsa_modulus: BigUint,
    pub rsa_generator: BigUint,
    pub accumulator: RSAAccumulator,
    pub bulletin_board: Vec<String>,
    pub lhe_pk: lhe::LhePublicKey,
    pub lhe_sk: lhe::LhePrivateKey,
    pub lhe_g: RistrettoPoint,
}

pub fn setup(lambda: usize) -> SystemParameters {
    let bp = BulletproofWrapper::new();
    let rsa_modulus = generate_rsa_modulus(2048, 20);
    let rsa_generator = BigUint::from(2u32);
    let accumulator = RSAAccumulator::new(rsa_modulus.clone(), rsa_generator.clone());
    let bulletin_board = Vec::new();
    let (lhe_pk, lhe_sk, lhe_g) = lhe::keygen();
    info!("System setup complete.");
    SystemParameters {
        lambda,
        bp,
        rsa_modulus,
        rsa_generator,
        accumulator,
        bulletin_board,
        lhe_pk,
        lhe_sk,
        lhe_g,
    }
}

pub fn keygen_parties() -> (IssuerKeys, UserKeys, AuditorKeys) {
    let mut rng = OsRng;
    let sk_blind = Scalar::random(&mut rng);
    let pk_blind = RistrettoPoint::hash_from_bytes::<Blake3Adapter>(sk_blind.as_bytes());
    let sk_group = Scalar::random(&mut rng);
    let pk_group = RistrettoPoint::hash_from_bytes::<Blake3Adapter>(sk_group.as_bytes());
    let pk_eq = RistrettoPoint::hash_from_bytes::<Blake3Adapter>(b"equiv_public");
    let issuer_keys = IssuerKeys {
        sk_blind,
        pk_blind,
        sk_group,
        pk_group,
        pk_eq,
    };
    let sk_user = Scalar::random(&mut rng);
    let pk_user = RistrettoPoint::hash_from_bytes::<Blake3Adapter>(sk_user.as_bytes());
    let user_keys = UserKeys {
        sk: sk_user,
        pk: pk_user,
    };
    let sk_auditor = Scalar::random(&mut rng);
    let pk_auditor = RistrettoPoint::hash_from_bytes::<Blake3Adapter>(sk_auditor.as_bytes());
    let auditor_keys = AuditorKeys {
        sk: sk_auditor,
        pk: pk_auditor,
    };
    info!("Key generation complete for all parties.");
    (issuer_keys, user_keys, auditor_keys)
}

// ====================== ZK 证明结构 ======================
#[derive(Debug, Serialize, Deserialize)]
pub struct ZKProof {
    pub witness: BigUint,
    pub remainder: BigUint,
}

// ====================== 协议函数 ======================

/// (Issue) 凭证发行
pub fn issue_credential(
    sys_params: &SystemParameters,
    _issuer: &IssuerKeys,
    _user_keys: &UserKeys,
    attributes: &[u64],
    counter: u64,
    uid: u64,
) -> Result<AnonymousCredential, CryptoError> {
    let cred = AnonymousCredential::issue(&sys_params.bp, attributes, counter, uid)?;
    info!("Credential issued for uid {}", uid);
    Ok(cred)
}

/// (Update) 凭证更新
pub fn update_credential(
    sys_params: &SystemParameters,
    cred: &mut AnonymousCredential,
    new_attributes: &[u64],
) -> Result<(), CryptoError> {
    cred.update(&sys_params.bp, new_attributes)
}

/// (Prove) 生成零知识证明（基于 RSA 累加器非成员证明）
pub fn prove(
    cred: &AnonymousCredential,
    accumulator: &RSAAccumulator,
) -> Result<ZKProof, CryptoError> {
    let uid_big = BigUint::from(cred.uid);
    let (witness, remainder) = accumulator.generate_non_membership_proof(&uid_big)?;
    info!("ZK proof generated for uid {}", cred.uid);
    Ok(ZKProof { witness, remainder })
}

/// (Verify) 验证零知识证明
pub fn verify(
    cred: &AnonymousCredential,
    zk_proof: &ZKProof,
    accumulator: &RSAAccumulator,
) -> Result<bool, CryptoError> {
    let uid_big = BigUint::from(cred.uid);
    if accumulator.verify_non_membership_proof(&uid_big, &zk_proof.witness, &zk_proof.remainder) {
        info!("ZK proof verification succeeded for uid {}", cred.uid);
        Ok(true)
    } else {
        error!("ZK proof verification failed for uid {}", cred.uid);
        Err(CryptoError::VerificationError)
    }
}

/// (BlacklistManage) 黑名单管理：更新累加器并记录公告
pub fn blacklist_manage(sys_params: &mut SystemParameters, uid: u64) -> Result<(), CryptoError> {
    sys_params.accumulator.add(BigUint::from(uid));
    let entry = format!("Blacklisted uid {}", uid);
    sys_params.bulletin_board.push(entry);
    info!("Blacklist updated for uid {}", uid);
    Ok(())
}

/// (Revoke) 凭证撤销
pub fn revoke(sys_params: &mut SystemParameters, uid: u64) -> Result<(), CryptoError> {
    blacklist_manage(sys_params, uid)
}

/// (Audit) 公开审计：返回公告板记录
pub fn audit(sys_params: &SystemParameters) -> Vec<String> {
    sys_params.bulletin_board.clone()
}

/// (Aggregate) 聚合停车费用（使用同态加密）
pub fn aggregate(
    sys_params: &SystemParameters,
    fees: &[u64],
) -> Result<lhe::LheCiphertext, CryptoError> {
    let mut agg = lhe::encrypt(&sys_params.lhe_pk, &sys_params.lhe_g, 0);
    for &fee in fees {
        let ct = lhe::encrypt(&sys_params.lhe_pk, &sys_params.lhe_g, fee);
        agg = lhe::add(&agg, &ct);
    }
    info!("Aggregated ciphertext computed.");
    Ok(agg)
}

/// (Payment) 支付处理
pub fn payment(
    sys_params: &mut SystemParameters,
    cred: &mut AnonymousCredential,
    fee: u64,
) -> Result<String, CryptoError> {
    if cred.counter < fee {
        error!(
            "Insufficient balance for uid {}: counter {}, fee {}",
            cred.uid, cred.counter, fee
        );
        return Err(CryptoError::VerificationError);
    }
    cred.counter -= fee;
    update_credential(
        sys_params,
        cred,
        &cred
            .blinded_attributes
            .iter()
            .map(|b| b.value)
            .collect::<Vec<_>>(),
    )?;
    let receipt = format!("Payment receipt for uid {}: fee {}", cred.uid, fee);
    info!("{}", receipt);
    Ok(receipt)
}

/// (Trace) 违规追踪：利用 EC-ElGamal 解密恢复 uid
pub fn trace(sys_params: &SystemParameters, ct: &lhe::LheCiphertext) -> Result<u64, CryptoError> {
    let m = lhe::decrypt(&sys_params.lhe_g, ct)?;
    Ok(m)
}

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


