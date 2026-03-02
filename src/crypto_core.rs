//! Crypto primitives taken from the user-provided core.
//!
//! This is a lightly wrapped copy of the provided `crypto.rs`.

use blake3;
use chacha20poly1305::{
    aead::{
        generic_array::GenericArray,
        AeadInPlace, Error as AeadError, KeyInit,
    },
    XChaCha20Poly1305, XNonce,
};
use curve25519_dalek::{
    ristretto::RistrettoPoint,
    scalar::Scalar,
    traits::Identity,
};
use rand_core::RngCore;

pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;

#[derive(Clone, Debug)]
pub struct CtBlob<const PT_LEN: usize> {
    pub nonce: [u8; NONCE_LEN],
    pub ct: [u8; PT_LEN],
    pub tag: [u8; TAG_LEN],
}

pub fn hash_to_point(msg: &[u8]) -> RistrettoPoint {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"uptspa/hash_to_point");
    hasher.update(msg);

    let mut wide = [0u8; 64];
    hasher.finalize_xof().fill(&mut wide);

    RistrettoPoint::from_uniform_bytes(&wide)
}

pub fn oprf_finalize(password: &[u8], y: &RistrettoPoint) -> [u8; 32] {
    let y_bytes = y.compress().to_bytes();

    let mut h = blake3::Hasher::new();
    h.update(b"uptspa/oprf_finalize");
    h.update(password);
    h.update(&y_bytes);

    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(out.as_bytes());
    r
}

pub fn xchacha_encrypt_detached<const PT_LEN: usize>(
    key: &[u8; 32],
    aad: &[u8],
    plaintext: &[u8; PT_LEN],
    rng: &mut impl RngCore,
) -> CtBlob<PT_LEN> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).unwrap();

    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let xnonce = XNonce::from_slice(&nonce);

    let mut ct = *plaintext;
    let tag = cipher.encrypt_in_place_detached(xnonce, aad, &mut ct).unwrap();

    let mut tag_bytes = [0u8; TAG_LEN];
    tag_bytes.copy_from_slice(tag.as_slice());

    CtBlob {
        nonce,
        ct,
        tag: tag_bytes,
    }
}

pub fn xchacha_decrypt_detached<const PT_LEN: usize>(
    key: &[u8; 32],
    aad: &[u8],
    blob: &CtBlob<PT_LEN>,
) -> Result<[u8; PT_LEN], AeadError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).unwrap();
    let xnonce = XNonce::from_slice(&blob.nonce);

    let mut pt = blob.ct;
    let tag = GenericArray::from_slice(&blob.tag);

    cipher.decrypt_in_place_detached(xnonce, aad, &mut pt, tag)?;
    Ok(pt)
}

pub fn hash_suid(rsp: &[u8; 32], lsj: &[u8], i: u32) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"uptspa/suid");
    h.update(rsp);
    h.update(lsj);
    h.update(&i.to_le_bytes());

    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(out.as_bytes());
    r
}

pub fn hash_vinfo(rlsj: &[u8; 32], lsj: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"uptspa/vinfo");
    h.update(rlsj);
    h.update(lsj);

    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(out.as_bytes());
    r
}

pub fn toprf_gen(nsp: usize, tsp: usize, rng: &mut impl RngCore) -> (Scalar, Vec<(u32, Scalar)>) {
    assert!(tsp >= 1 && tsp <= nsp);

    let a0 = random_scalar(rng);
    let mut coeffs = vec![a0];
    for _ in 1..tsp {
        coeffs.push(random_scalar(rng));
    }

    fn eval(coeffs: &[Scalar], x: Scalar) -> Scalar {
        let mut acc = Scalar::ZERO;
        let mut pow = Scalar::ONE;
        for c in coeffs {
            acc += c * pow;
            pow *= x;
        }
        acc
    }

    let mut shares = Vec::with_capacity(nsp);
    for i in 1..=nsp {
        shares.push((i as u32, eval(&coeffs, Scalar::from(i as u64))));
    }

    (a0, shares)
}

pub fn lagrange_coeffs_at_zero(ids: &[u32]) -> Vec<Scalar> {
    let xs: Vec<Scalar> = ids.iter().map(|&i| Scalar::from(i as u64)).collect();
    let mut lambdas = Vec::with_capacity(xs.len());

    for i in 0..xs.len() {
        let mut num = Scalar::ONE;
        let mut den = Scalar::ONE;
        for j in 0..xs.len() {
            if i != j {
                num *= xs[j];
                den *= xs[j] - xs[i];
            }
        }
        lambdas.push(num * den.invert());
    }
    lambdas
}

pub fn toprf_client_eval(
    password: &[u8],
    r: Scalar,
    partials: &[RistrettoPoint],
    lambdas: &[Scalar],
) -> [u8; 32] {
    let p = hash_to_point(password);
    let blinded = p * r;
    std::hint::black_box(blinded.compress());

    let mut acc = RistrettoPoint::identity();
    for (y, l) in partials.iter().zip(lambdas) {
        acc += y * l;
    }

    let y = acc * r.invert();
    oprf_finalize(password, &y)
}

pub fn toprf_client_eval_from_partials(
    password: &[u8],
    r: Scalar,
    partials: &[RistrettoPoint],
    lambdas: &[Scalar],
) -> [u8; 32] {
    let mut acc = RistrettoPoint::identity();
    for (y, l) in partials.iter().zip(lambdas) {
        acc += y * l;
    }

    let y = acc * r.invert();
    oprf_finalize(password, &y)
}

pub fn random_scalar(rng: &mut impl RngCore) -> Scalar {
    loop {
        let mut wide = [0u8; 64];
        rng.fill_bytes(&mut wide);
        let s = Scalar::from_bytes_mod_order_wide(&wide);
        if s != Scalar::ZERO {
            return s;
        }
    }
}
