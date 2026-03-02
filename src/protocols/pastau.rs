#![allow(clippy::needless_range_loop)]

//! PAS-TA-U (2020) protocol (client + identity servers) as described in the prompt.
//!
//! This implementation is intentionally "bench harness" style:
//! - It uses Ristretto TOPRF shares (threshold OPRF) for password-derived keys.
//! - It uses a threshold BLS signature (TTG) as the publicly verifiable token.
//! - It includes an explicit Registration flow (U + IP + servers) and
//!   the PasswordUpdate protocol.

use std::collections::HashMap;
use blake3;
use curve25519_dalek::{
    ristretto::CompressedRistretto,
    scalar::Scalar as RScalar,
};
use curve25519_dalek::RistrettoPoint;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

use crate::crypto_core;
use crate::crypto_pastau as pc;

pub const UID_LEN: usize = 32;
pub const X_LEN: usize = 32;
pub const TOP_REQ_LEN: usize = 32; // compressed Ristretto
pub const TOP_PARTIAL_LEN: usize = 32; // compressed Ristretto

pub const UPDATE_PT_LEN: usize = 64; // hi || h'i
pub const UPDATE_BLOB_LEN: usize = pc::NONCE_LEN + UPDATE_PT_LEN + pc::TAG_LEN;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ClientId(pub [u8; UID_LEN]);

#[derive(Clone, Copy, Debug)]
pub struct PublicParams {
    pub kappa: usize,
    pub n: usize,
    pub t: usize,
}

// ---------------------------
// GlobalSetup
// ---------------------------

#[derive(Clone)]
pub struct GlobalSetupOut {
    pub ttg_shares: Vec<(u32, pc::TtgShare)>,
    pub vk: pc::TtgVk,
    pub pp: PublicParams,
}

pub fn global_setup(kappa: usize, n: usize, t: usize, rng: &mut impl RngCore) -> GlobalSetupOut {
    let (ttg_shares, vk) = pc::ttg_setup(n, t, rng);
    GlobalSetupOut {
        ttg_shares,
        vk,
        pp: PublicParams { kappa, n, t },
    }
}

// ---------------------------
// Registration (U, IP, servers)
// ---------------------------

#[derive(Clone, Debug)]
pub struct RegistrationMsg {
    pub server_id: u32,
    pub k_i: RScalar,
    pub h_i: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct RegistrationOut {
    /// Identity provider's master TOPRF secret (k). Returned only for testing.
    pub k0: RScalar,
    pub msgs: Vec<RegistrationMsg>,
}

/// Simulate the 3-step PAS-TA-U registration and output per-server (k_i, h_i) messages.
///
/// Steps (high-level):
/// 1) U -> IP: reg = H2(pwd)^r
/// 2) IP chooses k, returns res = reg^k to U, and shares k -> (k_i)
/// 3) U unblinds to get H2(pwd)^k and derives h_i = H(TOP_k(pwd) || i)
pub fn registration(n: usize, t: usize, password: &[u8], rng: &mut impl RngCore) -> RegistrationOut {
    // Step 1 (U)
    let r = crypto_core::random_scalar(rng);
    let reg: RistrettoPoint = pc::toprf_encode(password, r);

    // Step 2 (IP)
    let (k0, shares) = crypto_core::toprf_gen(n, t, rng); // Shamir share
    let res: RistrettoPoint = reg * k0;

    // Step 3 (U)
    let y = res * r.invert(); // H2(pwd)^k
    let h = crypto_core::oprf_finalize(password, &y);

    let mut msgs = Vec::with_capacity(n);
    for (sid, k_i) in shares {
        let h_i = pc::hash_hi(&h, sid);
        msgs.push(RegistrationMsg {
            server_id: sid,
            k_i,
            h_i,
        });
    }

    RegistrationOut { k0, msgs }
}

#[derive(Clone, Debug)]
pub struct ServerRecord {
    pub k_i: RScalar,
    pub h_i: [u8; 32],
}

#[derive(Clone)]
pub struct PastauServer {
    pub id: u32,
    pub ttg_share: pc::TtgShare,
    records: HashMap<ClientId, ServerRecord>,
}

impl PastauServer {
    pub fn new(id: u32, ttg_share: pc::TtgShare) -> Self {
        Self {
            id,
            ttg_share,
            records: HashMap::new(),
        }
    }

    pub fn store(&mut self, c: ClientId, msg: &RegistrationMsg) {
        debug_assert_eq!(self.id, msg.server_id);
        self.records.insert(
            c,
            ServerRecord {
                k_i: msg.k_i,
                h_i: msg.h_i,
            },
        );
    }

    pub fn has_record(&self, c: ClientId) -> bool {
        self.records.contains_key(&c)
    }

    pub fn get_record(&self, c: ClientId) -> Option<&ServerRecord> {
        self.records.get(&c)
    }

    pub fn get_record_mut(&mut self, c: ClientId) -> Option<&mut ServerRecord> {
        self.records.get_mut(&c)
    }
}

// ---------------------------
// TokenGeneration (authentication): Request + Respond + Finalize
// ---------------------------

#[derive(Clone, Debug)]
pub struct ClientState {
    pub c: ClientId,
    pub password: Vec<u8>,
    pub rho: RScalar,
    pub t_set: Vec<u32>,
}

#[derive(Clone, Debug)]
pub struct ClientRequest {
    pub c: ClientId,
    pub x: [u8; X_LEN],
    pub req: [u8; TOP_REQ_LEN],
}

pub fn request(
    c: ClientId,
    password: &[u8],
    x: [u8; X_LEN],
    t_set: &[u32],
    rng: &mut impl RngCore,
) -> (ClientState, ClientRequest) {
    let rho = crypto_core::random_scalar(rng);
    request_with_rho(c, password, x, t_set, rho)
}

pub fn request_with_rho(
    c: ClientId,
    password: &[u8],
    x: [u8; X_LEN],
    t_set: &[u32],
    rho: RScalar,
) -> (ClientState, ClientRequest) {
    assert!(!t_set.is_empty());
    let req_point = pc::toprf_encode(password, rho);
    let req_bytes = req_point.compress().to_bytes();

    let st = ClientState {
        c,
        password: password.to_vec(),
        rho,
        t_set: t_set.to_vec(),
    };
    let req = ClientRequest { c, x, req: req_bytes };
    (st, req)
}

#[derive(Clone, Debug)]
pub struct ServerResponse {
    pub server_id: u32,
    pub z_i: [u8; TOP_PARTIAL_LEN],
    pub ctxt_i: pc::CtBlob<{pc::TTG_TOKEN_LEN}>,
}

/// Server-side TOPRF-only response (used by PasswordUpdate steps 1/2).
pub fn respond_toprf_only(
    srv: &PastauServer,
    c: ClientId,
    req_bytes: &[u8; TOP_REQ_LEN],
) -> Option<[u8; TOP_PARTIAL_LEN]> {
    let rec = srv.records.get(&c)?;
    let req_point = CompressedRistretto(*req_bytes).decompress()?;
    let z_i = pc::toprf_eval_share(rec.k_i, &req_point);
    Some(z_i.compress().to_bytes())
}

fn build_ttg_msg_stack(x: &[u8; X_LEN], c: &ClientId) -> [u8; X_LEN + UID_LEN] {
    let mut msg = [0u8; X_LEN + UID_LEN];
    msg[0..X_LEN].copy_from_slice(x);
    msg[X_LEN..X_LEN + UID_LEN].copy_from_slice(&c.0);
    msg
}

fn build_ttg_msg_heap(pld: &[u8], c: &ClientId) -> Vec<u8> {
    let mut v = Vec::with_capacity(pld.len() + UID_LEN);
    v.extend_from_slice(pld);
    v.extend_from_slice(&c.0);
    v
}

/// Server-side Respond with RNG (nonce generation) inside.
///
/// TTG message is `x || idU` (payload concatenated with user id).
pub fn respond(
    srv: &PastauServer,
    c: ClientId,
    x: [u8; X_LEN],
    req_bytes: &[u8; TOP_REQ_LEN],
    rng: &mut impl RngCore,
) -> Option<ServerResponse> {
    let rec = srv.records.get(&c)?;
    let req_point = CompressedRistretto(*req_bytes).decompress()?;

    let z_i = pc::toprf_eval_share(rec.k_i, &req_point);
    let z_bytes = z_i.compress().to_bytes();

    let msg = build_ttg_msg_stack(&x, &c);
    let y_i = pc::ttg_part_eval(&srv.ttg_share, &msg);
    let y_bytes = pc::ttg_partial_to_bytes(&y_i);

    // Spec shows SKE.Encrypt(hi, yi) with no AAD.
    let aad: [u8; 0] = [];
    let ctxt_i = pc::xchacha_encrypt_detached(&rec.h_i, &aad, &y_bytes, rng);

    Some(ServerResponse {
        server_id: srv.id,
        z_i: z_bytes,
        ctxt_i,
    })
}

/// Server-side Respond with a provided nonce (for "no RNG in timed region" benchmarks).
pub fn respond_with_nonce(
    srv: &PastauServer,
    c: ClientId,
    x: [u8; X_LEN],
    req_bytes: &[u8; TOP_REQ_LEN],
    nonce: &[u8; crypto_core::NONCE_LEN],
) -> Option<ServerResponse> {
    let rec = srv.records.get(&c)?;
    let req_point = CompressedRistretto(*req_bytes).decompress()?;

    let z_i = pc::toprf_eval_share(rec.k_i, &req_point);
    let z_bytes = z_i.compress().to_bytes();

    let msg = build_ttg_msg_stack(&x, &c);
    let y_i = pc::ttg_part_eval(&srv.ttg_share, &msg);
    let y_bytes = pc::ttg_partial_to_bytes(&y_i);

    let aad: [u8; 0] = [];
    let ctxt_i = pc::xchacha_encrypt_detached_with_nonce(&rec.h_i, &aad, &y_bytes, nonce);

    Some(ServerResponse {
        server_id: srv.id,
        z_i: z_bytes,
        ctxt_i,
    })
}

/// Generic Respond for variable-length payloads (used by PasswordUpdate token generation).
///
/// TTG message is `payload || idU`.
pub fn respond_var_payload(
    srv: &PastauServer,
    c: ClientId,
    payload: &[u8],
    req_bytes: &[u8; TOP_REQ_LEN],
    rng: &mut impl RngCore,
) -> Option<ServerResponse> {
    let rec = srv.records.get(&c)?;
    let req_point = CompressedRistretto(*req_bytes).decompress()?;

    let z_i = pc::toprf_eval_share(rec.k_i, &req_point);
    let z_bytes = z_i.compress().to_bytes();

    let msg = build_ttg_msg_heap(payload, &c);
    let y_i = pc::ttg_part_eval(&srv.ttg_share, &msg);
    let y_bytes = pc::ttg_partial_to_bytes(&y_i);

    let aad: [u8; 0] = [];
    let ctxt_i = pc::xchacha_encrypt_detached(&rec.h_i, &aad, &y_bytes, rng);

    Some(ServerResponse {
        server_id: srv.id,
        z_i: z_bytes,
        ctxt_i,
    })
}

pub fn finalize(st: &ClientState, resps: &[ServerResponse]) -> Option<pc::TtgToken> {
    if resps.len() != st.t_set.len() {
        return None;
    }

    // Ensure the response set matches T exactly.
    let mut ids: Vec<u32> = resps.iter().map(|r| r.server_id).collect();
    ids.sort_unstable();
    let mut t_sorted = st.t_set.clone();
    t_sorted.sort_unstable();
    if ids != t_sorted {
        return None;
    }

    // TOP.Combine -> h
    let lambdas = crypto_core::lagrange_coeffs_at_zero(&t_sorted);
    let mut partials = Vec::with_capacity(resps.len());
    for &sid in &t_sorted {
        let r = resps.iter().find(|r| r.server_id == sid).unwrap();
        let pt = CompressedRistretto(r.z_i).decompress()?;
        partials.push(pt);
    }
    let h = crypto_core::toprf_client_eval_from_partials(&st.password, st.rho, &partials, &lambdas);

    // Decrypt TTG partials and combine
    let aad: [u8; 0] = [];
    let mut ttg_partials = Vec::with_capacity(resps.len());
    for &sid in &t_sorted {
        let r = resps.iter().find(|r| r.server_id == sid).unwrap();
        let h_i = pc::hash_hi(&h, sid);
        let y_bytes = pc::xchacha_decrypt_detached(&h_i, &aad, &r.ctxt_i).ok()?;
        let part = pc::ttg_token_from_partial_bytes(&y_bytes)?;
        ttg_partials.push(part);
    }

    Some(pc::ttg_combine(&t_sorted, &ttg_partials))
}

pub fn verify(vk: &pc::TtgVk, c: ClientId, x: [u8; X_LEN], tk: &pc::TtgToken) -> bool {
    let msg = build_ttg_msg_stack(&x, &c);
    pc::ttg_verify(vk, &msg, tk)
}

/// Verify a token for a variable-length payload where the TTG message is `payload || idU`.
pub fn verify_var_payload(vk: &pc::TtgVk, c: ClientId, payload: &[u8], tk: &pc::TtgToken) -> bool {
    let msg = build_ttg_msg_heap(payload, &c);
    pc::ttg_verify(vk, &msg, tk)
}

// ---------------------------
// PasswordUpdate (PAS-TA-U)
// ---------------------------

#[derive(Clone, Debug)]
pub struct PasswordUpdateClientOut {
    /// Update payload sent to servers: (Enc(h1, h1||h'1) || ... || Enc(hn, hn||h'n) || idU)
    pub pld3: Vec<u8>,
    /// Authentication token over pld3 (TTG token).
    pub tk_pld3: pc::TtgToken,
    /// New per-server keys (for testing / debugging).
    pub new_hi: Vec<[u8; 32]>,
}

fn serialize_update_blob(blob: &pc::CtBlob<UPDATE_PT_LEN>) -> [u8; UPDATE_BLOB_LEN] {
    let mut out = [0u8; UPDATE_BLOB_LEN];
    let mut off = 0;
    out[off..off + pc::NONCE_LEN].copy_from_slice(&blob.nonce);
    off += pc::NONCE_LEN;
    out[off..off + UPDATE_PT_LEN].copy_from_slice(&blob.ct);
    off += UPDATE_PT_LEN;
    out[off..off + pc::TAG_LEN].copy_from_slice(&blob.tag);
    out
}

fn deserialize_update_blob(bytes: &[u8; UPDATE_BLOB_LEN]) -> pc::CtBlob<UPDATE_PT_LEN> {
    let mut off = 0;
    let mut nonce = [0u8; pc::NONCE_LEN];
    nonce.copy_from_slice(&bytes[off..off + pc::NONCE_LEN]);
    off += pc::NONCE_LEN;
    let mut ct = [0u8; UPDATE_PT_LEN];
    ct.copy_from_slice(&bytes[off..off + UPDATE_PT_LEN]);
    off += UPDATE_PT_LEN;
    let mut tag = [0u8; pc::TAG_LEN];
    tag.copy_from_slice(&bytes[off..off + pc::TAG_LEN]);
    pc::CtBlob { nonce, ct, tag }
}

fn derive_h_from_toprf_partials(
    password: &[u8],
    rho: RScalar,
    ids: &[u32],
    z_bytes: &[[u8; TOP_PARTIAL_LEN]],
) -> Option<[u8; 32]> {
    let lambdas = crypto_core::lagrange_coeffs_at_zero(ids);
    let mut partials = Vec::with_capacity(z_bytes.len());
    for zb in z_bytes {
        partials.push(CompressedRistretto(*zb).decompress()?);
    }
    Some(crypto_core::toprf_client_eval_from_partials(password, rho, &partials, &lambdas))
}

fn derive_all_hi(h: &[u8; 32], n: usize) -> Vec<[u8; 32]> {
    (1..=n as u32).map(|sid| pc::hash_hi(h, sid)).collect()
}

/// Client-side PAS-TA-U PasswordUpdate.
///
/// This follows the description in the prompt:
/// 1) Derive old h -> all old hi.
/// 2) Derive new h' -> all new h'i.
/// 3) Build pld3 = Enc(hi, hi||h'i) for all i, append idU.
/// 4) Authenticate pld3 using TokenGeneration under the *old* password.
pub fn password_update_client(
    c: ClientId,
    old_password: &[u8],
    new_password: &[u8],
    vk: &pc::TtgVk,
    servers: &[PastauServer],
    t_set: &[u32],
    rng: &mut impl RngCore,
) -> Option<PasswordUpdateClientOut> {
    let n = servers.len();
    if n == 0 || t_set.is_empty() {
        return None;
    }

    // Step 1: derive old h -> old hi
    let rho1 = crypto_core::random_scalar(rng);
    let req1 = pc::toprf_encode(old_password, rho1).compress().to_bytes();
    let mut z1: Vec<[u8; TOP_PARTIAL_LEN]> = Vec::with_capacity(t_set.len());
    for &sid in t_set {
        let srv = servers.get((sid - 1) as usize)?;
        z1.push(respond_toprf_only(srv, c, &req1)?);
    }
    let h_old = derive_h_from_toprf_partials(old_password, rho1, t_set, &z1)?;
    let old_hi = derive_all_hi(&h_old, n);

    // Step 2: derive new h' -> new hi'
    let rho2 = crypto_core::random_scalar(rng);
    let req2 = pc::toprf_encode(new_password, rho2).compress().to_bytes();
    let mut z2: Vec<[u8; TOP_PARTIAL_LEN]> = Vec::with_capacity(t_set.len());
    for &sid in t_set {
        let srv = servers.get((sid - 1) as usize)?;
        z2.push(respond_toprf_only(srv, c, &req2)?);
    }
    let h_new = derive_h_from_toprf_partials(new_password, rho2, t_set, &z2)?;
    let new_hi = derive_all_hi(&h_new, n);

    // Step 3: build payload body = Enc(hi, hi||h'i) for all servers.
    let aad: [u8; 0] = [];
    let mut payload_body = Vec::with_capacity(n * UPDATE_BLOB_LEN);
    for i in 0..n {
        let mut pt = [0u8; UPDATE_PT_LEN];
        pt[0..32].copy_from_slice(&old_hi[i]);
        pt[32..64].copy_from_slice(&new_hi[i]);

        let blob = pc::xchacha_encrypt_detached::<UPDATE_PT_LEN>(&old_hi[i], &aad, &pt, rng);
        let b = serialize_update_blob(&blob);
        payload_body.extend_from_slice(&b);
    }

    // pld3 = payload_body || idU
    let mut pld3 = Vec::with_capacity(payload_body.len() + UID_LEN);
    pld3.extend_from_slice(&payload_body);
    pld3.extend_from_slice(&c.0);

    // Step 4: authenticate pld3 using TokenGeneration(old_password, payload_body).
    // TTG message is (payload_body || idU) which is exactly pld3.
    let tk_pld3 = {
        // Run a full token generation on variable payload.
        let rho = crypto_core::random_scalar(rng);
        let req = pc::toprf_encode(old_password, rho).compress().to_bytes();

        // server responses
        let mut resps = Vec::with_capacity(t_set.len());
        for &sid in t_set {
            let srv = servers.get((sid - 1) as usize)?;
            let resp = respond_var_payload(srv, c, &payload_body, &req, rng)?;
            resps.push(resp);
        }

        let st = ClientState {
            c,
            password: old_password.to_vec(),
            rho,
            t_set: t_set.to_vec(),
        };
        finalize(&st, &resps)?
    };

    // Sanity check: token verifies over pld3.
    if !pc::ttg_verify(vk, &pld3, &tk_pld3) {
        return None;
    }

    Some(PasswordUpdateClientOut {
        pld3,
        tk_pld3,
        new_hi,
    })
}

/// Server-side PAS-TA-U PasswordUpdate handling.
///
/// - Verifies `tk_pld3` over message `pld3`.
/// - Extracts the server's own ciphertext chunk from `pld3`.
/// - Decrypts with current `h_i` and updates stored `h_i` to `h'_i`.
pub fn password_update_handle(
    srv: &mut PastauServer,
    vk: &pc::TtgVk,
    pld3: &[u8],
    tk_pld3: &pc::TtgToken,
) -> bool {
    // Must contain at least idU.
    if pld3.len() < UID_LEN {
        return false;
    }

    // Verify token on pld3.
    if !pc::ttg_verify(vk, pld3, tk_pld3) {
        return false;
    }

    // Parse idU (last 32 bytes).
    let mut id_bytes = [0u8; UID_LEN];
    id_bytes.copy_from_slice(&pld3[pld3.len() - UID_LEN..]);
    let c = ClientId(id_bytes);

    // payload_body length must be a multiple of UPDATE_BLOB_LEN.
    let body_len = match pld3.len().checked_sub(UID_LEN) {
        Some(x) => x,
        None => return false, // malformed (too short)
    };
    if body_len % UPDATE_BLOB_LEN != 0 {
        return false;
    }
    let n = body_len / UPDATE_BLOB_LEN;

    // This harness assumes server ids are 1..=n.
    let sid = srv.id as usize;
    if sid == 0 || sid > n {
        return false;
    }

    // Locate record (mutable borrow happens AFTER using srv.id).
    let rec = match srv.get_record_mut(c) {
        Some(r) => r,
        None => return false,
    };
    let off = (sid - 1) * UPDATE_BLOB_LEN;
    let chunk = &pld3[off..off + UPDATE_BLOB_LEN];
    let mut chunk_arr = [0u8; UPDATE_BLOB_LEN];
    chunk_arr.copy_from_slice(chunk);
    let blob = deserialize_update_blob(&chunk_arr);

    let aad: [u8; 0] = [];
    let pt = match pc::xchacha_decrypt_detached::<UPDATE_PT_LEN>(&rec.h_i, &aad, &blob) {
        Ok(v) => v,
        Err(_) => return false,
    };

    let mut old_hi = [0u8; 32];
    old_hi.copy_from_slice(&pt[0..32]);
    let mut new_hi = [0u8; 32];
    new_hi.copy_from_slice(&pt[32..64]);

    // Optional extra check: decrypted old_hi must match stored key.
    if old_hi != rec.h_i {
        return false;
    }

    rec.h_i = new_hi;
    true
}

// ---------------------------
// Benchmark fixtures
// ---------------------------

#[derive(Clone)]
pub struct Fixture {
    pub n: usize,
    pub t: usize,
    pub c: ClientId,
    pub x: [u8; X_LEN],
    pub password: Vec<u8>,
    pub vk: pc::TtgVk,
    pub servers: Vec<PastauServer>,
    /// The canonical first-t set of server ids.
    pub t_set: Vec<u32>,
}

fn seed_for(tag: &[u8], n: usize, t: usize) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(tag);
    h.update(&(n as u64).to_le_bytes());
    h.update(&(t as u64).to_le_bytes());
    let out = h.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(out.as_bytes());
    seed
}

pub fn make_fixture(n: usize, t: usize) -> Fixture {
    assert!(t >= 1 && t <= n);
    let mut rng = ChaCha20Rng::from_seed(seed_for(b"pastau/fixture/v1", n, t));

    let mut c_bytes = [0u8; UID_LEN];
    rng.fill_bytes(&mut c_bytes);
    let c = ClientId(c_bytes);

    let mut x = [0u8; X_LEN];
    rng.fill_bytes(&mut x);

    let password = b"correct horse battery staple".to_vec();

    let gs = global_setup(128, n, t, &mut rng);

    // Create servers with their TTG shares.
    let mut servers: Vec<PastauServer> = gs
        .ttg_shares
        .iter()
        .map(|(sid, sh)| PastauServer::new(*sid, *sh))
        .collect();
    servers.sort_by_key(|s| s.id);

    // Registration and Store.
    let reg = registration(n, t, &password, &mut rng);
    for msg in reg.msgs.iter() {
        let idx = (msg.server_id - 1) as usize;
        servers[idx].store(c, msg);
    }

    let t_set: Vec<u32> = (1..=t as u32).collect();
    Fixture {
        n,
        t,
        c,
        x,
        password,
        vk: gs.vk,
        servers,
        t_set,
    }
}

#[derive(Clone)]
pub struct IterData {
    pub rho: RScalar,
    pub req: [u8; TOP_REQ_LEN],
    pub nonces: Vec<[u8; crypto_core::NONCE_LEN]>,
}

pub fn make_iter_data(fx: &Fixture, rng: &mut impl RngCore) -> IterData {
    let rho = crypto_core::random_scalar(rng);
    let req_point = pc::toprf_encode(&fx.password, rho);
    let req = req_point.compress().to_bytes();

    let mut nonces = vec![[0u8; crypto_core::NONCE_LEN]; fx.t];
    for n in nonces.iter_mut() {
        rng.fill_bytes(n);
    }

    IterData { rho, req, nonces }
}
