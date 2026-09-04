#![no_main]
//! The three records of the §16.2 deletion loop. All of them cross the wire,
//! and `DeleteExecution` is the interesting one: it carries a **nested** list
//! of approvals, so its decoder recurses into another decoder over
//! attacker-chosen bytes — the shape that most often turns into unbounded
//! allocation or a stack problem.
//!
//! The property under test is not only "does not crash". A quorum is counted
//! over what came out of this decoder, so a record that decoded into more
//! distinct-looking approvers than the bytes actually contained would inflate
//! a quorum, and `decide` would never know.
use libfuzzer_sys::fuzz_target;
use nas_core::{encode_fields, Timestamp};
use nas_crypto::{SIGNATURE_LEN, VERIFYING_KEY_LEN};
use nas_delete::{
    decide, Authority, DeleteApproval, DeleteExecution, DeleteRequest, QuorumPolicy, MAX_APPROVALS,
};

/// Bytes laid out as the decoder's own field widths expect.
///
/// Without this the target is nearly useless: a key is 1952 bytes and a
/// signature 3309, so raw fuzzer bytes essentially never satisfy the width
/// checks and every run bails at the first field. The first version of this
/// file managed 14 million runs at coverage 92 — it was measuring how fast
/// garbage is rejected, not exercising the decoders.
fn framed(data: &[u8], widths: &[usize]) -> Vec<u8> {
    let mut parts: Vec<Vec<u8>> = Vec::new();
    let mut off = 0usize;
    for w in widths {
        parts.push((0..*w).map(|i| data[(off + i) % data.len()]).collect());
        off += w;
    }
    let refs: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
    encode_fields(&refs).unwrap()
}

fuzz_target!(|data: &[u8]| {
    if let Ok(r) = DeleteRequest::decode(data) {
        assert_eq!(
            r.encode().unwrap(),
            data,
            "decode accepted a non-canonical request"
        );
        let _ = r.verify();
        // The hash covers the signature, so it is defined for any record that
        // decoded and must not depend on anything outside it.
        assert_eq!(r.request_hash(), r.request_hash());
    }

    if let Ok(a) = DeleteApproval::decode(data) {
        assert_eq!(
            a.encode().unwrap(),
            data,
            "decode accepted a non-canonical approval"
        );
        let _ = a.verify();
    }

    if let Ok(e) = DeleteExecution::decode(data) {
        assert_eq!(
            e.encode().unwrap(),
            data,
            "decode accepted a non-canonical execution"
        );
        // Every approval it carries must bind this execution's request, or
        // `verify` has to reject it — that binding is what stops an approval
        // being replayed against a different request.
        let bound = e.approvals.iter().all(|a| a.request_hash == e.request_hash);
        if !bound {
            assert!(
                e.verify().is_err(),
                "an execution carrying an approval for another request verified"
            );
        }

        // Whatever came off the wire, an empty authority approves nothing.
        // This is the check that fails open if anyone ever "simplifies" it,
        // so it is asserted against arbitrary bytes rather than only against
        // records a test constructed.
        if let Ok(r) = DeleteRequest::decode(data) {
            let d = decide(
                &r,
                &e,
                &[],
                &QuorumPolicy::default(),
                &Authority::new(),
                Timestamp(1_800_000_000),
            );
            assert!(
                !matches!(d, nas_delete::Decision::Execute { .. }),
                "a deletion executed with no authority configured"
            );
        }
    }

    if data.is_empty() {
        return;
    }

    // The same three records, but framed so the width checks are reached and
    // the bodies actually parse.
    let req = framed(data, &[1, 16, 16, VERIFYING_KEY_LEN, 32, SIGNATURE_LEN]);
    if let Ok(r) = DeleteRequest::decode(&req) {
        assert_eq!(r.encode().unwrap(), req);
        assert!(r.verify().is_err(), "an unsigned delete request verified");
    }

    let appr = framed(data, &[32, VERIFYING_KEY_LEN, SIGNATURE_LEN]);
    if let Ok(a) = DeleteApproval::decode(&appr) {
        assert_eq!(a.encode().unwrap(), appr);
        assert!(a.verify().is_err(), "an unsigned approval verified");
    }

    // An execution wrapping that approval: the nested case, which is the one
    // shape here whose decoder recurses over attacker-chosen bytes.
    if let Ok(head) = DeleteApproval::decode(&appr) {
        let inner = head.encode().unwrap();
        let h = head.request_hash;
        let pk = head.approver_pk.clone();
        let sig = head.sig.clone();
        let fields: Vec<&[u8]> = vec![&h, &pk, &sig, &inner];
        if let Ok(bytes) = encode_fields(&fields) {
            if let Ok(e) = DeleteExecution::decode(&bytes) {
                assert_eq!(e.encode().unwrap(), bytes);
                assert!(e.verify().is_err(), "an unsigned execution verified");
                assert!(e.approvals.len() <= MAX_APPROVALS);
            }
        }
    }
});
