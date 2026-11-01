use pri_driver::{Model, PendingRecovery};
use shielded_pool_circuit::field::Fr;
fn model() -> Model {
    let mut m = Model::new();
    m.recovery_charge = Some(100);
    m.reserved_recovery = 1;
    m.pending_recoveries.push(PendingRecovery {
        minted_amount: 0,
        minted_leaf: None,
        body_hash: "original".into(),
        recipient: "recipient".into(),
        owner: Fr::from(1u64),
        payload: vec![7; 1493],
        payout_value: 1000,
        consumed: false,
    });
    m
}
#[test]
fn recovers_returned_value_less_charge_once() {
    let mut m = model();
    m.apply_recovery("original", "recipient", 900, 10).unwrap();
    assert_eq!(m.liability, 800);
    assert_eq!(m.reserved_recovery, 0);
    assert_eq!(m.leaves.len(), 1);
    let before = m.expected();
    assert!(m.apply_recovery("original", "recipient", 900, 11).is_err());
    assert_eq!(before, m.expected());
}
#[test]
fn dust_consumes_reservation_without_mint() {
    for returned in [0, 99, 100] {
        let mut m = model();
        m.apply_recovery("original", "recipient", returned, 10)
            .unwrap();
        assert_eq!(m.reserved_recovery, 0);
        assert_eq!(m.liability, 0);
        assert!(m.leaves.is_empty());
    }
}
#[test]
fn refuses_unmatched_sender_excess_and_missing_quote() {
    for (hash, sender, value, quote) in [
        ("other", "recipient", 900, Some(100)),
        ("original", "other", 900, Some(100)),
        ("original", "recipient", 1001, Some(100)),
        ("original", "recipient", 900, None),
        ("original", "recipient", 900, Some(0)),
    ] {
        let mut m = model();
        m.recovery_charge = quote;
        let before = m.expected();
        assert!(m.apply_recovery(hash, sender, value, 10).is_err());
        assert_eq!(before, m.expected());
        assert!(!m.pending_recoveries[0].consumed);
    }
}
