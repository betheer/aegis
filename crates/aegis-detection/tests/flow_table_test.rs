use aegis_detection::flow_table::FlowTable;
use aegis_detection::FlowKey;

fn key(src_port: u16, dst_port: u16) -> FlowKey {
    FlowKey {
        src_ip: "1.2.3.4".parse().unwrap(),
        dst_ip: "5.6.7.8".parse().unwrap(),
        src_port,
        dst_port,
        proto: 6,
    }
}

#[test]
fn get_or_create_same_key_returns_same_arc() {
    let table = FlowTable::new(1000);
    let k = key(1234, 80);
    let a = table.get_or_create(k.clone());
    let b = table.get_or_create(k.clone());
    assert!(std::sync::Arc::ptr_eq(&a, &b), "same key must return same Arc");
}

#[test]
fn different_keys_return_different_arcs() {
    let table = FlowTable::new(1000);
    let a = table.get_or_create(key(1, 80));
    let b = table.get_or_create(key(2, 80));
    assert!(!std::sync::Arc::ptr_eq(&a, &b));
}

#[test]
fn entry_count_increments() {
    let table = FlowTable::new(1000);
    table.get_or_create(key(1, 80));
    table.get_or_create(key(2, 80));
    // moka entry_count is updated by a background thread — run_pending_tasks()
    // flushes the write queue synchronously so the count is accurate immediately.
    table.run_pending_tasks();
    assert!(table.entry_count() >= 1);
}

#[test]
fn flow_state_mutations_visible_across_handles() {
    let table = FlowTable::new(1000);
    let k = key(9000, 443);
    let arc1 = table.get_or_create(k.clone());
    let arc2 = table.get_or_create(k.clone());

    arc1.lock().unwrap().syn_count = 42;
    assert_eq!(arc2.lock().unwrap().syn_count, 42);
}
