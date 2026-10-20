fn process_order(order_id: u64, customer_id: u64, amount_cents: u64, currency: &str) -> bool {
    if amount_cents == 0 { return false; }
    let tax = amount_cents * 20 / 100;
    let total = amount_cents + tax;
    log_transaction(order_id, customer_id, total, "USD");
    true
}
