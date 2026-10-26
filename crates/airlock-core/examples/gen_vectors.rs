fn main() {
    let v = airlock_core::vectors::generate().expect("vector generation failed");
    println!("{}", serde_json::to_string_pretty(&v).expect("json"));
}
