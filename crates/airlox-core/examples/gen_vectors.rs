fn main() {
    let v = airlox_core::vectors::generate().expect("vector generation failed");
    println!("{}", serde_json::to_string_pretty(&v).expect("json"));
}
