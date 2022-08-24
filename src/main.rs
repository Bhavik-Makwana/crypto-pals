mod errors;
mod set1;

fn main() {
    println!(
        "msg: {:?}",
        set1::aes_ecb("input/set1_challenge7.txt", "YELLOW SUBMARINE")
    );
}
