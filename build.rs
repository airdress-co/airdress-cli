fn main() {
    println!(
        "cargo:rustc-env=TARGET={}",
        std::env::var("TARGET").unwrap()
    );
    if let Ok(v) = std::env::var("AIRDRESS_BUILD_VERSION") {
        println!("cargo:rustc-env=AIRDRESS_BUILD_VERSION={v}");
    }
}
