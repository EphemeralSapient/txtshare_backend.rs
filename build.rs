// build.rs
fn main() -> Result<(), Box<dyn std::error::Error>> {

    tonic_build::configure()
        .protoc_arg("--experimental_allow_proto3_optional")
        .build_server(true) // Generate server code
        .build_client(false) // Generate client code
        .compile(
            &["proto/ping.proto","proto/auth.proto","proto/txt.proto","proto/account.proto"], 
            &["proto"], // Path to the directory containing your .proto file
        )?;
    Ok(())
}
