use std::process::ExitCode;
use tokio::fs::File;

//use rsa::{BoxedUint, PublicKey};

pub async fn run(path: String) -> ExitCode {
    let file = match File::open(path).await {
        Ok(f) => f,
        Err(e) => {
            tracing::error!("Failed to open MSIXVC file: {e:?}");
            return ExitCode::FAILURE;
        }
    };

    let verifier = match msixvc_new::header::read_header(file).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("Failed to read MSIXVC file: {e:?}");
            return ExitCode::FAILURE;
        }
    };

    let header = verifier.unlock_any(&[]).expect("failed verification");

    println!("header: {header:#?}");

    ExitCode::SUCCESS
}
