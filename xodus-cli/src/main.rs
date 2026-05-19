use clap::{Parser, Subcommand};
mod commands;
mod webview;

use xodus::xal::TokenStore;
use xodus::xal::client_params::CLIENT_WINDOWS;
use xodus::{hardware, licensing};

#[derive(Subcommand)]
enum SubCommand {
    Download {
        product: String,
        #[arg(short, long)]
        market: Option<String>,
        #[arg(long, default_value_t = false)]
        dry_run: bool,
    },
    License {
        content_id: String,
        #[arg(short, long)]
        market: Option<String>,
    },
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct CliArgs {
    #[command(subcommand)]
    command: SubCommand,
}

#[tokio::main]
async fn main() {
    env_logger::init_from_env("XODUS_LOG");
    let client = reqwest::ClientBuilder::new()
        .user_agent(CLIENT_WINDOWS().user_agent)
        .connection_verbose(true)
        .build()
        .unwrap();

    let args = CliArgs::parse();

    match args.command {
        SubCommand::Download {
            product: _,
            market: _,
            dry_run: _,
        } => (), //commands::download::run(&client, &ts, product, market, dry_run).await,
        SubCommand::License {
            content_id: _,
            market: _,
        } => {
            commands::license::run(&client).await;
        }
    }
}
