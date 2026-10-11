use ats_opsec_suite::cli::{self, Cli};
use ats_opsec_suite::config::Config;
use clap::Parser;

fn main() -> ats_opsec_suite::error::Result<()> {
    let cli = Cli::parse();
    let mut config = Config::load();
    cli::dispatch(cli, &mut config)
}
