//! Bare minimum scaffold necessary to have identical experience to orb-software

use orb_x_optee::reexports::{
    clap::{self, Parser, Subcommand},
    color_eyre::{self, Result},
};

fn main() -> Result<()> {
    color_eyre::install()?;
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    let Args {
        subcmd: Cmd::Optee(optee_args),
    } = args;

    optee_args.run()
}

#[derive(Debug, Parser)]
struct Args {
    #[command(subcommand)]
    subcmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    #[command(subcommand)]
    Optee(orb_x_optee::Subcommands),
}
