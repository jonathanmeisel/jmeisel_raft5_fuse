//! `raft5fs`: see `raft5fs_fuse::commands`.

use clap::Parser;
use raft5fs_fuse::commands::{Cli, run};

fn main() {
    std::process::exit(run(Cli::parse()));
}
