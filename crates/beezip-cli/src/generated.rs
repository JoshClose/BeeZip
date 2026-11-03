//! Subcommands generated from the registry: one for every command with a `CliSpec`, its
//! arguments taken from the input type's `clap::Args` derive.

use beezip_commands::Registry;

pub fn add_subcommands(mut root: clap::Command, registry: &Registry) -> clap::Command {
    for entry in registry.entries().iter().filter(|e| e.surfaces.cli) {
        let Some(spec) = entry.cli else { continue };
        let summary = entry
            .description
            .split("\n\n")
            .next()
            .unwrap_or_default()
            .to_owned();
        let sub = entry
            .augment_args(clap::Command::new(spec.name))
            .visible_aliases(spec.aliases.iter().copied())
            .about(summary)
            .long_about(entry.description.clone());
        root = root.subcommand(sub);
    }
    root
}
