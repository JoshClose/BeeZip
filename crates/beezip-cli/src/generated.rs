//! Subcommands generated from the registry: one for every command with a `CliSpec`, its
//! arguments taken from the input type's `clap::Args` derive. Commands with a group nest
//! under it: `beezip settings get` (docs/M4.md §8).

use beezip_commands::{CLI_GROUPS, Registry};

pub fn add_subcommands(mut root: clap::Command, registry: &Registry) -> clap::Command {
    let mut groups: Vec<clap::Command> = Vec::new();
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
        let Some(group) = spec.group else {
            root = root.subcommand(sub);
            continue;
        };
        match groups.iter().position(|g| g.get_name() == group) {
            Some(i) => {
                let g = groups.remove(i);
                groups.insert(i, g.subcommand(sub));
            }
            None => {
                let about = CLI_GROUPS
                    .iter()
                    .find(|(g, _)| *g == group)
                    .map_or("", |(_, about)| *about);
                groups.push(
                    clap::Command::new(group)
                        .about(about)
                        .subcommand_required(true)
                        .arg_required_else_help(true)
                        .subcommand(sub),
                );
            }
        }
    }
    root.subcommands(groups)
}

/// Whether `name` is a group's subcommand rather than a command's.
pub fn is_group(name: &str) -> bool {
    CLI_GROUPS.iter().any(|(g, _)| *g == name)
}
