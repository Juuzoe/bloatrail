//! `bloatrail config` — show or generate configuration.

use anyhow::{bail, Context as _, Result};
use clap::Args;
use serde::Serialize;

use crate::cli::Context;

/// `bloatrail config --json`: the settings actually in effect.
#[derive(Debug, Serialize)]
struct SettingsDocument {
    schema_version: u32,
    source: Option<String>,
    min_size: u64,
    threads: Option<usize>,
    depth: usize,
    top: usize,
    follow_symlinks: bool,
    include_hidden: bool,
    same_filesystem: bool,
    ascii: bool,
    stale_days: u32,
    exclude: Vec<String>,
}

/// Arguments for `bloatrail config`.
#[derive(Debug, Args)]
pub struct ConfigArgs {
    /// Print a commented starter configuration.
    #[arg(long)]
    pub example: bool,

    /// Print the path Bloatrail reads configuration from.
    #[arg(long)]
    pub path: bool,

    /// Write the starter configuration to that path.
    #[arg(long, conflicts_with_all = ["example", "path"])]
    pub init: bool,
}

/// Run the command.
///
/// # Errors
///
/// Fails if the configuration directory cannot be determined or written.
pub fn run(context: &Context, args: &ConfigArgs) -> Result<()> {
    if args.example {
        return context.emit(&crate::config::example());
    }

    if args.path {
        let path = crate::config::default_config_path()
            .context("could not determine a configuration directory for this platform")?;
        return context.emit(&format!("{}\n", path.display()));
    }

    if args.init {
        let path = crate::config::default_config_path()
            .context("could not determine a configuration directory for this platform")?;
        if path.exists() {
            bail!(
                "`{}` already exists; remove it first or edit it in place",
                path.display()
            );
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("could not create `{}`", parent.display()))?;
        }
        std::fs::write(&path, crate::config::example())
            .with_context(|| format!("could not write `{}`", path.display()))?;
        return context.emit(&format!("Wrote {}\n", path.display()));
    }

    // No flags: describe the settings actually in effect.
    let settings = &context.settings;

    if context.json {
        let document = SettingsDocument {
            schema_version: crate::output::json::SCHEMA_VERSION,
            source: settings.source.as_ref().map(|p| p.display().to_string()),
            min_size: settings.min_size.as_u64(),
            threads: settings.threads,
            depth: settings.depth,
            top: settings.top,
            follow_symlinks: settings.follow_symlinks,
            include_hidden: settings.include_hidden,
            same_filesystem: settings.same_filesystem,
            ascii: settings.ascii,
            stale_days: settings.stale_days,
            exclude: settings.exclude.clone(),
        };
        return context.emit(&crate::output::json::to_string(&document)?);
    }

    let mut out = String::new();
    out.push_str(&context.theme.heading("Effective settings\n\n"));

    let source = settings
        .source
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "built-in defaults (no config file found)".to_string());
    out.push_str(&format!("  source            {source}\n"));
    out.push_str(&format!("  min_size          {}\n", settings.min_size));
    out.push_str(&format!(
        "  threads           {}\n",
        settings
            .threads
            .map_or_else(|| "auto".to_string(), |n| n.to_string())
    ));
    out.push_str(&format!("  depth             {}\n", settings.depth));
    out.push_str(&format!("  top               {}\n", settings.top));
    out.push_str(&format!(
        "  follow_symlinks   {}\n",
        settings.follow_symlinks
    ));
    out.push_str(&format!(
        "  include_hidden    {}\n",
        settings.include_hidden
    ));
    out.push_str(&format!(
        "  same_filesystem   {}\n",
        settings.same_filesystem
    ));
    out.push_str(&format!("  ascii             {}\n", settings.ascii));
    out.push_str(&format!("  stale_days        {}\n", settings.stale_days));
    out.push_str(&format!(
        "  exclude           {}\n",
        if settings.exclude.is_empty() {
            "(none)".to_string()
        } else {
            settings.exclude.join(", ")
        }
    ));
    out.push('\n');
    out.push_str(
        &context
            .theme
            .dim("`bloatrail config --example` prints a starter file; `--init` writes one.\n"),
    );

    context.emit(&out)
}
