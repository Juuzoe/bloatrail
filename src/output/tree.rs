//! The terminal tree view.
//!
//! Layout is column-based rather than free-form so that sizes line up no matter
//! how deeply nested an entry is — the thing that makes a tree readable is being
//! able to compare the right-hand column at a glance.

use std::fmt::Write as _;

use crate::analysis::domain::CleanupSafety;
use crate::output::{pad_right, truncate, Theme};
use crate::scanner::tree::{DirTree, NodeId};
use crate::units::ByteSize;

/// Tree rendering settings.
#[derive(Debug, Clone, Copy)]
pub struct TreeOptions {
    /// How many levels below the root to show.
    pub max_depth: usize,
    /// Hide entries below this size.
    pub min_size: u64,
    /// Maximum children shown per directory.
    pub max_children: usize,
    /// Draw proportional bars.
    pub bars: bool,
}

impl Default for TreeOptions {
    fn default() -> Self {
        TreeOptions {
            max_depth: 2,
            min_size: 0,
            max_children: 12,
            bars: true,
        }
    }
}

/// Render a subtree rooted at `root`.
#[must_use]
pub fn render(
    tree: &DirTree,
    root: NodeId,
    theme: &Theme,
    options: &TreeOptions,
    title: &str,
) -> String {
    let mut out = String::with_capacity(4_096);
    let node = tree.node(root);

    let name_width = name_column_width(theme.width);
    let total = ByteSize(node.total.bytes);

    let _ = writeln!(
        out,
        "{}{}",
        pad_right(&truncate(title, name_width), name_width + 2),
        crate::output::pad_left(&total.to_string(), 10),
    );
    let _ = writeln!(out);

    render_children(tree, root, theme, options, 0, "", name_width, &mut out);
    out
}

#[allow(clippy::too_many_arguments)]
fn render_children(
    tree: &DirTree,
    parent: NodeId,
    theme: &Theme,
    options: &TreeOptions,
    depth: usize,
    prefix: &str,
    name_width: usize,
    out: &mut String,
) {
    if depth >= options.max_depth {
        return;
    }

    let node = tree.node(parent);
    let glyphs = theme.glyphs();

    let visible: Vec<NodeId> = node
        .children
        .iter()
        .copied()
        .filter(|id| tree.node(*id).total.bytes >= options.min_size)
        .take(options.max_children)
        .collect();

    let hidden = node.children.len().saturating_sub(visible.len());
    // Children are pre-sorted largest-first, so the first one sets the scale.
    let largest = visible
        .first()
        .map_or(0, |id| tree.node(*id).total.bytes)
        .max(1);

    for (index, id) in visible.iter().enumerate() {
        let child = tree.node(*id);
        let is_last = index + 1 == visible.len() && hidden == 0;
        let connector = if is_last { glyphs.last } else { glyphs.branch };

        let mut label = format!("{prefix}{connector}{}", child.name);
        if !child.is_leaf() || child.truncated {
            label.push(std::path::MAIN_SEPARATOR);
        }

        let size = ByteSize(child.total.bytes).to_string();
        let mut line = String::with_capacity(160);
        let _ = write!(
            line,
            "{}{}",
            pad_right(&truncate(&label, name_width), name_width + 2),
            crate::output::pad_left(&size, 10),
        );

        if let Some(detection) = &child.detection {
            let _ = write!(
                line,
                "   {}",
                theme.by_safety(detection.cleanup, &detection.reason)
            );
            if detection.cleanup == CleanupSafety::NeverDelete {
                let _ = write!(line, " {}", theme.dim("(kept)"));
            }
        } else if options.bars {
            let fraction = child.total.bytes as f64 / largest as f64;
            let width = bar_width(theme.width, name_width);
            if width > 0 {
                let _ = write!(line, "   {}", theme.dim(&theme.bar(fraction, width)));
            }
        }

        let _ = writeln!(out, "{}", line.trim_end());

        let child_prefix = format!(
            "{prefix}{}",
            if is_last {
                glyphs.blank
            } else {
                glyphs.vertical
            }
        );
        render_children(
            tree,
            *id,
            theme,
            options,
            depth + 1,
            &child_prefix,
            name_width,
            out,
        );
    }

    if hidden > 0 {
        let connector = glyphs.last;
        let _ = writeln!(
            out,
            "{}",
            theme.dim(&format!("{prefix}{connector}… {hidden} more",))
        );
    }
}

/// Width of the name column, chosen so the size column stays visible on narrow
/// terminals but does not float away on wide ones.
fn name_column_width(terminal_width: usize) -> usize {
    terminal_width.saturating_sub(38).clamp(24, 52)
}

fn bar_width(terminal_width: usize, name_width: usize) -> usize {
    terminal_width.saturating_sub(name_width + 18).min(16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::domain::{Category, Confidence, Detection};
    use crate::output::ColorMode;
    use crate::scanner::tree::{DirNode, Totals};
    use std::path::PathBuf;

    fn node(
        name: &str,
        parent: Option<NodeId>,
        children: Vec<NodeId>,
        bytes: u64,
        detection: Option<Detection>,
    ) -> DirNode {
        DirNode {
            name: name.into(),
            parent,
            children,
            depth: parent.map_or(0, |_| 1),
            own: Totals::default(),
            total: Totals {
                bytes,
                files: 1,
                dirs: 1,
                stale_bytes: 0,
            },
            detection,
            truncated: false,
        }
    }

    fn sample_tree() -> DirTree {
        DirTree::new(
            PathBuf::from("/dev"),
            vec![
                node("", None, vec![1, 3], 10_000, None),
                node("dashboard", Some(0), vec![2], 7_000, None),
                node(
                    "node_modules",
                    Some(1),
                    vec![],
                    6_000,
                    Some(Detection::new(
                        Category::Dependency,
                        Confidence::High,
                        CleanupSafety::Safe,
                        "npm dependencies",
                    )),
                ),
                node("experiments", Some(0), vec![], 3_000, None),
            ],
        )
    }

    #[test]
    fn renders_children_largest_first_with_sizes() {
        let tree = sample_tree();
        let theme = Theme::new(ColorMode::Never, true);
        let output = render(&tree, 0, &theme, &TreeOptions::default(), "/dev");

        let lines: Vec<&str> = output.lines().filter(|l| !l.trim().is_empty()).collect();
        assert!(lines[0].contains("/dev"));
        assert!(lines[1].contains("dashboard"));
        assert!(lines[3].contains("experiments"));
    }

    #[test]
    fn detections_are_annotated_instead_of_bars() {
        let tree = sample_tree();
        let theme = Theme::new(ColorMode::Never, true);
        let output = render(&tree, 0, &theme, &TreeOptions::default(), "/dev");
        assert!(output.contains("npm dependencies"));
    }

    #[test]
    fn depth_limit_is_respected() {
        let tree = sample_tree();
        let theme = Theme::new(ColorMode::Never, true);
        let options = TreeOptions {
            max_depth: 1,
            ..TreeOptions::default()
        };
        let output = render(&tree, 0, &theme, &options, "/dev");
        assert!(output.contains("dashboard"));
        assert!(!output.contains("node_modules"));
    }

    #[test]
    fn min_size_filters_small_entries() {
        let tree = sample_tree();
        let theme = Theme::new(ColorMode::Never, true);
        let options = TreeOptions {
            min_size: 5_000,
            ..TreeOptions::default()
        };
        let output = render(&tree, 0, &theme, &options, "/dev");
        assert!(output.contains("dashboard"));
        assert!(!output.contains("experiments"));
    }

    #[test]
    fn overflowing_children_are_summarised() {
        let mut nodes = vec![node("", None, (1..=5).collect(), 5_000, None)];
        for i in 1..=5 {
            nodes.push(node(&format!("d{i}"), Some(0), vec![], 1_000, None));
        }
        let tree = DirTree::new(PathBuf::from("/x"), nodes);
        let theme = Theme::new(ColorMode::Never, true);
        let options = TreeOptions {
            max_children: 2,
            ..TreeOptions::default()
        };
        let output = render(&tree, 0, &theme, &options, "/x");
        assert!(output.contains("3 more"));
    }

    #[test]
    fn ascii_mode_produces_only_ascii_connectors() {
        let tree = sample_tree();
        let theme = Theme::new(ColorMode::Never, true);
        let output = render(&tree, 0, &theme, &TreeOptions::default(), "/dev");
        assert!(output.contains("|-- ") || output.contains("`-- "));
        assert!(!output.contains('├'));
    }
}
