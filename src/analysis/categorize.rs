//! File-level categorisation.
//!
//! This is the fallback used for files that are not inside a classified
//! directory. It is intentionally the *least* clever part of the analysis: an
//! extension tells you a file's format, never its purpose. Anything important
//! (dependencies, build output, caches) is decided by the directory detectors
//! long before this table is consulted.

use crate::analysis::context::extension_of;
use crate::analysis::domain::Category;

/// Classify a file from its name.
///
/// The comparison is case-insensitive without allocating: extensions are short,
/// so a byte-wise ASCII comparison beats lowercasing into a `String`.
#[must_use]
pub fn categorize_file(name: &str) -> Category {
    let Some(ext) = extension_of(name) else {
        return categorize_extensionless(name);
    };

    // Longest real-world extension we care about is `sqlite3`/`gradle`.
    if ext.len() > 12 {
        return Category::Unknown;
    }
    let mut buffer = [0u8; 12];
    let bytes = ext.as_bytes();
    for (slot, byte) in buffer.iter_mut().zip(bytes) {
        *slot = byte.to_ascii_lowercase();
    }
    let lower = match std::str::from_utf8(&buffer[..bytes.len()]) {
        Ok(s) => s,
        Err(_) => return Category::Unknown,
    };

    match lower {
        // Moving pictures.
        "mp4" | "mkv" | "mov" | "avi" | "webm" | "wmv" | "flv" | "m4v" | "mpg" | "mpeg"
        | "m2ts" | "mts" | "3gp" | "ogv" | "vob" | "rmvb" => Category::Video,

        // Still pictures. `svg` is arguably source, but it is far more often an
        // asset, and it is small either way.
        "jpg" | "jpeg" | "png" | "gif" | "bmp" | "tiff" | "tif" | "webp" | "heic" | "heif"
        | "svg" | "ico" | "raw" | "cr2" | "cr3" | "nef" | "arw" | "dng" | "orf" | "psd" | "xcf"
        | "avif" => Category::Image,

        "mp3" | "wav" | "flac" | "aac" | "ogg" | "oga" | "m4a" | "wma" | "aiff" | "opus"
        | "mid" | "midi" | "ape" => Category::Audio,

        "zip" | "tar" | "gz" | "tgz" | "bz2" | "tbz" | "xz" | "7z" | "rar" | "zst" | "lz4"
        | "lzma" | "cab" | "iso" | "dmg" | "jar" | "war" | "ear" | "crate" | "whl" | "nupkg"
        | "gem" | "xip" => Category::Archive,

        "vdi" | "vmdk" | "vhd" | "vhdx" | "qcow2" | "qcow" | "ova" | "ovf" | "hds" | "vmem"
        | "vswp" | "avhdx" | "box" => Category::VirtualMachine,

        "pdf" | "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" | "odt" | "ods" | "odp"
        | "rtf" | "epub" | "mobi" | "azw3" | "pages" | "numbers" | "key" | "txt" | "md" | "csv"
        | "tsv" | "db" | "sqlite" | "sqlite3" | "mdb" | "accdb" | "bak" => Category::Document,

        "exe" | "msi" | "appimage" | "deb" | "rpm" | "pkg" | "apk" | "dll" | "so" | "dylib"
        | "wasm" | "com" | "bat" | "cmd" => Category::Application,

        // Intermediate compiler output. These are only ever produced by a build
        // and are never authored, so calling them "Applications" would put
        // regenerable bytes in a category that implies installed software.
        "pdb" | "obj" | "lib" | "a" | "o" | "d" | "gcno" | "gcda" | "ilk" | "exp" | "idb"
        | "ncb" | "sbr" | "bc" | "rlib" | "rmeta" | "class" => Category::BuildArtifact,

        "log" | "log1" | "log2" => Category::Log,

        "tmp" | "temp" | "swp" | "swo" | "part" | "crdownload" | "partial" => Category::Temporary,

        "rs" | "ts" | "tsx" | "js" | "jsx" | "mjs" | "cjs" | "py" | "pyi" | "java" | "kt"
        | "kts" | "go" | "c" | "h" | "cc" | "cpp" | "cxx" | "hpp" | "hxx" | "cs" | "fs" | "vb"
        | "rb" | "php" | "swift" | "sh" | "bash" | "zsh" | "fish" | "ps1" | "psm1" | "sql"
        | "html" | "htm" | "css" | "scss" | "sass" | "less" | "json" | "jsonc" | "yaml" | "yml"
        | "toml" | "ini" | "cfg" | "conf" | "xml" | "lock" | "ipynb" | "vue" | "svelte"
        | "astro" | "dart" | "ex" | "exs" | "erl" | "hs" | "lua" | "r" | "pl" | "pm" | "scala"
        | "clj" | "cljs" | "zig" | "nim" | "m" | "mm" | "gradle" | "cmake" | "make" | "mk"
        | "tf" | "tfvars" | "proto" | "graphql" | "gql" | "patch" | "diff" | "el" | "vim"
        | "asm" | "s" => Category::SourceCode,

        _ => Category::Unknown,
    }
}

/// Files with no extension still have a few recognisable names.
fn categorize_extensionless(name: &str) -> Category {
    match name {
        "Makefile" | "makefile" | "GNUmakefile" | "Dockerfile" | "Rakefile" | "Gemfile"
        | "Procfile" | "Justfile" | "justfile" | "CMakeLists" | "LICENSE" | "README"
        | "CHANGELOG" | "AUTHORS" | "NOTICE" | "COPYING" => Category::SourceCode,
        _ => Category::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn video_files_are_recognised_case_insensitively() {
        assert_eq!(categorize_file("holiday.MP4"), Category::Video);
        assert_eq!(categorize_file("screen-recording.mov"), Category::Video);
    }

    #[test]
    fn typescript_is_source_not_video() {
        // `.ts` is a MPEG transport stream *and* a TypeScript file. On a
        // developer machine it is overwhelmingly the latter, and misfiling it as
        // video would be far more confusing than the reverse.
        assert_eq!(categorize_file("index.ts"), Category::SourceCode);
        assert_eq!(categorize_file("component.tsx"), Category::SourceCode);
    }

    #[test]
    fn virtual_machine_images_have_their_own_category() {
        assert_eq!(categorize_file("ubuntu-vm.qcow2"), Category::VirtualMachine);
        assert_eq!(categorize_file("win11.vhdx"), Category::VirtualMachine);
    }

    #[test]
    fn multi_part_extensions_use_the_last_component() {
        assert_eq!(categorize_file("backup.tar.gz"), Category::Archive);
        assert_eq!(categorize_file("app.min.js"), Category::SourceCode);
    }

    #[test]
    fn dotfiles_are_not_treated_as_extensions() {
        assert_eq!(categorize_file(".gitignore"), Category::Unknown);
        assert_eq!(categorize_file(".env"), Category::Unknown);
    }

    #[test]
    fn well_known_extensionless_files_are_source() {
        assert_eq!(categorize_file("Dockerfile"), Category::SourceCode);
        assert_eq!(categorize_file("Makefile"), Category::SourceCode);
        assert_eq!(categorize_file("LICENSE"), Category::SourceCode);
    }

    #[test]
    fn compiler_intermediates_are_build_artifacts_not_applications() {
        for name in ["main.o", "libfoo.a", "app.pdb", "Widget.class", "core.rlib"] {
            assert_eq!(
                categorize_file(name),
                Category::BuildArtifact,
                "{name} should be build output"
            );
        }
        assert_eq!(categorize_file("setup.exe"), Category::Application);
        assert_eq!(categorize_file("libssl.so"), Category::Application);
    }

    #[test]
    fn unknown_extensions_fall_through() {
        assert_eq!(categorize_file("data.qqqq"), Category::Unknown);
        assert_eq!(
            categorize_file("file.averyveryverylongext"),
            Category::Unknown
        );
    }
}
