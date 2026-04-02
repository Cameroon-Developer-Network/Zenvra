//! Supported programming languages.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Language {
    Python,
    JavaScript,
    TypeScript,
    Rust,
    Go,
    Java,
    CSharp,
    Cpp,
    C,
    Ruby,
    Php,
    Swift,
    Kotlin,
    Unknown,
}

impl Language {
    /// Detect language from a file extension.
    pub fn from_extension(ext: &str) -> Self {
        match ext.to_lowercase().as_str() {
            "py" => Self::Python,
            "js" | "mjs" | "cjs" => Self::JavaScript,
            "ts" | "tsx" => Self::TypeScript,
            "rs" => Self::Rust,
            "go" => Self::Go,
            "java" => Self::Java,
            "cs" => Self::CSharp,
            "cpp" | "cc" | "cxx" => Self::Cpp,
            "c" | "h" => Self::C,
            "rb" => Self::Ruby,
            "php" => Self::Php,
            "swift" => Self::Swift,
            "kt" | "kts" => Self::Kotlin,
            _ => Self::Unknown,
        }
    }
}
