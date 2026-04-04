//! Supported programming languages.

use serde::{Deserialize, Serialize};
use std::str::FromStr;

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

impl FromStr for Language {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "python" | "py" => Self::Python,
            "javascript" | "js" => Self::JavaScript,
            "typescript" | "ts" => Self::TypeScript,
            "rust" | "rs" => Self::Rust,
            "go" | "golang" => Self::Go,
            "java" => Self::Java,
            "csharp" | "cs" => Self::CSharp,
            "cpp" | "c++" => Self::Cpp,
            "c" => Self::C,
            "ruby" | "rb" => Self::Ruby,
            "php" => Self::Php,
            "swift" => Self::Swift,
            "kotlin" | "kt" => Self::Kotlin,
            _ => Self::Unknown,
        })
    }
}
