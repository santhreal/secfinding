//! Location of a security finding in a file or project.

use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Specific location where a finding was discovered.
///
/// Used for code scanners (SAST), malware detection, and secrets detection.
///
/// # Examples
///
/// ```
/// use secfinding::Location;
///
/// let location = Location::new("src/main.rs")?.line(42)?.column(7)?;
/// assert_eq!(location.to_string(), "src/main.rs:42:7");
/// # Ok::<(), secfinding::LocationError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Location {
    /// File path relative to the scan root.
    #[serde(deserialize_with = "deserialize_location_file")]
    pub file: Arc<str>,
    /// Line number (1-based).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_positive_u32"
    )]
    pub line: Option<u32>,
    /// Column number (1-based).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_positive_u32"
    )]
    pub column: Option<u32>,
}

/// Errors that can occur when creating a [`Location`].
///
/// # Examples
///
/// ```
/// use secfinding::{Location, LocationError};
///
/// let err = Location::new("../etc/passwd").unwrap_err();
/// assert_eq!(err, LocationError::PathTraversal);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LocationError {
    /// The file path is empty.
    EmptyFilePath,
    /// The file path contains null bytes.
    NullByteInPath,
    /// The file path is excessively long (>16KB).
    PathTooLong,
    /// Line number is 0 (line numbers are 1-based).
    ZeroLineNumber,
    /// Column number is 0 (column numbers are 1-based).
    ZeroColumnNumber,
    /// The path contains potential directory traversal sequences.
    PathTraversal,
}

impl std::fmt::Display for LocationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyFilePath => write!(f, "file path cannot be empty. Fix: provide a valid file path."),
            Self::NullByteInPath => write!(f, "file path cannot contain null bytes. Fix: sanitize the file path."),
            Self::PathTooLong => write!(f, "file path exceeds maximum length (16KB). Fix: use a shorter path."),
            Self::ZeroLineNumber => write!(f, "line number cannot be 0 (line numbers are 1-based). Fix: use 1 or greater."),
            Self::ZeroColumnNumber => write!(f, "column number cannot be 0 (column numbers are 1-based). Fix: use 1 or greater."),
            Self::PathTraversal => write!(f, "file path contains directory traversal sequences (..). Fix: use a normalized path."),
        }
    }
}

impl std::error::Error for LocationError {}

impl Location {
    /// Maximum allowed length for file path (16KB).
    ///
    /// This is a fixed, Location-intrinsic safety bound rather than a
    /// configurable `FindingConfig` field. `Location` is constructed and
    /// deserialized independently of any `Finding`, so there is no `FindingConfig`
    /// in scope at those sites; coupling the two types would break the
    /// standalone `Location` contract for a rarely-tuned value.
    pub const MAX_PATH_LEN: usize = 16_384;

    /// Create a new location with just a file path.
    ///
    /// # Errors
    ///
    /// Returns `LocationError` if the file path is invalid:
    /// - Empty path
    /// - Contains null bytes
    /// - Exceeds 16KB
    /// - Contains path traversal sequences (`..`)
    ///
    /// # Examples
    /// ```
    /// use secfinding::Location;
    ///
    /// let loc = Location::new("src/main.rs").unwrap();
    /// ```
    pub fn new(file: impl Into<String>) -> Result<Self, LocationError> {
        let file = file.into();
        validate_location_file(&file)?;
        Ok(Self {
            file: Arc::from(file),
            line: None,
            column: None,
        })
    }

    /// Set the line number.
    ///
    /// # Errors
    ///
    /// Returns `LocationError::ZeroLineNumber` if line is 0.
    pub fn line(mut self, line: u32) -> Result<Self, LocationError> {
        if line == 0 {
            return Err(LocationError::ZeroLineNumber);
        }
        self.line = Some(line);
        Ok(self)
    }

    /// Set the column number.
    ///
    /// # Errors
    ///
    /// Returns `LocationError::ZeroColumnNumber` if column is 0.
    pub fn column(mut self, column: u32) -> Result<Self, LocationError> {
        if column == 0 {
            return Err(LocationError::ZeroColumnNumber);
        }
        self.column = Some(column);
        Ok(self)
    }
}

impl std::fmt::Display for Location {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.file)?;
        if let Some(line) = self.line {
            write!(f, ":{line}")?;
            if let Some(col) = self.column {
                write!(f, ":{col}")?;
            }
        }
        Ok(())
    }
}

fn validate_location_file(file: &str) -> Result<(), LocationError> {
    if file.is_empty() {
        return Err(LocationError::EmptyFilePath);
    }
    if file.len() > Location::MAX_PATH_LEN {
        return Err(LocationError::PathTooLong);
    }
    if file.contains('\0') {
        return Err(LocationError::NullByteInPath);
    }

    // Normalize Windows-style backslash separators to '/' before parsing.
    // On Unix, `Path` treats '\' as an ordinary character, so a payload like
    // `..\..\etc\passwd` would collapse into a single `Normal` component and the
    // ParentDir check below would never fire, letting traversal through. We hold
    // the normalized string in a binding so `path` borrows a live value.
    let normalized = if file.contains('\\') {
        file.replace('\\', "/")
    } else {
        file.to_owned()
    };

    // Use the Path components API to detect ParentDir elements explicitly.
    // This avoids false positives caused by substrings like "ver..sion".
    let path = std::path::Path::new(&normalized);

    // Disallow absolute paths; findings should be expressed relative to the scan root.
    if path.is_absolute() {
        return Err(LocationError::PathTraversal);
    }

    for component in path.components() {
        use std::path::Component;
        if matches!(component, Component::ParentDir) {
            return Err(LocationError::PathTraversal);
        }
        // Also reject Windows prefixes (C:\) or other platform-specific absolute markers.
        if matches!(component, Component::Prefix(_)) {
            return Err(LocationError::PathTraversal);
        }
    }

    Ok(())
}

fn deserialize_location_file<'de, D>(deserializer: D) -> Result<Arc<str>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let file = String::deserialize(deserializer)?;
    validate_location_file(&file).map_err(serde::de::Error::custom)?;
    Ok(Arc::from(file))
}

fn deserialize_optional_positive_u32<'de, D>(deserializer: D) -> Result<Option<u32>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<u32>::deserialize(deserializer)?;
    match value {
        Some(0) => Err(serde::de::Error::custom(
            "line and column values must be 1 or greater. Fix: use a positive source coordinate.",
        )),
        _ => Ok(value),
    }
}
