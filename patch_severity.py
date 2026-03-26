import re

with open('src/severity.rs', 'r') as f:
    text = f.read()

# Fix from_str_loose
text = re.sub(
    r'match s\.to_ascii_lowercase\(\)\.as_str\(\) \{.*?\n        \}',
    r'''if s.eq_ignore_ascii_case("info") || s.eq_ignore_ascii_case("informational") { Some(Self::Info) }
        else if s.eq_ignore_ascii_case("low") { Some(Self::Low) }
        else if s.eq_ignore_ascii_case("medium") || s.eq_ignore_ascii_case("med") { Some(Self::Medium) }
        else if s.eq_ignore_ascii_case("high") { Some(Self::High) }
        else if s.eq_ignore_ascii_case("critical") || s.eq_ignore_ascii_case("crit") { Some(Self::Critical) }
        else { None }''',
    text,
    flags=re.DOTALL
)

# Remove colored_label
text = re.sub(
    r'    /// ANSI-colored label for terminal output\.\n    #\[must_use\]\n    pub fn colored_label\(&self\) -> &\'static str \{.*?\n    \}\n\n',
    '',
    text,
    flags=re.DOTALL
)

# Change From<u8> to TryFrom<u8>
text = text.replace(
    '''impl From<u8> for Severity {
    fn from(n: u8) -> Self {
        match n {
            0 => Self::Info,
            1 => Self::Low,
            2 => Self::Medium,
            3 => Self::High,
            _ => Self::Critical,
        }
    }
}''',
    '''impl TryFrom<u8> for Severity {
    type Error = &'static str;
    fn try_from(n: u8) -> Result<Self, Self::Error> {
        match n {
            0 => Ok(Self::Info),
            1 => Ok(Self::Low),
            2 => Ok(Self::Medium),
            3 => Ok(Self::High),
            4 => Ok(Self::Critical),
            _ => Err("Invalid severity level: must be between 0 and 4"),
        }
    }
}'''
)

with open('src/severity.rs', 'w') as f:
    f.write(text)
