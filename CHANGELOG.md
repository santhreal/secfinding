# Changelog

## v0.2.0

- Added `#[non_exhaustive]` to extensible public enums such as `Severity`.
- Added `Display` implementations for printable public types including `Finding`, `FindingBuilder`, `FindingFilter`, and `Evidence`.
- Added `# Thread Safety` API docs for all public types and traits.
- Added `#[must_use]` to important constructors and builders that return values callers should not ignore.
