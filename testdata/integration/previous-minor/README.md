# Previous-compatible integration fixture

This bundle represents the minimum compatible Tally producer version, `0.1.0-alpha.0`. The current
Rust contracts must continue to deserialize, validate, and canonically replay it. When the
integration schema gains a new compatible minor, this directory is replaced with the immediately
preceding minor fixture; breaking changes require a schema-major change and the documented
deprecation window.
