//! Fixed exit codes for deadboltctl. Monitoring checks depend on these.

/// Nothing found, everything required is present.
pub const CLEAN: i32 = 0;
/// A scan found at least one threat.
pub const THREATS: i32 = 1;
/// Something went wrong, or (for `doctor`) something required is missing.
pub const ERROR: i32 = 2;
