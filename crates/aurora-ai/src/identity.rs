//! Caller identity representation for policy authorization.
//!
//! Pursuant to ADR-002, caller identity is an explicit input to the deterministic
//! authorization pipeline. At M3, identity is abstracted cleanly from specific IPC
//! mechanisms (such as D-Bus or socket credentials) to facilitate deterministic testing
//! without coupling to external system services.

/// Represents the identity of the calling principal requesting an action.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CallerIdentity {
    /// An authenticated principal identified by a unique ID string
    /// (e.g., user session ID, application ID, or system UID).
    Principal(String),
    /// An anonymous or unauthenticated caller (always rejected by policy).
    Anonymous,
}

impl CallerIdentity {
    /// Constructs an authenticated principal identity.
    pub fn principal(id: impl Into<String>) -> Self {
        let s = id.into();
        if s.trim().is_empty() {
            Self::Anonymous
        } else {
            Self::Principal(s)
        }
    }

    /// Constructs an anonymous / unauthenticated identity.
    pub fn anonymous() -> Self {
        Self::Anonymous
    }

    /// Returns true if the caller represents an authenticated principal.
    pub fn is_authenticated(&self) -> bool {
        match self {
            Self::Principal(id) => !id.trim().is_empty(),
            Self::Anonymous => false,
        }
    }

    /// Returns the principal identifier string, if authenticated.
    pub fn id(&self) -> Option<&str> {
        match self {
            Self::Principal(id) => Some(id.as_str()),
            Self::Anonymous => None,
        }
    }
}

impl std::fmt::Display for CallerIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Principal(id) => write!(f, "Principal({id})"),
            Self::Anonymous => write!(f, "Anonymous"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_principal_identity() {
        let caller = CallerIdentity::principal("user-1000");
        assert!(caller.is_authenticated());
        assert_eq!(caller.id(), Some("user-1000"));
        assert_eq!(caller.to_string(), "Principal(user-1000)");
    }

    #[test]
    fn test_anonymous_identity() {
        let anon = CallerIdentity::anonymous();
        assert!(!anon.is_authenticated());
        assert_eq!(anon.id(), None);
        assert_eq!(anon.to_string(), "Anonymous");

        // Empty string maps to Anonymous
        let empty = CallerIdentity::principal("   ");
        assert!(!empty.is_authenticated());
    }
}
