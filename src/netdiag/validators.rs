// SPDX-License-Identifier: MIT OR Apache-2.0

//! Caller-supplied argument-token validators — the input-sanitization half
//! of the security boundary.
//!
//! Every user-controlled argv fragment (interface, unit, target, MAC) reaches
//! the allowlisted command in [`super::commands`] *only* after passing through
//! one of these validators. They funnel into [`validate_token_with_extra`],
//! which is what blocks shell-metacharacter injection and argv-flag injection
//! (a leading `-` would be parsed by the underlying command as a CLI option,
//! breaking the "no arbitrary flags" guarantee).

use crate::errors::NetdiagError;

/// Validate an interface (or systemd unit) name token.
pub fn validate_interface(value: &str) -> Result<(), NetdiagError> {
    validate_token("interface", value)
}

/// Validate a systemd unit name token.
pub fn validate_unit(value: &str) -> Result<(), NetdiagError> {
    validate_token_with_extra("unit", value, &['@'])
}

/// Validate an IP address or hostname token. Shares the leading-`-` reject
/// with [`validate_interface`] and [`validate_unit`] via [`validate_token`].
pub fn validate_ip_or_host(value: &str) -> Result<(), NetdiagError> {
    validate_token("target", value)
}

/// Validate a MAC address in `aa:bb:cc:dd:ee:ff` form (case-insensitive).
pub fn validate_mac(value: &str) -> Result<(), NetdiagError> {
    let normalized = value.to_ascii_lowercase();
    let parts: Vec<_> = normalized.split(':').collect();
    if parts.len() != 6
        || parts
            .iter()
            .any(|p| p.len() != 2 || !p.chars().all(|c| c.is_ascii_hexdigit()))
    {
        return Err(NetdiagError::InvalidParam {
            name: "mac".to_string(),
            reason: "must be in aa:bb:cc:dd:ee:ff form".to_string(),
        });
    }
    Ok(())
}

/// Shared token validator: non-empty, ≤ 128 chars, must not start with `-`,
/// and restricted to a conservative character class. This is what blocks
/// shell-metacharacter injection and argv-flag injection (a leading `-`
/// would be parsed by the underlying command as a CLI option, breaking the
/// "no arbitrary flags" security boundary) — extra args reach the command
/// only through here.
fn validate_token(name: &str, value: &str) -> Result<(), NetdiagError> {
    validate_token_with_extra(name, value, &[])
}

fn validate_token_with_extra(
    name: &str,
    value: &str,
    extra_allowed: &[char],
) -> Result<(), NetdiagError> {
    if value.is_empty() || value.len() > 128 {
        return Err(NetdiagError::InvalidParam {
            name: name.to_string(),
            reason: "must be non-empty and <= 128 chars".to_string(),
        });
    }

    if value.starts_with('-') {
        return Err(NetdiagError::InvalidParam {
            name: name.to_string(),
            reason: "must not begin with '-'".to_string(),
        });
    }

    if !value.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || matches!(c, '.' | ':' | '-' | '_' | '/')
            || extra_allowed.contains(&c)
    }) {
        return Err(NetdiagError::InvalidParam {
            name: name.to_string(),
            reason: "contains unsupported characters".to_string(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_mac_accepts_valid_mac() {
        assert!(validate_mac("aa:bb:cc:dd:ee:ff").is_ok());
    }

    #[test]
    fn validate_mac_rejects_invalid_mac() {
        assert!(validate_mac("aa:bb:cc").is_err());
    }

    #[test]
    fn validate_token_rejects_bad_chars() {
        assert!(validate_token("target", "8.8.8.8;rm").is_err());
    }

    #[test]
    fn validate_unit_accepts_template_units() {
        assert!(validate_unit("serial-getty@ttyS0.service").is_ok());
    }

    #[test]
    fn validate_ip_or_host_accepts_normal_targets() {
        assert!(validate_ip_or_host("8.8.8.8").is_ok());
        assert!(validate_ip_or_host("gateway.local").is_ok());
    }

    #[test]
    fn validate_ip_or_host_rejects_leading_dash() {
        // A leading '-' would be parsed by ping/traceroute as a CLI flag.
        let err = validate_ip_or_host("-f").unwrap_err();
        assert!(matches!(err, NetdiagError::InvalidParam { ref name, .. } if name == "target"),);
        assert_eq!(err.code(), -32010);
        assert!(validate_ip_or_host("-q30").is_err());
    }

    #[test]
    fn validate_interface_accepts_normal_names() {
        assert!(validate_interface("eth0").is_ok());
        assert!(validate_interface("wlp3s0").is_ok());
        assert!(validate_interface("br-lan").is_ok());
    }

    #[test]
    fn validate_interface_rejects_leading_dash() {
        // ethtool is invoked with no base args, so a leading '-' would be
        // parsed as a CLI flag (e.g. "-h", "-i", "-S"). Block at validation.
        let err = validate_interface("-h").unwrap_err();
        assert!(
            matches!(err, NetdiagError::InvalidParam { ref name, ref reason, .. }
                if name == "interface" && reason.contains("must not begin with '-'"))
        );
        assert_eq!(err.code(), -32010);
        assert!(validate_interface("-i").is_err());
        assert!(validate_interface("--reset").is_err());
    }

    #[test]
    fn validate_unit_rejects_leading_dash() {
        // systemctl status / journalctl -u would parse a leading '-' as an
        // option flag (the validator-token then leaks past the consuming
        // flag in some argv positions). Block at validation.
        let err = validate_unit("-h").unwrap_err();
        assert!(
            matches!(err, NetdiagError::InvalidParam { ref name, ref reason, .. }
                if name == "unit" && reason.contains("must not begin with '-'"))
        );
        assert_eq!(err.code(), -32010);
        assert!(validate_unit("-foo.service").is_err());
    }
}
