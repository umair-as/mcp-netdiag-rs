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

use std::path::Path;

use crate::errors::NetdiagError;

/// Longest Linux interface name (`IFNAMSIZ - 1`).
const IFNAME_MAX: usize = 15;

/// Validate a network interface name token. On top of [`validate_token`],
/// apply the kernel's own `dev_valid_name` rules: at most 15 bytes, not `.`
/// or `..`, and no `:` or `/` (so the name is also safe as a single path
/// component under `/sys/class/net`).
pub fn validate_interface(value: &str) -> Result<(), NetdiagError> {
    validate_token("interface", value)?;
    let invalid = |reason: &str| {
        Err(NetdiagError::InvalidParam {
            name: "interface".to_string(),
            reason: reason.to_string(),
        })
    };
    if value.len() > IFNAME_MAX {
        return invalid("must be <= 15 chars (Linux IFNAMSIZ)");
    }
    if value == "." || value == ".." || value.contains([':', '/']) {
        return invalid("is not a valid Linux interface name");
    }
    Ok(())
}

/// Default root for [`validate_capture_interface`]: where the kernel lists
/// real network devices.
pub const SYS_CLASS_NET: &str = "/sys/class/net";

/// Common libpcap pseudo-device names, refused even if a netdev of that name
/// exists. (libpcap claims more, e.g. `dbus-*`, `bluetooth*`, `usbmon*`; those
/// are rejected by the `/sys/class/net` check unless an admin creates such a
/// netdev.)
const PCAP_RESERVED: &[&str] = &["any", "nflog", "nfqueue"];

/// Validate the interface handed to `tcpdump -i`. tcpdump also accepts
/// libpcap pseudo-devices (`any`, `nflog`, `nfqueue`, `dbus-system`,
/// `dbus-session`, `bluetooth-monitor`, …) and bare numbers as indexes
/// into `tcpdump -D`, which reach far beyond a network interface — e.g.
/// eavesdropping on D-Bus or binding a netfilter queue. Only names of real
/// network devices (with an `ifindex` under `sys_class_net`, normally
/// [`SYS_CLASS_NET`]) are accepted.
pub async fn validate_capture_interface(
    value: &str,
    sys_class_net: &Path,
) -> Result<(), NetdiagError> {
    validate_interface(value)?;
    let invalid = |reason: String| {
        Err(NetdiagError::InvalidParam {
            name: "interface".to_string(),
            reason,
        })
    };
    let not_an_interface = || {
        invalid(
            "not a network interface on this host (pseudo-devices such as `any`, \
             `nflog` or `dbus-*` are not accepted)"
                .to_string(),
        )
    };
    if value.bytes().all(|b| b.is_ascii_digit()) {
        return invalid(
            "numeric interface indexes are not accepted; use the interface name".to_string(),
        );
    }
    if PCAP_RESERVED.contains(&value) {
        return invalid(format!(
            "`{value}` is a libpcap pseudo-device, not an interface"
        ));
    }
    // `validate_interface` guarantees `value` is one plain path component.
    // Requiring `ifindex` skips non-device entries such as `bonding_masters`.
    match tokio::fs::try_exists(sys_class_net.join(value).join("ifindex")).await {
        Ok(true) => Ok(()),
        Ok(false) => not_an_interface(),
        // NotADirectory: `<value>` is a plain file such as `bonding_masters`.
        Err(e) if e.kind() == std::io::ErrorKind::NotADirectory => not_an_interface(),
        // A host condition, not the caller's input.
        Err(e) => Err(NetdiagError::CommandExec {
            message: format!("could not check {}: {e}", sys_class_net.display()),
        }),
    }
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
    fn validate_interface_applies_kernel_name_rules() {
        assert!(validate_interface("enp0s31f6").is_ok());
        assert!(validate_interface("eth0.100").is_ok());
        assert!(validate_interface("a23456789012345").is_ok()); // 15 = IFNAMSIZ-1
        assert!(validate_interface("a234567890123456").is_err());
        assert!(validate_interface(".").is_err());
        assert!(validate_interface("..").is_err());
        assert!(validate_interface("eth0:1").is_err());
        assert!(validate_interface("../lo").is_err());
    }

    #[tokio::test]
    async fn capture_interface_must_exist_in_sys_class_net() {
        let sys = tempfile::tempdir().unwrap();
        std::fs::create_dir(sys.path().join("eth0")).unwrap();
        std::fs::write(sys.path().join("eth0/ifindex"), "2\n").unwrap();
        // A non-device entry (as `bonding_masters` is) must not pass.
        std::fs::write(sys.path().join("bonding_masters"), "").unwrap();
        assert!(validate_capture_interface("eth0", sys.path()).await.is_ok());
        let err = validate_capture_interface("bonding_masters", sys.path())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not a network interface"), "{err}");
        for pseudo in ["any", "nflog", "nfqueue", "dbus-system", "dbus-session"] {
            let err = validate_capture_interface(pseudo, sys.path())
                .await
                .unwrap_err();
            assert_eq!(err.code(), -32010, "{pseudo} must be rejected");
        }
    }

    #[tokio::test]
    async fn capture_interface_rejects_numeric_index_and_pcap_names() {
        // `tcpdump -i 2` picks entry 2 of `tcpdump -D` (often `any`). Reject
        // all-digit names even if such a device happened to exist.
        let sys = tempfile::tempdir().unwrap();
        for name in ["2", "any", "nflog"] {
            std::fs::create_dir(sys.path().join(name)).unwrap();
            std::fs::write(sys.path().join(name).join("ifindex"), "9\n").unwrap();
            assert!(validate_capture_interface(name, sys.path()).await.is_err());
        }
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
