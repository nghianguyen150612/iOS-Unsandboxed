//! Canonical, bounded read-only builder transaction metadata.

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Pair {
    pub generation: u64,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Marker {
    pub roots: Pair,
    pub policies: Pair,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Journal {
    pub operation: String,
    pub old_roots: Option<Pair>,
    pub new_roots: Pair,
    pub old_policies: Option<Pair>,
    pub new_policies: Pair,
}

fn lines(bytes: &[u8], maximum: usize) -> Result<Vec<&str>, &'static str> {
    if bytes.is_empty()
        || bytes.len() > maximum
        || bytes.last() != Some(&b'\n')
        || bytes
            .iter()
            .any(|b| *b != b'\n' && !(0x20..=0x7e).contains(b))
    {
        return Err("invalid ASCII/LF metadata");
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "invalid ASCII")?;
    Ok(text[..text.len() - 1].split('\n').collect())
}

fn field<'a>(line: &'a str, name: &str) -> Result<&'a str, &'static str> {
    line.strip_prefix(name)
        .filter(|v| !v.is_empty())
        .ok_or("invalid field order or value")
}

fn number(value: &str) -> Result<u64, &'static str> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|b| b.is_ascii_digit())
    {
        return Err("noncanonical generation");
    }
    value.parse().map_err(|_| "generation overflow")
}

fn digest(value: &str) -> Result<String, &'static str> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid SHA-256");
    }
    Ok(value.to_owned())
}

fn pair(generation: &str, hash: &str) -> Result<Pair, &'static str> {
    Ok(Pair {
        generation: number(generation)?,
        digest: digest(hash)?,
    })
}

fn old_pair(generation: &str, hash: &str) -> Result<Option<Pair>, &'static str> {
    if generation == "none" && hash == "none" {
        Ok(None)
    } else if generation == "none" || hash == "none" {
        Err("inconsistent absent store")
    } else {
        Ok(Some(pair(generation, hash)?))
    }
}

fn changed(old: &Option<Pair>, new: &Pair) -> Result<bool, &'static str> {
    match old {
        None if new.generation == 1 => Ok(true),
        None => Err("invalid initial generation"),
        Some(old) if old == new => Ok(false),
        Some(old)
            if old.generation.checked_add(1) == Some(new.generation)
                && old.digest != new.digest =>
        {
            Ok(true)
        }
        Some(_) => Err("invalid generation transition"),
    }
}

pub(crate) fn parse_journal(bytes: &[u8]) -> Result<Journal, &'static str> {
    let l = lines(bytes, 1024)?;
    if l.len() != 14 || l[0] != "ios-unsandboxed-builder-transaction" || l[1] != "schema_version=1"
    {
        return Err("unsupported journal schema");
    }
    let operation = field(l[2], "operation=")?;
    let old_roots = old_pair(
        field(l[3], "old_root_generation=")?,
        field(l[5], "old_root_sha256=")?,
    )?;
    let new_roots = pair(
        field(l[4], "new_root_generation=")?,
        field(l[6], "new_root_sha256=")?,
    )?;
    let old_policies = old_pair(
        field(l[7], "old_policy_generation=")?,
        field(l[9], "old_policy_sha256=")?,
    )?;
    let new_policies = pair(
        field(l[8], "new_policy_generation=")?,
        field(l[10], "new_policy_sha256=")?,
    )?;
    if l[11] != "stage_roots=roots.stage.v1"
        || l[12] != "stage_policies=policies.stage.v1"
        || l[13] != "phase=prepared"
    {
        return Err("unsupported stage or phase");
    }
    let roots_changed = changed(&old_roots, &new_roots)?;
    let policies_changed = changed(&old_policies, &new_policies)?;
    if !matches!(
        (operation, roots_changed, policies_changed),
        ("roots", true, false) | ("policies", false, true) | ("combined", true, true)
    ) {
        return Err("operation does not match changes");
    }
    Ok(Journal {
        operation: operation.to_owned(),
        old_roots,
        new_roots,
        old_policies,
        new_policies,
    })
}

pub(crate) fn parse_marker(bytes: &[u8]) -> Result<Marker, &'static str> {
    let l = lines(bytes, 512)?;
    if l.len() != 6 || l[0] != "ios-unsandboxed-builder-state" || l[1] != "schema_version=1" {
        return Err("unsupported marker schema");
    }
    Ok(Marker {
        roots: pair(
            field(l[2], "root_generation=")?,
            field(l[3], "root_sha256=")?,
        )?,
        policies: pair(
            field(l[4], "policy_generation=")?,
            field(l[5], "policy_sha256=")?,
        )?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_metadata_rejects_duplicates_and_overflow() {
        assert!(parse_journal(include_bytes!(
            "../../tests/builder-trust/valid-transaction.v1"
        ))
        .is_ok());
        let hash = "a".repeat(64);
        let marker = format!("ios-unsandboxed-builder-state\nschema_version=1\nroot_generation=1\nroot_sha256={hash}\npolicy_generation=2\npolicy_sha256={hash}\n");
        assert!(parse_marker(marker.as_bytes()).is_ok());
        assert!(parse_marker(
            marker
                .replace("root_generation=1", "root_generation=01")
                .as_bytes()
        )
        .is_err());
        assert!(parse_marker(
            marker
                .replace("policy_generation=2", "root_generation=2")
                .as_bytes()
        )
        .is_err());
        let journal = format!("ios-unsandboxed-builder-transaction\nschema_version=1\noperation=combined\nold_root_generation=none\nnew_root_generation=1\nold_root_sha256=none\nnew_root_sha256={hash}\nold_policy_generation=none\nnew_policy_generation=1\nold_policy_sha256=none\nnew_policy_sha256={hash}\nstage_roots=roots.stage.v1\nstage_policies=policies.stage.v1\nphase=prepared\n");
        assert!(parse_journal(journal.as_bytes()).is_ok());
        assert!(parse_journal(journal.replace("roots.stage.v1", "../roots").as_bytes()).is_err());
        assert!(parse_journal(
            journal
                .replace(
                    "new_root_generation=1",
                    "new_root_generation=18446744073709551616"
                )
                .as_bytes()
        )
        .is_err());
    }
}
