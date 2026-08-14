use thiserror::Error;
use url::{Host, Url};

use crate::FilterReason;

#[derive(Clone, Debug, Error)]
pub enum CandidateError {
    #[error("{0:?}")]
    Filtered(FilterReason),
}

pub fn normalize_domain(value: &str) -> Result<String, CandidateError> {
    let candidate = value.trim().trim_end_matches('.');
    if candidate.is_empty() || candidate.len() > 253 {
        return Err(CandidateError::Filtered(FilterReason::InvalidDomain));
    }
    match Host::parse(candidate) {
        Ok(Host::Domain(domain)) if domain.contains('.') => Ok(domain.to_ascii_lowercase()),
        _ => Err(CandidateError::Filtered(FilterReason::InvalidDomain)),
    }
}

pub fn accept_candidate(
    value: &str,
    root_domain: &str,
    include_root: bool,
) -> Result<String, CandidateError> {
    let candidate = value.trim();
    if candidate.starts_with("*.") {
        return Err(CandidateError::Filtered(FilterReason::Wildcard));
    }
    let normalized = normalize_domain(candidate)?;
    if normalized == root_domain {
        return if include_root {
            Ok(normalized)
        } else {
            Err(CandidateError::Filtered(FilterReason::RootExcluded))
        };
    }
    if normalized.ends_with(&format!(".{root_domain}")) {
        Ok(normalized)
    } else {
        Err(CandidateError::Filtered(FilterReason::OutOfScope))
    }
}

pub fn host_from_url(value: &str) -> Result<String, CandidateError> {
    let url = Url::parse(value).map_err(|_| CandidateError::Filtered(FilterReason::InvalidUrl))?;
    url.host_str()
        .map(str::to_owned)
        .ok_or(CandidateError::Filtered(FilterReason::InvalidUrl))
}

#[must_use]
pub fn domainish_tokens(value: &str) -> Vec<String> {
    value
        .split(|character: char| {
            !(character.is_ascii_alphanumeric() || character == '.' || character == '-')
        })
        .filter(|token| token.contains('.'))
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{accept_candidate, host_from_url, normalize_domain};

    #[test]
    fn normalizes_unicode_and_rejects_scope_confusion() {
        assert_eq!(
            normalize_domain("BÜCHER.acme.test.").expect("domain"),
            "xn--bcher-kva.acme.test"
        );
        assert!(accept_candidate("evil-acme.test", "acme.test", false).is_err());
        assert!(accept_candidate("acme.test.attacker.example", "acme.test", false).is_err());
    }

    #[test]
    fn parses_url_host_without_exposing_credentials() {
        assert_eq!(
            host_from_url("https://user:secret@api.acme.test:8443/v1").expect("host"),
            "api.acme.test"
        );
    }
}
