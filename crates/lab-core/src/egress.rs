use std::sync::{Arc, Mutex};

use thiserror::Error;
use url::Url;

#[derive(Clone, Debug, Default)]
pub struct EgressGuard {
    rejected: Arc<Mutex<Vec<String>>>,
}

#[derive(Clone, Debug, Error)]
#[error("strict passive mode blocked non-local URL: {url}")]
pub struct EgressViolation {
    pub url: String,
}

impl EgressGuard {
    pub fn validate(&self, value: &str) -> Result<(), EgressViolation> {
        let allowed = Url::parse(value).is_ok_and(|url| {
            url.scheme() == "http"
                && url.host_str() == Some("127.0.0.1")
                && url.username().is_empty()
                && url.password().is_none()
        });
        if allowed {
            return Ok(());
        }
        let safe = redact_url(value);
        self.rejected
            .lock()
            .expect("egress lock poisoned")
            .push(safe.clone());
        Err(EgressViolation { url: safe })
    }

    #[must_use]
    pub fn rejected_urls(&self) -> Vec<String> {
        self.rejected.lock().expect("egress lock poisoned").clone()
    }
}

fn redact_url(value: &str) -> String {
    match Url::parse(value) {
        Ok(mut url) => {
            let _ = url.set_username("");
            let _ = url.set_password(None);
            url.set_query(None);
            url.to_string()
        }
        Err(_) => "<invalid-url>".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::EgressGuard;

    #[test]
    fn rejects_non_loopback_before_networking() {
        let guard = EgressGuard::default();
        assert!(guard.validate("http://127.0.0.1:18080/health").is_ok());
        assert!(guard.validate("https://acme.test/ct?token=value").is_err());
        assert!(guard.validate("http://localhost:18080/health").is_err());
        assert_eq!(guard.rejected_urls().len(), 2);
    }
}
