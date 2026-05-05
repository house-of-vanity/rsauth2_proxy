use crate::crypto::CookieCrypto;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Session {
    pub sub: String,
    pub username: String,
    pub email: String,
    pub groups: Vec<String>,
    pub exp: i64,
    pub iat: i64,
    pub refresh_token: Option<String>,
}

impl Session {
    pub fn is_access_expired(&self) -> bool {
        now_timestamp() >= self.exp
    }

    pub fn encrypt(&self, crypto: &CookieCrypto) -> anyhow::Result<String> {
        let json = serde_json::to_vec(self)?;
        crypto.encrypt(&json)
    }

    pub fn decrypt(crypto: &CookieCrypto, encoded: &str) -> anyhow::Result<Self> {
        let plaintext = crypto.decrypt(encoded)?;
        Ok(serde_json::from_slice(&plaintext)?)
    }
}

pub fn now_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::CookieCrypto;

    fn make_session(exp_offset: i64) -> Session {
        Session {
            sub: "user-123".into(),
            username: "john".into(),
            email: "john@example.com".into(),
            groups: vec!["admins".into(), "devs".into()],
            exp: now_timestamp() + exp_offset,
            iat: now_timestamp(),
            refresh_token: Some("refresh-tok-xyz".into()),
        }
    }

    #[test]
    fn encrypt_decrypt_preserves_all_fields() {
        let crypto = CookieCrypto::new(&[0x42; 32]);
        let session = make_session(3600);
        let encrypted = session.encrypt(&crypto).unwrap();
        let restored = Session::decrypt(&crypto, &encrypted).unwrap();

        assert_eq!(restored.sub, "user-123");
        assert_eq!(restored.username, "john");
        assert_eq!(restored.email, "john@example.com");
        assert_eq!(restored.groups, vec!["admins", "devs"]);
        assert_eq!(restored.exp, session.exp);
        assert_eq!(restored.iat, session.iat);
        assert_eq!(restored.refresh_token.as_deref(), Some("refresh-tok-xyz"));
    }

    #[test]
    fn session_without_refresh_token() {
        let crypto = CookieCrypto::new(&[0x42; 32]);
        let mut session = make_session(3600);
        session.refresh_token = None;
        let encrypted = session.encrypt(&crypto).unwrap();
        let restored = Session::decrypt(&crypto, &encrypted).unwrap();
        assert!(restored.refresh_token.is_none());
    }

    #[test]
    fn active_session_not_expired() {
        let session = make_session(3600); // +1h
        assert!(!session.is_access_expired());
    }

    #[test]
    fn past_session_is_expired() {
        let session = make_session(-1); // 1 second ago
        assert!(session.is_access_expired());
    }

    #[test]
    fn wrong_key_cannot_decrypt() {
        let crypto1 = CookieCrypto::new(&[0x42; 32]);
        let crypto2 = CookieCrypto::new(&[0x99; 32]);
        let encrypted = make_session(3600).encrypt(&crypto1).unwrap();
        assert!(Session::decrypt(&crypto2, &encrypted).is_err());
    }
}
