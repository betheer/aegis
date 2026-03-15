use aegis_core::{CoreError, FirewallBackend, Ruleset};
use async_trait::async_trait;
use std::sync::{Arc, Mutex};

struct MockBackend {
    applied: Arc<Mutex<Vec<String>>>,
    flushed: Arc<Mutex<bool>>,
}

#[async_trait]
impl FirewallBackend for MockBackend {
    async fn apply_ruleset(&self, ruleset: &Ruleset) -> aegis_core::Result<()> {
        self.applied.lock().unwrap().push(ruleset.version.clone());
        Ok(())
    }

    async fn flush(&self) -> aegis_core::Result<()> {
        *self.flushed.lock().unwrap() = true;
        Ok(())
    }

    async fn list_active(&self) -> aegis_core::Result<String> {
        Ok("{}".to_string())
    }
}

#[tokio::test]
async fn mock_backend_apply_ruleset() {
    let applied = Arc::new(Mutex::new(vec![]));
    let backend = MockBackend {
        applied: Arc::clone(&applied),
        flushed: Arc::new(Mutex::new(false)),
    };

    let ruleset = Ruleset {
        nftables_json: r#"{"nftables": []}"#.to_string(),
        version: "v1.0".to_string(),
    };

    backend.apply_ruleset(&ruleset).await.unwrap();
    assert_eq!(*applied.lock().unwrap(), vec!["v1.0"]);
}

#[tokio::test]
async fn mock_backend_flush() {
    let flushed = Arc::new(Mutex::new(false));
    let backend = MockBackend {
        applied: Arc::new(Mutex::new(vec![])),
        flushed: Arc::clone(&flushed),
    };

    backend.flush().await.unwrap();
    assert!(*flushed.lock().unwrap());
}

#[test]
fn core_error_display() {
    let e = CoreError::NftablesFailed("exit 1".to_string());
    assert!(e.to_string().contains("nftables command failed"));

    let e = CoreError::InvalidRule {
        id: "test-rule".to_string(),
        reason: "bad port".to_string(),
    };
    assert!(e.to_string().contains("test-rule"));
    assert!(e.to_string().contains("bad port"));
}
