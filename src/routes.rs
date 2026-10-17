use anyhow::Result;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Deserialize, Clone)]
pub struct RouteConfig {
    #[serde(default)]
    pub allowed_groups: Vec<String>,
    #[serde(default = "default_browser_access")]
    pub browser_access: bool,
    #[serde(default)]
    pub machine_access: Option<MachineAccess>,
}

fn default_browser_access() -> bool {
    true
}

#[derive(Debug, Deserialize, Clone)]
pub struct MachineAccess {
    pub client_ids: Vec<String>,
    pub method: String,
    pub path: String,
}

#[derive(Debug, Deserialize)]
pub struct RoutesFile {
    pub routes: HashMap<String, RouteConfig>,
}

pub type SharedRoutes = Arc<RwLock<HashMap<String, RouteConfig>>>;

pub fn load_routes(path: &str) -> Result<HashMap<String, RouteConfig>> {
    let content = std::fs::read_to_string(path)?;
    let routes_file: RoutesFile = serde_yaml::from_str(&content)?;
    let count = routes_file.routes.len();
    tracing::info!(count, "routes loaded");
    metrics::gauge!("routes_loaded_total").set(count as f64);
    Ok(routes_file.routes)
}

pub async fn watch_routes(path: String, routes: SharedRoutes) {
    let mut last_content = std::fs::read_to_string(&path).unwrap_or_default();
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));

    loop {
        interval.tick().await;

        // Read through the symlink — k8s ConfigMap updates swap the symlink target,
        // so reading the original path always gives current content.
        match std::fs::read_to_string(&path) {
            Ok(content) if content != last_content => {
                match serde_yaml::from_str::<RoutesFile>(&content) {
                    Ok(routes_file) => {
                        let count = routes_file.routes.len();
                        *routes.write().await = routes_file.routes;
                        last_content = content;
                        metrics::gauge!("routes_loaded_total").set(count as f64);
                        tracing::info!(count, "routes reloaded");
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "failed to parse routes file");
                    }
                }
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(error = %e, "failed to read routes file");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_routes_yaml() {
        let yaml = r#"
routes:
  grafana.example.com:
    allowed_groups: ["admins", "developers"]
  wiki.example.com:
    allowed_groups: []
"#;
        let rf: RoutesFile = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(rf.routes.len(), 2);
        assert_eq!(
            rf.routes["grafana.example.com"].allowed_groups,
            vec!["admins", "developers"]
        );
        assert!(rf.routes["wiki.example.com"].allowed_groups.is_empty());
    }

    #[test]
    fn load_routes_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("routes.yaml");
        std::fs::write(
            &path,
            "routes:\n  app.example.com:\n    allowed_groups: [\"users\"]\n",
        )
        .unwrap();
        let routes = load_routes(path.to_str().unwrap()).unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes["app.example.com"].allowed_groups, vec!["users"]);
    }

    #[test]
    fn empty_routes_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("routes.yaml");
        std::fs::write(&path, "routes: {}\n").unwrap();
        let routes = load_routes(path.to_str().unwrap()).unwrap();
        assert!(routes.is_empty());
    }

    #[test]
    fn invalid_yaml_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("routes.yaml");
        std::fs::write(&path, "not: valid: yaml: [[[").unwrap();
        assert!(load_routes(path.to_str().unwrap()).is_err());
    }

    #[test]
    fn missing_file_returns_error() {
        assert!(load_routes("/nonexistent/routes.yaml").is_err());
    }

    #[tokio::test]
    async fn watch_routes_detects_change() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("routes.yaml");
        std::fs::write(&path, "routes:\n  a.example.com:\n    allowed_groups: []\n").unwrap();

        let initial = load_routes(path.to_str().unwrap()).unwrap();
        let shared: SharedRoutes = Arc::new(RwLock::new(initial));
        assert_eq!(shared.read().await.len(), 1);

        let watch_path = path.to_str().unwrap().to_string();
        let watch_routes = shared.clone();
        let handle = tokio::spawn(async move {
            super::watch_routes(watch_path, watch_routes).await;
        });

        // Let the watcher initialize and read the original content
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Update the file
        std::fs::write(
            &path,
            "routes:\n  a.example.com:\n    allowed_groups: []\n  b.example.com:\n    allowed_groups: [\"admins\"]\n",
        )
        .unwrap();

        // Poll interval is 5s; wait up to 12s for the change to be detected
        for _ in 0..12 {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            if shared.read().await.len() == 2 {
                break;
            }
        }
        assert_eq!(shared.read().await.len(), 2);

        handle.abort();
    }
}
