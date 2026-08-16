use std::{
    fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

/// Non-sensitive, machine-local preferences shared by the console UI and CLI.
/// This deliberately contains no run data, capabilities, manifests, or credentials.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ConsolePreferences {
    pub auto_open: bool,
}

impl Default for ConsolePreferences {
    fn default() -> Self {
        Self { auto_open: true }
    }
}

pub fn load_console_preferences() -> ConsolePreferences {
    load_from_path(&console_preferences_path())
}

pub fn save_console_preferences(
    preferences: ConsolePreferences,
) -> Result<ConsolePreferences, String> {
    save_to_path(&console_preferences_path(), &preferences)?;
    Ok(preferences)
}

fn console_preferences_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../artifacts/console/preferences.json")
}

fn load_from_path(path: &Path) -> ConsolePreferences {
    fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn save_to_path(path: &Path, preferences: &ConsolePreferences) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "console preferences path has no parent directory".to_owned())?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let value = serde_json::to_vec_pretty(preferences).map_err(|error| error.to_string())?;
    fs::write(path, value).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{ConsolePreferences, load_from_path, save_to_path};

    #[test]
    fn preferences_round_trip_contains_only_auto_open() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("fqdn-forge-console-preferences-{nonce}.json"));
        let preferences = ConsolePreferences { auto_open: false };

        save_to_path(&path, &preferences).expect("save preferences");
        assert_eq!(load_from_path(&path), preferences);
        let contents = std::fs::read_to_string(&path).expect("read preferences");
        assert!(!contents.contains("capability"));
        assert!(!contents.contains("credential"));
        std::fs::remove_file(path).expect("remove preferences");
    }
}
