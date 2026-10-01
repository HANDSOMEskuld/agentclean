use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub state_dir: Option<String>,
    pub protected: Vec<String>,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            state_dir: None,
            protected: vec![".ssh".into(), ".gnupg".into()],
        }
    }
}
impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        };
        Ok(serde_yaml::from_str(&fs::read_to_string(path)?)?)
    }
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(p) = path.parent() {
            fs::create_dir_all(p)?
        };
        fs::write(path, serde_yaml::to_string(self)?)?;
        Ok(())
    }
}
