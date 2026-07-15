use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub id: Uuid,
    pub name: String,
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub tags: Vec<String>,
    pub updated_at: DateTime<Utc>,
}

impl Zeroize for Entry {
    fn zeroize(&mut self) {
        self.name.zeroize();
        self.username.zeroize();
        self.password.zeroize();
        self.url.zeroize();
        self.notes.zeroize();
        for tag in &mut self.tags {
            tag.zeroize();
        }
        self.tags.clear();
    }
}

impl Drop for Entry {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct VaultData {
    pub version: u32,
    #[zeroize(skip)]
    pub entries: Vec<Entry>,
}

impl VaultData {
    pub fn new() -> Self {
        Self {
            version: 1,
            entries: Vec::new(),
        }
    }

    pub fn find_mut(&mut self, query: &str) -> Option<&mut Entry> {
        let idx = if let Ok(id) = Uuid::parse_str(query) {
            self.entries.iter().position(|e| e.id == id)
        } else {
            let q = query.to_lowercase();
            self.entries
                .iter()
                .position(|e| e.name.to_lowercase() == q || e.name.to_lowercase().contains(&q))
        }?;
        Some(&mut self.entries[idx])
    }

    pub fn find(&self, query: &str) -> Option<&Entry> {
        if let Ok(id) = Uuid::parse_str(query) {
            if let Some(e) = self.entries.iter().find(|e| e.id == id) {
                return Some(e);
            }
        }
        let q = query.to_lowercase();
        self.entries
            .iter()
            .find(|e| e.name.to_lowercase() == q || e.name.to_lowercase().contains(&q))
    }

    pub fn remove(&mut self, query: &str) -> Option<Entry> {
        let idx = if let Ok(id) = Uuid::parse_str(query) {
            self.entries.iter().position(|e| e.id == id)
        } else {
            let q = query.to_lowercase();
            self.entries
                .iter()
                .position(|e| e.name.to_lowercase() == q || e.name.to_lowercase().contains(&q))
        }?;
        Some(self.entries.remove(idx))
    }
}

impl Default for VaultData {
    fn default() -> Self {
        Self::new()
    }
}
