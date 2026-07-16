use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
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

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LookupError {
    #[error("no entry matching '{query}'")]
    NotFound { query: String },
    #[error("multiple entries match '{query}': {matches}. Use an exact name or id")]
    Ambiguous { query: String, matches: String },
}

impl VaultData {
    pub fn new() -> Self {
        Self {
            version: 1,
            entries: Vec::new(),
        }
    }

    fn resolve_index(&self, query: &str) -> Result<usize, LookupError> {
        if let Ok(id) = Uuid::parse_str(query) {
            return self
                .entries
                .iter()
                .position(|entry| entry.id == id)
                .ok_or_else(|| LookupError::NotFound {
                    query: query.to_string(),
                });
        }

        let normalized_query = query.to_lowercase();
        let exact: Vec<usize> = self
            .entries
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| {
                (entry.name.to_lowercase() == normalized_query).then_some(index)
            })
            .collect();
        if !exact.is_empty() {
            return self.require_single_match(query, exact);
        }

        let partial: Vec<usize> = self
            .entries
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| {
                entry
                    .name
                    .to_lowercase()
                    .contains(&normalized_query)
                    .then_some(index)
            })
            .collect();
        self.require_single_match(query, partial)
    }

    fn require_single_match(
        &self,
        query: &str,
        matches: Vec<usize>,
    ) -> Result<usize, LookupError> {
        if matches.len() == 1 {
            return Ok(matches[0]);
        }
        if matches.is_empty() {
            return Err(LookupError::NotFound {
                query: query.to_string(),
            });
        }

        let candidates = matches
            .into_iter()
            .map(|index| {
                let entry = &self.entries[index];
                format!("{:?} ({})", entry.name, entry.id)
            })
            .collect::<Vec<_>>()
            .join(", ");
        Err(LookupError::Ambiguous {
            query: query.to_string(),
            matches: candidates,
        })
    }

    pub fn find_mut(&mut self, query: &str) -> Result<&mut Entry, LookupError> {
        let index = self.resolve_index(query)?;
        Ok(&mut self.entries[index])
    }

    pub fn find(&self, query: &str) -> Result<&Entry, LookupError> {
        let index = self.resolve_index(query)?;
        Ok(&self.entries[index])
    }

    pub fn remove(&mut self, query: &str) -> Result<Entry, LookupError> {
        let index = self.resolve_index(query)?;
        Ok(self.entries.remove(index))
    }
}

impl Default for VaultData {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: u128, name: &str) -> Entry {
        Entry {
            id: Uuid::from_u128(id),
            name: name.into(),
            username: String::new(),
            password: String::new(),
            url: String::new(),
            notes: String::new(),
            tags: Vec::new(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn exact_name_wins_over_earlier_partial_match() {
        let mut data = VaultData::new();
        data.entries.push(entry(1, "github-admin"));
        data.entries.push(entry(2, "GitHub"));

        assert_eq!(data.find("github").unwrap().id, Uuid::from_u128(2));
    }

    #[test]
    fn unique_partial_match_is_allowed() {
        let mut data = VaultData::new();
        data.entries.push(entry(1, "github"));
        data.entries.push(entry(2, "gitlab"));

        assert_eq!(data.find("hub").unwrap().id, Uuid::from_u128(1));
    }

    #[test]
    fn ambiguous_partial_match_lists_candidates() {
        let mut data = VaultData::new();
        data.entries.push(entry(1, "github-personal"));
        data.entries.push(entry(2, "github-admin"));

        let error = data.find("github").unwrap_err();
        let LookupError::Ambiguous { matches, .. } = error else {
            panic!("expected ambiguous lookup");
        };
        assert!(matches.contains("github-personal"));
        assert!(matches.contains("github-admin"));
    }
}
