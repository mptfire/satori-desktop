//! NIP-23 long-form articles — tag parsing slice of `src/nostr/content.ts` +
//! `src/render/note.ts` articleRow/reader; the publish half ports
//! `signArticle` (publish.ts) + the route's `d` generation (article.ts:
//! random 8 bytes hex).

use nostr::prelude::*;

#[derive(Clone)]
pub struct ArticleData {
    pub title: String,
    pub summary: String,
    pub image: Option<String>,
    pub published_at: Option<u64>,
    pub slug: String,
}

/// The `t` topics (NIP-23: zero or more `t` tags).
pub fn topics(ev: &Event) -> Vec<String> {
    ev.tags
        .clone()
        .to_vec()
        .into_iter()
        .filter(|t| t.as_slice().first().map(String::as_str) == Some("t"))
        .filter_map(|t| t.as_slice().get(1).cloned())
        .filter(|t| !t.is_empty())
        .collect()
}

/// Estimated reading time in whole minutes (≥1) at ~220 wpm — the char-walk
/// port of readingMinutes (content.ts): no throwaway word-array per call.
pub fn reading_minutes(markdown: &str) -> u64 {
    let mut words = 0u64;
    let mut in_word = false;
    for c in markdown.chars() {
        let ws = c.is_whitespace();
        if !ws && !in_word {
            words += 1;
        }
        in_word = !ws;
    }
    words.div_ceil(220).max(1)
}

/// The composer's fields (signArticle's ArticleFields).
pub struct ArticleDraft {
    pub title: String,
    pub summary: String,
    /// Cover image URL (often a Blossom blob from upload-at-attach).
    pub image: Option<String>,
    pub topics: Vec<String>,
    /// The Markdown body — the event's content.
    pub body: String,
    /// The addressable `d`. Empty → a fresh random identifier.
    pub identifier: String,
}

impl ArticleDraft {
    /// Build the NIP-23 tag set (signArticle): `d` + `title` structural,
    /// then `summary` / `image` when present, `published_at` = now (a
    /// fresh publish — edits preserving an original date are not wired),
    /// one `t` per topic.
    pub fn tags(&self, now: u64) -> Vec<Tag> {
        let identifier = if self.identifier.trim().is_empty() {
            new_identifier()
        } else {
            self.identifier.trim().to_string()
        };
        let mut tags = vec![
            Tag::custom("d", [identifier]),
            Tag::custom("title", [self.title.trim().to_string()]),
        ];
        let summary = self.summary.trim();
        if !summary.is_empty() {
            tags.push(Tag::custom("summary", [summary]));
        }
        if let Some(image) = self
            .image
            .as_deref()
            .map(str::trim)
            .filter(|i| !i.is_empty())
        {
            tags.push(Tag::custom("image", [image]));
        }
        tags.push(Tag::custom("published_at", [now.to_string()]));
        for t in &self.topics {
            let t = t.trim().trim_start_matches('#');
            if !t.is_empty() {
                tags.push(Tag::custom("t", [t]));
            }
        }
        tags
    }
}

/// A fresh addressable `d`: 16 hex chars (the article route's
/// randomBytes(8).toString('hex')). Time-seeded xorshift — poll_option_id's
/// discipline (core has no rng dep).
pub fn new_identifier() -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
        ^ 0x9E37_79B9_7F4A_7C15;
    let mut id = String::new();
    for _ in 0..16 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        id.push(HEX[(seed % HEX.len() as u64) as usize] as char);
    }
    id
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;

    /// signArticle's tag shape: d + title structural, summary/image when
    /// present, published_at, one t per topic (a leading # stripped).
    #[test]
    fn draft_tags_build() {
        let draft = ArticleDraft {
            title: "  The Tao of Whitespace  ".into(),
            summary: " why margins matter ".into(),
            image: Some("https://cdn.example/cover.png".into()),
            topics: vec!["writing".into(), "#nostr".into(), "  ".into()],
            body: "# H1\n\nbody".into(),
            identifier: String::new(),
        };
        let tags = draft.tags(1700000000);
        let find = |k: &str| {
            tags.iter()
                .filter(|t| t.as_slice().first().map(String::as_str) == Some(k))
                .map(|t| t.as_slice().get(1).cloned().unwrap_or_default())
                .collect::<Vec<_>>()
        };
        assert_eq!(find("d").len(), 1);
        assert_eq!(find("d")[0].len(), 16, "blank identifier → random hex");
        assert!(find("d")[0].chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(find("title"), vec!["The Tao of Whitespace"], "trimmed");
        assert_eq!(find("summary"), vec!["why margins matter"]);
        assert_eq!(find("image"), vec!["https://cdn.example/cover.png"]);
        assert_eq!(find("published_at"), vec!["1700000000"]);
        assert_eq!(
            find("t"),
            vec!["writing", "nostr"],
            "topics trimmed, # stripped, blanks dropped"
        );
    }

    /// A carried identifier survives verbatim (the edit-path shape).
    #[test]
    fn identifier_carried() {
        let draft = ArticleDraft {
            title: "t".into(),
            summary: String::new(),
            image: None,
            topics: Vec::new(),
            body: "b".into(),
            identifier: "my-slug-42".into(),
        };
        let tags = draft.tags(1);
        let d = tags
            .iter()
            .find(|t| t.as_slice().first() == Some(&"d".to_string()))
            .unwrap()
            .as_slice()[1]
            .clone();
        assert_eq!(d, "my-slug-42");
    }

    /// readingMinutes's rate: ~220 wpm, floor 1.
    #[test]
    fn reading_time() {
        assert_eq!(reading_minutes(""), 1, "floor");
        let short = "one two three";
        assert_eq!(reading_minutes(short), 1);
        let long = "word ".repeat(220 * 5);
        assert_eq!(reading_minutes(&long), 5);
    }
}

pub fn parse(ev: &Event) -> Option<ArticleData> {
    let mut d = ArticleData {
        title: String::new(),
        summary: String::new(),
        image: None,
        published_at: None,
        slug: String::new(),
    };
    for tag in ev.tags.clone().to_vec() {
        let parts = tag.as_slice();
        match parts.first().map(String::as_str) {
            Some("title") if parts.len() >= 2 => d.title = parts[1..].join(" "),
            Some("summary") if parts.len() >= 2 => d.summary = parts[1..].join(" "),
            Some("image") if parts.len() >= 2 => d.image = Some(parts[1].clone()),
            Some("published_at") if parts.len() >= 2 => {
                d.published_at = parts.get(1).and_then(|v| v.parse().ok())
            }
            Some("d") if parts.len() >= 2 => d.slug = parts[1].clone(),
            _ => {}
        }
    }
    (!d.title.is_empty()).then_some(d)
}
