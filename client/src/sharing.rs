//! How a node is shared, for showing: with whom besides this account, and
//! whether it has a public link. It is the servers' word, not checked.

use raft5fs_proto::types::{Grantee, LINK_PREFIX};
use serde::Serialize;

/// Whom a node is shared with besides this account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NodeSharing {
    /// Their names, in order; public links aren't among them.
    pub people: Vec<String>,
    /// Whether it has a public link.
    pub link: bool,
}

impl NodeSharing {
    /// How a folder's mark shows it: a link, or people.
    pub fn mark(&self) -> &'static str {
        if self.link { "link" } else { "people" }
    }
}

/// Whom a node with `grantees` is shared with besides `me`, if anyone.
pub fn sharing_of(grantees: &[Grantee], me: &str) -> Option<NodeSharing> {
    let link = grantees.iter().any(|g| g.user.starts_with(LINK_PREFIX));
    let mut people: Vec<String> = grantees
        .iter()
        .filter(|g| g.user != me && !g.user.starts_with(LINK_PREFIX))
        .map(|g| g.user.clone())
        .collect();
    people.sort();
    (link || !people.is_empty()).then_some(NodeSharing { people, link })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grantee(user: &str) -> Grantee {
        Grantee {
            user: user.into(),
            public_key: Vec::new(),
            writable: false,
        }
    }

    #[test]
    fn sharing_leaves_out_this_account_and_counts_links_apart() {
        let link = format!("{LINK_PREFIX}x1");
        let got = sharing_of(
            &[
                grantee("me"),
                grantee("carol"),
                grantee(&link),
                grantee("bob"),
            ],
            "me",
        );
        assert_eq!(
            got,
            Some(NodeSharing {
                people: vec!["bob".into(), "carol".into()],
                link: true
            })
        );
        assert_eq!(got.unwrap().mark(), "link");
        assert_eq!(sharing_of(&[grantee("me")], "me"), None);
        let people = sharing_of(&[grantee("bob")], "me").unwrap();
        assert_eq!((people.link, people.mark()), (false, "people"));
    }
}
