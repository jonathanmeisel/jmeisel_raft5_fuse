//! What one device keeps of the account's data for itself, such as the
//! search index it has downloaded: sealed under a key that only the
//! account's key pair gives. A copy of the device's storage is then
//! ciphertext to anyone who can't log in as the account.
//!
//! Each piece is bound to its name, so one piece can't be passed off as
//! another.

use crate::identity::Identity;
use crate::{Error, aad, open, seal};

const PURPOSE: &str = "local-cache";

/// `plain`, sealed for this device to keep under `name`.
pub fn seal_local(identity: &Identity, name: &str, plain: &[u8]) -> Vec<u8> {
    let key = identity.derive_key(PURPOSE);
    seal(&key, &aad(PURPOSE, &[name.as_bytes()]), plain)
}

/// What `seal_local` sealed under `name`.
pub fn open_local(identity: &Identity, name: &str, sealed: &[u8]) -> Result<Vec<u8>, Error> {
    let key = identity.derive_key(PURPOSE);
    open(
        &key,
        &aad(PURPOSE, &[name.as_bytes()]),
        sealed,
        "a piece this device kept",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_account_opens_it_and_only_under_its_name() {
        let me = Identity::generate();
        let sealed = seal_local(&me, "v/seg-1", b"entries");
        assert_eq!(open_local(&me, "v/seg-1", &sealed).unwrap(), b"entries");
        assert!(open_local(&me, "v/seg-2", &sealed).is_err());
        assert!(open_local(&Identity::generate(), "v/seg-1", &sealed).is_err());
    }
}
