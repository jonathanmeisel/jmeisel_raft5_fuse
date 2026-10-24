//! The field encoding that one-line strings (invitations, links) share:
//! each field a big-endian u32 length and then its bytes, so no field can
//! run into the next.

pub(crate) fn put(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u32).to_be_bytes());
    out.extend_from_slice(field);
}

pub(crate) fn put_u32(out: &mut Vec<u8>, n: usize) {
    out.extend_from_slice(&(n as u32).to_be_bytes());
}

/// Reads fields in turn. `what` names the string in errors ("the
/// invitation is cut short").
pub(crate) struct Reader<'a> {
    pub(crate) rest: &'a [u8],
    what: &'static str,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8], what: &'static str) -> Self {
        Self { rest: bytes, what }
    }

    pub(crate) fn garbled(&self) -> String {
        format!("the {} is garbled", self.what)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.rest.len() < n {
            return Err(format!("the {} is cut short", self.what));
        }
        let (head, rest) = self.rest.split_at(n);
        self.rest = rest;
        Ok(head)
    }

    pub(crate) fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    pub(crate) fn bytes(&mut self) -> Result<&'a [u8], String> {
        let n = self.u32()? as usize;
        self.take(n)
    }

    pub(crate) fn string(&mut self) -> Result<String, String> {
        let garbled = self.garbled();
        String::from_utf8(self.bytes()?.to_vec()).map_err(|_| garbled)
    }
}
