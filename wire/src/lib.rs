//! The byte layout that raft5fs's records share: numbers are big-endian
//! and fixed width, and a variable field is a u32 length and then its
//! bytes, so no field can run into the next.
//!
//! - `put_*` append a field to a buffer.
//! - `Reader` reads fields back in order. Each read fails, and does not
//!   panic, on input that is too short. `finish` fails on input left over.
//! - A `Reader` is named for what it reads (`what`), so its `Error` says
//!   what was cut short or garbled. Each crate turns that into its own
//!   error type.

use std::fmt;

/// A record could not be read: it ended too soon (`short`), or held
/// something that doesn't belong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error {
    pub what: &'static str,
    pub short: bool,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let how = if self.short { "cut short" } else { "garbled" };
        write!(f, "the {} is {how}", self.what)
    }
}

impl std::error::Error for Error {}

/// For callers that report errors as text.
impl From<Error> for String {
    fn from(e: Error) -> Self {
        e.to_string()
    }
}

pub fn put_u8(out: &mut Vec<u8>, n: u8) {
    out.push(n);
}

pub fn put_u16(out: &mut Vec<u8>, n: u16) {
    out.extend_from_slice(&n.to_be_bytes());
}

pub fn put_u32(out: &mut Vec<u8>, n: u32) {
    out.extend_from_slice(&n.to_be_bytes());
}

pub fn put_u64(out: &mut Vec<u8>, n: u64) {
    out.extend_from_slice(&n.to_be_bytes());
}

/// Appends a variable field: its length, then its bytes.
pub fn put_bytes(out: &mut Vec<u8>, field: &[u8]) {
    put_u32(out, field.len() as u32);
    out.extend_from_slice(field);
}

/// A number in as few bytes as it needs (LEB128): seven bits a byte, low
/// bits first, the top bit set on every byte but the last.
pub fn put_varint(out: &mut Vec<u8>, mut n: u64) {
    loop {
        let byte = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// A variable field whose length is a varint (`put_varint`).
pub fn put_short_bytes(out: &mut Vec<u8>, field: &[u8]) {
    put_varint(out, field.len() as u64);
    out.extend_from_slice(field);
}

/// Reads fields in the order they were put.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    rest: &'a [u8],
    what: &'static str,
}

impl<'a> Reader<'a> {
    /// A reader of `bytes`, a record of the kind `what` names.
    pub fn new(bytes: &'a [u8], what: &'static str) -> Self {
        Self { rest: bytes, what }
    }

    /// The error for a record that holds something that doesn't belong, for
    /// checks of the caller's own.
    pub fn garbled(&self) -> Error {
        Error {
            what: self.what,
            short: false,
        }
    }

    /// What is not read yet.
    pub fn rest(&self) -> &'a [u8] {
        self.rest
    }

    pub fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    /// The next `n` bytes.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let Some((head, rest)) = self.rest.split_at_checked(n) else {
            return Err(Error {
                what: self.what,
                short: true,
            });
        };
        self.rest = rest;
        Ok(head)
    }

    /// The next `N` bytes, as an array.
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        Ok(self.take(N)?.try_into().expect("take gives N bytes"))
    }

    pub fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.array::<1>()?[0])
    }

    pub fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    pub fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    pub fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    /// A variable field that `put_bytes` wrote.
    pub fn bytes(&mut self) -> Result<&'a [u8], Error> {
        let n = self.u32()? as usize;
        self.take(n)
    }

    /// What `put_varint` wrote. Fails on more than ten bytes.
    pub fn varint(&mut self) -> Result<u64, Error> {
        let mut n = 0u64;
        for shift in (0..64).step_by(7) {
            let b = self.u8()?;
            n |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Ok(n);
            }
        }
        Err(self.garbled())
    }

    /// What `put_short_bytes` wrote.
    pub fn short_bytes(&mut self) -> Result<&'a [u8], Error> {
        let n = usize::try_from(self.varint()?).map_err(|_| self.garbled())?;
        self.take(n)
    }

    /// A variable field that holds UTF-8 text.
    pub fn string(&mut self) -> Result<String, Error> {
        let garbled = self.garbled();
        String::from_utf8(self.bytes()?.to_vec()).map_err(|_| garbled)
    }

    /// Checks that nothing is left over.
    pub fn finish(self) -> Result<(), Error> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(self.garbled())
        }
    }
}

/// `bytes` in lower-case hex.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The bytes that `text` holds in hex, in either case; `None` if it isn't
/// hex.
pub fn from_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn varints_round_trip_and_stay_short() {
        let mut out = Vec::new();
        for n in [0u64, 1, 127, 128, 300, u64::MAX] {
            put_varint(&mut out, n);
        }
        assert_eq!(&out[..5], &[0, 1, 0x7f, 0x80, 0x01]);
        let mut r = Reader::new(&out, "varints");
        for n in [0u64, 1, 127, 128, 300, u64::MAX] {
            assert_eq!(r.varint().unwrap(), n);
        }
        r.finish().unwrap();
        assert!(Reader::new(&[0x80; 11], "too long").varint().is_err());
        let mut s = Vec::new();
        put_short_bytes(&mut s, b"word");
        assert_eq!(s, b"\x04word");
        assert_eq!(Reader::new(&s, "short").short_bytes().unwrap(), b"word");
    }

    use super::*;

    #[test]
    fn fields_read_back_in_order() {
        let mut out = Vec::new();
        put_u8(&mut out, 7);
        put_u16(&mut out, 0x0102);
        put_u32(&mut out, 3);
        put_u64(&mut out, 4);
        put_bytes(&mut out, b"name");
        let mut r = Reader::new(&out, "test record");
        assert_eq!(r.u8(), Ok(7));
        assert_eq!(r.u16(), Ok(0x0102));
        assert_eq!(r.u32(), Ok(3));
        assert_eq!(r.u64(), Ok(4));
        assert_eq!(r.string().as_deref(), Ok("name"));
        r.finish().unwrap();
    }

    #[test]
    fn short_or_left_over_input_is_an_error_that_says_what() {
        let mut r = Reader::new(&[0, 0, 0, 5, 1], "test record");
        let e = r.bytes().unwrap_err();
        assert!(e.short);
        assert_eq!(e.to_string(), "the test record is cut short");
        let r = Reader::new(&[1], "test record");
        assert_eq!(
            r.finish().unwrap_err().to_string(),
            "the test record is garbled"
        );
        let mut bad = Vec::new();
        put_bytes(&mut bad, &[0xff, 0xfe]);
        assert!(!Reader::new(&bad, "x").string().unwrap_err().short);
    }

    #[test]
    fn hex_round_trips() {
        assert_eq!(hex(&[0, 0xab, 0x10]), "00ab10");
        assert_eq!(from_hex("00AB10"), Some(vec![0, 0xab, 0x10]));
        assert_eq!(from_hex("abc"), None);
        assert_eq!(from_hex("zz"), None);
    }
}
