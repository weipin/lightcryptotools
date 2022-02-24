use quickcheck::{Arbitrary, Gen};

#[derive(Debug)]
struct HexChar(u8);

impl Clone for HexChar {
    fn clone(&self) -> Self {
        HexChar(self.0.clone())
    }
}

const HEX_CHARS_BYTES: &[u8] = "0123456789abcdefABCDEF".as_bytes();
impl Arbitrary for HexChar {
    fn arbitrary(g: &mut Gen) -> Self {
        HexChar(*g.choose(HEX_CHARS_BYTES).unwrap())
    }
}

#[derive(Debug)]
pub(crate) struct HexString(pub(crate) String);

impl Clone for HexString {
    fn clone(&self) -> Self {
        HexString(self.0.clone())
    }
}

impl Arbitrary for HexString {
    fn arbitrary(g: &mut Gen) -> Self {
        use std::str::from_utf8;

        let mut v = Vec::<HexChar>::arbitrary(g);
        if v.len() == 0 {
            v.push(HexChar::arbitrary(g));
            v.push(HexChar::arbitrary(g));
        } else if v.len() & 1 != 0 {
            v.push(HexChar::arbitrary(g));
        }

        let v_char: Vec<u8> = v.iter().map(|x| x.0).collect();
        Self(String::from(from_utf8(&v_char).unwrap()))
    }
}

#[derive(Debug)]
pub(crate) struct BigIntHexString(pub(crate) String);

impl Clone for BigIntHexString {
    fn clone(&self) -> Self {
        BigIntHexString(self.0.clone())
    }
}

const SIGN_CHARS_BYTES: &[u8] = "+-".as_bytes();
impl Arbitrary for BigIntHexString {
    fn arbitrary(g: &mut Gen) -> Self {
        use std::str::from_utf8;

        let mut v = Vec::<HexChar>::arbitrary(g);
        if v.len() == 0 {
            v.push(HexChar::arbitrary(g));
            v.push(HexChar::arbitrary(g));
        } else if v.len() & 1 != 0 {
            v.push(HexChar::arbitrary(g));
        }

        let mut v_char: Vec<u8> = v.iter().map(|x| x.0).collect();
        let sign = *g.choose(SIGN_CHARS_BYTES).unwrap();
        v_char.insert(0, sign);
        Self(String::from(from_utf8(&v_char).unwrap()))
    }
}
