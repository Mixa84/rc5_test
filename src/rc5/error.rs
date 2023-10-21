use std::fmt;

#[derive(Debug, PartialEq, Eq)]
pub enum RC5Error{
    UnsupportedWordSize,
    UnsupportedKeyLength,
    InvalidPhraseSize,
}

impl fmt::Display for RC5Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            RC5Error::InvalidPhraseSize => {
                write!(f, "Size of phrase param is invalid, must be two times the word size!")
            },
            RC5Error::UnsupportedWordSize => {
                write!(f, "Currently only 32bit word size is supported!")
            },
            RC5Error::UnsupportedKeyLength => {
                write!(f, "Secret key too long!")
            },
        }
    }
}

impl std::error::Error for RC5Error {}