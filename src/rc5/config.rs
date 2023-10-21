use crate::rc5::error;

#[derive(Debug, Clone)]
pub struct RC5Config {
    pub word_size : u8,
    pub number_of_rounds : u8,
    pub bytes_in_key : u8,
    pub word_in_key : u8,
    pub bytes_in_word : usize,
}

impl RC5Config {
    pub fn new(word_size : &u8, number_of_rounds : &u8, bytes_in_key : &u8) -> Result<Self, error::RC5Error> {
        if *word_size != 32 {
            return Err(error::RC5Error::UnsupportedWordSize);
        }
        let word_in_key = bytes_in_key / (word_size / 8);
        let bytes_in_word = (word_size / 8) as usize;

        Ok(Self {
            word_size : *word_size ,
            number_of_rounds : *number_of_rounds ,
            bytes_in_key : *bytes_in_key ,
            word_in_key,
            bytes_in_word,
        })
    }
}

#[cfg(test)]
mod tests {
	use super::*;

    #[test]
    fn invalid_config() {
        assert_eq!(error::RC5Error::UnsupportedWordSize, RC5Config::new(&64, &12, &16).unwrap_err());
        assert_eq!(error::RC5Error::UnsupportedWordSize, RC5Config::new(&16, &12, &16).unwrap_err());
    }
}