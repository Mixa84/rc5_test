use std::convert::TryInto;
use std::error::Error;

pub mod error;
pub mod config;

const P: u32 = 0xb7e15163;
const Q: u32 = 0x9e3779b9;

use config::RC5Config;
use error::RC5Error;

#[derive(Debug, Clone)]
pub struct RC5 {
    config : config::RC5Config,
    table_size : usize,
    table : Vec<u32>,
}

impl RC5 {
    pub fn new(config: RC5Config, key : Vec<u8>) -> Result<Self, Box<dyn Error>> {
        let table_size : usize = 2 * (config.number_of_rounds as usize + 1);
        let mut rc5 = Self {
            config,
            table_size,
            table : vec!(0; table_size),
        };

        rc5.setup(key)?;

        Ok(rc5)
    }
    pub fn setup(&mut self, key: Vec<u8>) -> Result<(), Box<dyn Error>> {
        if key.len() != self.config.bytes_in_key as usize{
            return Err(Box::new(RC5Error::UnsupportedKeyLength));
        }
        let mut l : Vec<u32> = vec!(0; self.config.word_in_key as usize);

        for idx in (0..self.config.bytes_in_key as usize).rev() {
            l[idx / self.config.bytes_in_word] = (l[idx / self.config.bytes_in_word] << 8) + (key[idx] as u32);
        }

        self.table[0] = P;
        for idx in 1..self.table_size {
            self.table[idx] = self.table[idx - 1].wrapping_add(Q);
        }

        let (mut a, mut b, mut i, mut j) = (0, 0, 0 ,0);

        for _idx in 0..self.table_size * 3 {
            self.table[i] = self.table[i].wrapping_add(a).wrapping_add(b).rotate_left(3);
            a = self.table[i];

            l[j] = l[j].wrapping_add(a).wrapping_add(b).rotate_left(a.wrapping_add(b));
            b = l[j];

            i = (i + 1) % self.table_size;
            j = (j + 1) % self.config.word_in_key as usize;
        }

        Ok(())
    }

    pub fn encrypt(& self, plain_text : Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
        if plain_text.len() != self.config.bytes_in_word * 2 {
            return Err(Box::new(RC5Error::InvalidPhraseSize));
        }

        let mut a = u32::from_ne_bytes(plain_text[0..self.config.bytes_in_word].try_into()?).wrapping_add(self.table[0]);
        let mut b = u32::from_ne_bytes(plain_text[self.config.bytes_in_word..plain_text.len()].try_into()?).wrapping_add(self.table[1]);

        for idx in 1..(self.config.number_of_rounds + 1) as usize {
            a = (a ^ b).rotate_left(b).wrapping_add(self.table[2 * idx]);
            b = (b ^ a).rotate_left(a).wrapping_add(self.table[2 * idx + 1]);
        }

        let mut cipher_text : Vec<u8> = Vec::new();
        cipher_text.extend(u32::to_ne_bytes(a));
        cipher_text.extend(u32::to_ne_bytes(b));

        Ok(cipher_text)
    }

    pub fn decrypt(& self, cipher_text : Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
        if cipher_text.len() != self.config.bytes_in_word * 2 {
            return Err(Box::new(RC5Error::InvalidPhraseSize));
        }

        let mut a = u32::from_ne_bytes(cipher_text[0..self.config.bytes_in_word].try_into()?);
        let mut b = u32::from_ne_bytes(cipher_text[self.config.bytes_in_word..cipher_text.len()].try_into()?);

        for idx in (1..(self.config.number_of_rounds + 1) as usize).rev() {
            b = b.wrapping_sub(self.table[2 * idx + 1]).rotate_right(a) ^ a;
            a = a.wrapping_sub(self.table[2 * idx]).rotate_right(b) ^ b;
        }

        let mut plain_text : Vec<u8> = Vec::new();
        plain_text.extend(u32::to_ne_bytes(a.wrapping_sub(self.table[0])));
        plain_text.extend(u32::to_ne_bytes(b.wrapping_sub(self.table[1])));

        Ok(plain_text)
    }
}

#[cfg(test)]
mod tests {
	use super::*;

    fn setup_tests(key : Vec<u8>, number_of_rounds : u8, bytes_in_key : u8) -> Result<RC5, Box<dyn Error>> {
        let config = RC5Config::new(&32, &number_of_rounds, &bytes_in_key)?;
        let rc5 = RC5::new(config, key)?;

        Ok(rc5)
    }

    #[test]
    fn encrypt_decrypt_32_12_16() -> Result<(), Box<dyn Error>> {
    	let key = vec![0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81, 0xFF, 0x48];
    	let pt  = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
    	let ct  = vec![0x11, 0xE4, 0x3B, 0x86, 0xD2, 0x31, 0xEA, 0x64];
        let rc5 = setup_tests(key, 12, 16)?;

        let res = rc5.encrypt(pt)?;
        assert!(&ct[..] == &res[..]);

    	let pt  = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
        let res = rc5.decrypt(ct)?;
        assert!(&pt[..] == &res[..]);

        Ok(())
    }

    #[test]
    fn encrypt_decrypt_32_12_16_2() -> Result<(), Box<dyn Error>> {
    	let key = vec![0x91, 0x5F, 0x46, 0x19, 0xBE, 0x41, 0xB2, 0x51, 0x63, 0x55, 0xA5, 0x01, 0x10, 0xA9, 0xCE, 0x91];
    	let pt  = vec![0x21, 0xA5, 0xDB, 0xEE, 0x15, 0x4B, 0x8F, 0x6D];
    	let ct  = vec![0xF7, 0xC0, 0x13, 0xAC, 0x5B, 0x2B, 0x89, 0x52];
        let rc5 = setup_tests(key, 12, 16)?;

        let res = rc5.encrypt(pt)?;
        assert!(&ct[..] == &res[..]);

    	let pt  = vec![0x21, 0xA5, 0xDB, 0xEE, 0x15, 0x4B, 0x8F, 0x6D];
        let res = rc5.decrypt(ct)?;
        assert!(&pt[..] == &res[..]);

        Ok(())
    }

    #[test]
    fn encrypt_decrypt_32_20_16() -> Result<(), Box<dyn Error>> {
    	let key = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
    	let pt  = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    	let ct  = vec![0x2A, 0x0E, 0xDC, 0x0E, 0x94, 0x31, 0xFF, 0x73];
        let rc5 = setup_tests(key, 20, 16)?;

        let res = rc5.encrypt(pt)?;
        assert!(&ct[..] == &res[..]);

    	let pt  = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let res = rc5.decrypt(ct)?;
        assert!(&pt[..] == &res[..]);

        Ok(())
    }

    #[test]
    fn invalid_config() {
        let config = RC5Config::new(&32, &12, &16).unwrap();
    	let key15 = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E];
    	let key17 = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];

        let err = RC5::new(config.clone(), key15).err().unwrap().downcast::<RC5Error>().unwrap();
        assert_eq!(*err, RC5Error::UnsupportedKeyLength);

        let err = RC5::new(config.clone(), key17).err().unwrap().downcast::<RC5Error>().unwrap();
        assert_eq!(*err, RC5Error::UnsupportedKeyLength);

    	let key = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        let rc5 = RC5::new(config.clone(), key).unwrap();

        let phrase : Vec<u8> = Vec::new();
        let err = rc5.encrypt(phrase).err().unwrap().downcast::<RC5Error>().unwrap();
        assert_eq!(*err, RC5Error::InvalidPhraseSize);

        let phrase = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let err = rc5.encrypt(phrase).err().unwrap().downcast::<RC5Error>().unwrap();
        assert_eq!(*err, RC5Error::InvalidPhraseSize);

        let phrase = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let err = rc5.encrypt(phrase).err().unwrap().downcast::<RC5Error>().unwrap();
        assert_eq!(*err, RC5Error::InvalidPhraseSize);
    }
}