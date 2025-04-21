use num_bigint::BigInt;

#[derive(Debug, Clone)]
pub struct DecryptionShare {
    pub index: u8,
    pub ci: BigInt,
}
