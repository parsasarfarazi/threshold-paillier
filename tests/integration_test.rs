#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigInt;

    #[test]
    fn test_full_workflow() {
        let (shares, pk) = ThresholdPaillier::new(512, 1, 5, 3).unwrap();
        let twelve = BigInt::from(12);
        let twenty_five = BigInt::from(25);

        let (enc_twelve, zk) = pk.encrypt_with_proof(&twelve).unwrap();
        zk.verify(&pk, &enc_twelve).unwrap();
        let (enc_twenty_five, zk) = pk.encrypt_with_proof(&twenty_five).unwrap();

        let sum = pk.add(&[enc_twelve, enc_twenty_five]).unwrap();

        let mut decrypt_shares = Vec::new();
        for share in &shares.key_shares {
            let (ds, zk) = share.partial_decrypt_with_proof(&sum).unwrap();
            zk.verify(&pk, &sum, &ds).unwrap();
            decrypt_shares.push(ds);
        }

        let decrypted = pk.combine_shares(&decrypt_shares).unwrap();
        assert_eq!(decrypted, BigInt::from(37), "decryption failed");
    }
}
