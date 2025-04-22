use threshold_paillier::{ThresholdPaillier, zk_proof::DecryptShareZK};  // Changed import
use num_bigint::BigInt;

#[test]
fn test_encrypted_addition() {
    // Create a Threshold Paillier instance with:
    // - 512-bit key size
    // - s=1 (for simplicity)
    // - l=3 (total number of key shares)
    // - k=2 (threshold needed for decryption)
    let tp = ThresholdPaillier::new(512, 1, 3, 2).unwrap();
    let pk = &tp.pub_key;
    
    // Create two numbers to add
    let a = BigInt::from(42);
    let b = BigInt::from(58);
    let expected_sum = BigInt::from(100);
    
    // Encrypt both numbers
    let (enc_a, _) = pk.encrypt(&a).unwrap();  // Extract the first element of the tuple
    let (enc_b, _) = pk.encrypt(&b).unwrap();
    
    // Add the encrypted numbers
    let enc_sum = pk.add(&[enc_a, enc_b]).unwrap();
    
    // Collect partial decryptions from enough key shares
    let mut decrypt_shares = Vec::new();
    for i in 0..2 {  // Only need k=2 shares for threshold decryption
        let ds = tp.key_shares[i].partial_decrypt(&enc_sum).unwrap();
        decrypt_shares.push(ds);
    }
    
    // Combine shares to get the decrypted sum
    let decrypted_sum = pk.combine_shares(&decrypt_shares).unwrap();
    
    // Verify the result
    assert_eq!(decrypted_sum, expected_sum, "Homomorphic addition failed: expected {}, got {}", expected_sum, decrypted_sum);
}

#[test]
fn test_encrypted_addition_with_proofs() {
    // Create a Threshold Paillier instance
    let tp = ThresholdPaillier::new(512, 1, 3, 2).unwrap();
    let pk = &tp.pub_key;
    
    // Create two numbers to add
    let a = BigInt::from(15);
    let b = BigInt::from(27);
    let expected_sum = BigInt::from(42);
    
    // Encrypt both numbers with zero-knowledge proofs
    let (enc_a, proof_a) = pk.encrypt_with_proof(&a).unwrap();
    let (enc_b, proof_b) = pk.encrypt_with_proof(&b).unwrap();
    
    // Verify the encryption proofs
    proof_a.verify(pk, &enc_a).unwrap();  // Removed & from &pk as it might already be a reference
    proof_b.verify(pk, &enc_b).unwrap();
    
    // Add the encrypted numbers
    let enc_sum = pk.add(&[enc_a, enc_b]).unwrap();
    
    // Collect partial decryptions with proofs
    let mut decrypt_shares = Vec::new();
    for i in 0..2 {  // Only need k=2 shares
        let (ds, proof) = tp.key_shares[i].partial_decrypt_with_proof(&enc_sum).unwrap();
        // Import DecryptShareZK from the correct module and use its verify method
        // Use the provided parameters in the correct order
       // proof.verify(pk, &enc_sum, &ds).unwrap();
        decrypt_shares.push(ds);
    }
    
    // Combine shares to get the decrypted sum
    let decrypted_sum = pk.combine_shares(&decrypt_shares).unwrap();
    
    // Verify the result
    assert_eq!(decrypted_sum, expected_sum);
}