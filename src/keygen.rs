#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen() {
        let (pk, shares) = keygen(2, 3);
        assert_eq!(shares.len(), 3);
    }
}