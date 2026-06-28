use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz Base58 decoding
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = scannerbtc::encoding::base58check_decode(s);
    }

    // Fuzz mnemonic validation
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = scannerbtc::bip39::validate_mnemonic(s);
    }

    // Fuzz address validation
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = scannerbtc::encoding::is_valid_btc_address(s);
    }
});
