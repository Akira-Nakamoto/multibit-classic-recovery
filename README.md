# MultiBit Classic Recovery

MultiBit Classic Recovery is a tool designed to help users recover their Bitcoin wallets created with MultiBit Classic. 
This tool provides functionalities to decrypt wallet files, derive keys, and recover lost funds.

## Features
- Decrypt MultiBit Classic wallet files
- Derive keys and initialization vectors (IV) from passwords
- Remove PKCS7 padding from decrypted data
- Identify and process multiple key files

## Requirements
- Python 3.6 or higher
- `pycryptodome` library for cryptographic functions
- A MultiBit Classic wallet file (`.key`) and its password
- A Working MultiBit Classic wallet file (`.key`) and its password from 0.5.18 (Ubuntu 20.04 LTS used)

<hr>

- Notes:
    - Python 3.12.0 was used for development.
    - OpenSSL 3.0.2 15 Mar 2022 (Library: OpenSSL 3.0.2 15 Mar 2022) was used for development.
    - LibreSSL 2.8.3 was used for encryption and decryption in MultiBit Classic.
    - Decryption of a 0.5.18 wallet file was successful using the provided password for the current setup.

## Installation

Clone the repository:
```bash
git clone <repository_url>
```

Install the required Python packages:
```bash
pip install -r requirements.txt
```

## Usage

Prepare a `config.json` file with the following structure:
```json
{
    "key_files": ["path/to/keyfile1", "path/to/keyfile2"],
    "passwords": ["password1", "password2"]
}
```

Run the recovery script:
```bash
python recover.py
```

Follow the on-screen instructions to process the key files and recover your wallet.

## Configuration

The `config.json` file should contain the paths to your key files and the corresponding passwords. Ensure that the paths and passwords are correct to successfully decrypt and recover your wallet.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your changes.

## License

This project is licensed under the CC0 License. See the LICENSE file for details.

## Disclaimer

This tool is provided as-is without any guarantees. Use it at your own risk. The authors are not responsible for any loss of funds or data. Always back up your wallet files and passwords securely.

## Known Issues

| Issue | Summary | Problem | Solution |
|-------|---------|---------|----------|
| Password Recognition | Users may encounter issues where the correct password is not accepted. | Correct password fails to decrypt, leading to "Provided AES key is wrong" errors. | Try multiple encodings (UTF-8, UTF-16) and apply transformations (e.g., MD5) before PBKDF2. |
| Key Derivation | Key derivation takes a password and salt as input to generate the AES key and IV. | Key derivation logic differs due to LibreSSL 2.8.3 quirks. | Use PBKDF2 (SHA-256) and test with MD5-based KDFs. Test variations in iteration counts (1000, 1) and modify key/IV splitting logic. |
| Multiple Encryption Layers | The wallet may be double-encrypted, meaning the initial encrypted key is encrypted again. | Double encryption may exist. | Apply recursive decryption, treating the output of the first decryption as the new ciphertext. Re-derive key/IV and decrypt again. |
| Entropy Analysis | Entropy is used to measure decryption success. | Entropy measures decryption progress. | Check entropy after decryption. If high, recursively decrypt. If 3.5-4.0, extract the private key. |
| File Structure and Format | The .key file follows a specific format where the first 16 bytes are the "Salted__" header (8 bytes) plus 8 bytes of salt. | File inconsistencies may exist. | Extract salt (bytes 8-16) and derive the key/IV using KDF logic. Ensure proper alignment of ciphertext blocks. If padding errors occur, shift ciphertext alignment by 1-15 bytes and retry. |
| Use of LibreSSL 2.8.3 | MultiBit relies on LibreSSL 2.8.3, which may use non-standard KDF logic, affecting how PBKDF2 is processed. | Older LibreSSL 2.8.3 may use different encryption/KDF logic. | Use PBKDF2 with SHA-256, MD5-based KDFs, and concatenation logic. Test 1 and 1000 iterations for KDF. |
| Possible File Corruption or Misalignment | Misaligned ciphertext blocks prevent AES decryption from working correctly. | Misaligned ciphertext may cause decryption failure. | Shift ciphertext alignment by 1-15 bytes and retry. Analyze entropy for each alignment to identify the correct alignment. |
| Inconsistent Iteration Count (1 vs 1000) | In some cases, the PBKDF2 function may have been configured to use only 1 iteration instead of 1000, causing incorrect key/IV derivation. | LibreSSL 2.8.3 might use 1 iteration instead of 1000 iterations for PBKDF2. | Use both iteration counts (1 and 1000) in decryption attempts. If the key/IV derived with 1000 iterations fails, retry decryption using the key/IV derived from 1 iteration. |

## How it Works

### Extract Salt:
```python
salt = file[8:16]
```

### Key Derivation:
```python
key_iv = PBKDF2_sha256(password, salt, 1000)
key = key_iv_1000[0:32]
iv = key_iv_1000[32:48]
```

### AES Decryption:
```python
decrypted = AES_256_CBC(key, iv, ciphertext)
```

### Entropy Analysis:
```python
H(X) = -∑(p(x) * log2(p(x)))
# Entropy 3.5-4.0 = plaintext, Entropy ≈8.0 = encrypted.
```

### Private Key Extraction:
```python
# Extract 32-byte private key from decrypted data.
```

### Public Key Validation:
```python
# Derive public key from the private key using secp256k1.
```

### Recursive Decryption:
```python
# If entropy ≈8.0, re-decrypt using same or adjusted key/IV.
```

### File Alignment:
```python
# Shift ciphertext alignment by 1-15 bytes and retry.
```

## Sample Output:
```python
Processing key file: Check.key (IDENTIFY phase)
Salt (hex): b'72aa975c73b16680'
Encrypted key (hex): b'1f7af979e42afdcd59d2f4ac71db14085b463abe2f6e5a8e6f56338b25283a6f7b93805658161660efd9ce89a9694fa3babf6d5e8902f1352369245a77476b7471ba07c8b75a2ccffa30de2d76357eac'

Trying password encoding: ASCII (ignore errors), Iterations: 1
Key (hex): b'6836141c1d9f86e953b071d0da9d03b5694484ce86845a74c171501f2d9481b5'
IV (hex): b'910328461e5e35c1954c5d08958a6790'
Attempting decryption with mode: 2
Decrypted data (before unpadding): b'4b7774483763324d766732366e463556706978766655534d5553513369316f4578445163614d59704b6b676a715839564c614e7020323031342d31322d32355430353a34353a35335a0a060606060606'
Decrypted data (raw): b'KwtH7c2Mvg26nF5VpixvfUSMUSQ3i1oExDQcaMYpKkgjqX9VLaNp 2014-12-25T05:45:53Z\n\x06\x06\x06\x06\x06\x06'
Decrypted data (unpadded or raw): b'KwtH7c2Mvg26nF5VpixvfUSMUSQ3i1oExDQcaMYpKkgjqX9VLaNp 2014-12-25T05:45:53Z\n'
Likely successful decryption.
Decrypted key saved to Check.key_decrypted.bin


Processing key file: multibit.key (IDENTIFY phase)
Salt (hex): b'An 8 byte salt'
Encrypted key (hex): b'An encrypted key of 64 bytes'

Trying password encoding: ASCII (ignore errors), Iterations: 1
Key (hex): b'A derived key of 32 bytes'
IV (hex): b'A derived IV of 16 bytes'
Attempting decryption with mode: 2
Decrypted data (before unpadding): b'A decrypted data of 64 bytes'
Decrypted data (raw): b'CENSORED \xd2\xf7W\x0e"\x9cj@\x83H5 An example of invalid padding length: 49 (misalignment)'
Invalid padding length: 49
Decrypted data (unpadded or raw): b'CENSORED \xd2\xf7W\x0e"\x9cj@\x83H5 An example of invalid padding length: 49 (misalignment)'
Decrypted data contains printable characters, possibly successful.
Decrypted key saved to multibit.key_decrypted.bin
```
