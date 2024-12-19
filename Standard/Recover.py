import base64
import binascii
import json
import hashlib
from Crypto.Cipher import AES

# Load configuration from config.json
with open('config.json', 'r') as config_file:
    config = json.load(config_file)

# File paths and corresponding passwords
keyfile_paths = config['keyfile_paths']
passwords = config['passwords']

def derive_key_and_iv(password_bytes, salt, key_len, iv_len, hash_algorithm='md5', iterations=1):
    """
    Derives the key and IV using OpenSSL's EVP_BytesToKey method with iterations.
    """
    d = b''
    d_i = b''
    while len(d) < key_len + iv_len:
        d_i = hashlib.new(hash_algorithm, d_i + password_bytes + salt).digest()
        for _ in range(1, iterations):
            d_i = hashlib.new(hash_algorithm, d_i).digest()
        d += d_i
    key = d[:key_len]
    iv = d[key_len:key_len + iv_len]
    return key, iv

def unpad_pkcs7(data):
    """
    Removes PKCS7 padding.
    """
    pad_len = data[-1]
    if pad_len < 1 or pad_len > AES.block_size:
        print(f"Invalid padding length: {pad_len}")
        return data
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        print("Invalid PKCS7 padding.")
        return data
    return data[:-pad_len]

def try_unpad(data):
    """
    Attempts to unpad data using PKCS7.
    """
    return unpad_pkcs7(data)

# Phase 1: Identify the correct settings for decryption
for keyfile_path in keyfile_paths:
    print(f"\nProcessing key file: {keyfile_path} (IDENTIFY phase)")
    password = passwords.get(keyfile_path)
    if password is None:
        print(f"No password provided for {keyfile_path}. Skipping.")
        continue

    # Step 1: Clean and Decode Base64 Data
    try:
        with open(keyfile_path, 'r') as f:
            base64_content = f.read().replace('\n', '').replace('\r', '')

        decoded_content = base64.b64decode(base64_content)
    except Exception as e:
        print(f"Base64 decoding error: {str(e)}")
        continue

    # Step 2: Verify Salt and Encrypted Key
    if decoded_content.startswith(b'Salted__'):
        salt = decoded_content[8:16]
        encrypted_key = decoded_content[16:]
        print(f"Salt (hex): {binascii.hexlify(salt)}")
    else:
        print("No 'Salted__' header found. Cannot extract salt.")
        continue

    print(f"Encrypted key (hex): {binascii.hexlify(encrypted_key)}")

    # Try different password encodings
    encodings = [
        ('ASCII (ignore errors)', password.encode('ascii', errors='ignore')),
        ('UTF-8', password.encode('utf-8')),
        ('Latin-1', password.encode('latin-1', errors='ignore')),
        ('UTF-16LE', password.encode('utf-16le')),
        ('Char-to-byte casting', bytes([ord(c) & 0xFF for c in password])),
    ]

    success = False

    for encoding_name, password_bytes in encodings:
        for iterations in [1, 1024]:
            print(f"\nTrying password encoding: {encoding_name}, Iterations: {iterations}")
            # Step 3: Derive Key and IV
            hash_algorithm = 'md5'  # As per Java code
            key_len = 32  # 256 bits
            iv_len = 16   # 128 bits

            try:
                key, iv = derive_key_and_iv(password_bytes, salt, key_len, iv_len, hash_algorithm, iterations)
                print(f"Key (hex): {binascii.hexlify(key)}")
                print(f"IV (hex): {binascii.hexlify(iv)}")

                # Step 4: Decrypt using AES with CBC mode
                mode = AES.MODE_CBC
                print(f"Attempting decryption with mode: {mode}")
                cipher = AES.new(key, mode, iv)
                decrypted_data = cipher.decrypt(encrypted_key)
                print("Decrypted data (before unpadding):", binascii.hexlify(decrypted_data))
                print("Decrypted data (raw):", repr(decrypted_data))

                # Unpad the decrypted data
                unpadded_data = try_unpad(decrypted_data)
                print("Decrypted data (unpadded or raw):", repr(unpadded_data))

                # Check if decryption is likely successful
                if b'20' in unpadded_data and b'-' in unpadded_data:
                    print("Likely successful decryption.")
                    success = True
                    break
                elif any(32 <= byte <= 126 for byte in unpadded_data):
                    print("Decrypted data contains printable characters, possibly successful.")
                    success = True
                    break
                else:
                    print("Decrypted data does not contain expected patterns.")
                    success = False

            except Exception as e:
                print(f"Decryption error: {str(e)}")
                continue

        if success:
            break

    if not success:
        print("Decryption unsuccessful with all password encodings and iteration counts.")
        continue

    # Step 5: Output Full Decrypted Text
    try:
        with open(f'{keyfile_path}_decrypted.bin', 'wb') as f:
            f.write(unpadded_data)
        print(f"Decrypted key saved to {keyfile_path}_decrypted.bin\n")
    except Exception as e:
        print(f"Error writing decrypted data: {str(e)}\n")
