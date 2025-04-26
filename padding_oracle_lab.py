# Padding Oracle Attack Lab
# Author: Giorgi Kordzaia

from binascii import unhexlify, hexlify
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK_SIZE = 16  # AES block size is 16 bytes
KEY = b"this_is_16_bytes"

CIPHERTEXT_HEX = (
    "746869735f69735f31365f6279746573"
    "9404628dcdf3f003482b3b0648bd920b"
    "3f60e13e89fa6950d3340adbbbb41c12"
    "b3d1d97ef97860e9df7ec0d31d13839a"
    "e17b3be8f69921a07627021af16430e1"
)

# --- Task 1: Theory Answers ---
"""
1. How does padding_oracle check padding?
   -> It decrypts the ciphertext and tries to unpad it using PKCS#7. If no error, padding is valid.

2. Purpose of IV in CBC mode?
   -> IV ensures even identical plaintext encrypts differently, adding randomness.

3. Why must ciphertext be multiple of block size?
   -> Because AES operates block-by-block (16 bytes); incomplete blocks cause decryption failure.
"""

# --- Provided Function ---
def padding_oracle(ciphertext: bytes) -> bool:
    if len(ciphertext) % BLOCK_SIZE != 0:
        return False
    try:
        iv = ciphertext[:BLOCK_SIZE]
        ct = ciphertext[BLOCK_SIZE:]
        cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ct) + decryptor.finalize()

        unpadder = padding.PKCS7(BLOCK_SIZE * 8).unpadder()
        unpadder.update(decrypted)
        unpadder.finalize()
        return True
    except (ValueError, TypeError):
        return False

# --- Task 2: Block splitting ---
def split_blocks(data: bytes, block_size: int = BLOCK_SIZE) -> list[bytes]:
    """Split data into blocks of the specified size."""
    return [data[i:i+block_size] for i in range(0, len(data), block_size)]

# --- Task 3: Decrypt single block ---
def decrypt_block(prev_block: bytes, target_block: bytes) -> bytes:
    """Decrypt a single block using the padding oracle attack."""
    intermediate = [0] * BLOCK_SIZE
    recovered = bytearray(BLOCK_SIZE)

    for pad in range(1, BLOCK_SIZE + 1):
        for guess in range(256):
            prefix = b'\x00' * (BLOCK_SIZE - pad)
            guessed_byte = bytes([guess])
            modified = bytearray(prefix + guessed_byte)

            for j in range(1, pad):
                modified[-j] = intermediate[-j] ^ pad

            fake_block = bytearray(BLOCK_SIZE)
            for i in range(BLOCK_SIZE):
                fake_block[i] = modified[i] ^ prev_block[i]

            crafted = fake_block + target_block

            if padding_oracle(crafted):
                intermediate[-pad] = guess ^ pad
                recovered[-pad] = intermediate[-pad] ^ prev_block[-pad]
                break

    return bytes(recovered)

# --- Task 4: Full attack ---
def padding_oracle_attack(ciphertext: bytes) -> bytes:
    """Perform the padding oracle attack on the entire ciphertext."""
    blocks = split_blocks(ciphertext)
    iv = blocks[0]
    cipher_blocks = blocks[1:]

    recovered_plaintext = b''

    for i in range(len(cipher_blocks)):
        prev = iv if i == 0 else cipher_blocks[i-1]
        target = cipher_blocks[i]
        plaintext_block = decrypt_block(prev, target)
        recovered_plaintext += plaintext_block

    return recovered_plaintext

# --- Task 5: Unpad and decode ---
def unpad_and_decode(plaintext: bytes) -> str:
    """Attempt to unpad and decode the plaintext."""
    try:
        unpadder = padding.PKCS7(BLOCK_SIZE * 8).unpadder()
        unpadded = unpadder.update(plaintext) + unpadder.finalize()
        return unpadded.decode('utf-8')
    except Exception as e:
        return f"[!] Decoding failed: {e}"

# --- Main Execution ---
if __name__ == "__main__":
    try:
        ciphertext = unhexlify(CIPHERTEXT_HEX)
        print(f"[*] Ciphertext length: {len(ciphertext)} bytes")
        print(f"[*] IV: {ciphertext[:BLOCK_SIZE].hex()}")

        recovered = padding_oracle_attack(ciphertext)

        print("\n[+] Decryption complete!")
        print(f" Recovered plaintext (raw bytes): {recovered}")
        print(f" Hex: {recovered.hex()}")

        decoded = unpad_and_decode(recovered)
        print("\nFinal plaintext:")
        print(decoded)

    except Exception as e:
        print(f"\n[!] Error occurred: {e}")
