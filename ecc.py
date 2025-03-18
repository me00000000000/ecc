#!/usr/bin/env python3

import argparse
import base64
import os
import sys
import hashlib
from nacl.signing import SigningKey, VerifyKey
from nacl.bindings import crypto_scalarmult
from Crypto.Cipher import AES
from Crypto.Util import Counter
from argon2.low_level import hash_secret_raw, Type

def generate_keys(private_key_file):
    while True:
        sk = SigningKey.generate()
        vk = sk.verify_key
        pub_bytes = vk.encode()
        pub_b64 = base64.b64encode(pub_bytes).decode('ascii').rstrip("=")
        if ("+" not in pub_b64) and ("/" not in pub_b64):
            break

    priv_bytes = sk.encode()
    if private_key_file == False:
        private_key_file = pub_b64[:11].translate(str.maketrans("+/", "-_")) + ".priv"
    with open(private_key_file, 'wb') as f:
        f.write(priv_bytes)
    print("Public key: ", end="")
    print(pub_b64)
    print(f"Private key saved to {private_key_file}")

def load_public_key(b64_pub):
    missing_padding = len(b64_pub) % 4
    if missing_padding:
        b64_pub += '=' * (4 - missing_padding)
    pub_bytes = base64.b64decode(b64_pub)
    if len(pub_bytes) != 32:
        raise ValueError("Invalid public key format")
    return VerifyKey(pub_bytes)

def load_private_key_file(private_key_file):
    with open(private_key_file, 'rb') as f:
        priv_bytes = f.read()
    return SigningKey(priv_bytes)

def derive_shared_key(priv_signing, peer_verify):
    x25519_priv = priv_signing.to_curve25519_private_key()
    x25519_peer = peer_verify.to_curve25519_public_key()
    shared = crypto_scalarmult(x25519_priv.encode(), x25519_peer.encode())
    h = hashlib.sha256(shared).digest()
    return h[:16]

def argon2id_kdf(key_material, salt, hash_len=16):
    return hash_secret_raw(secret=key_material, salt=salt, time_cost=2,
                           memory_cost=1048576, parallelism=1, hash_len=hash_len, type=Type.ID)

def encrypt_file(recipient_b64, infile, outfile):
    recipient_vk = load_public_key(recipient_b64)
    eph_sk = SigningKey.generate()
    eph_vk = eph_sk.verify_key
    shared_key = derive_shared_key(eph_sk, recipient_vk)
    salt = os.urandom(16)
    final_key = argon2id_kdf(shared_key, salt, hash_len=16)
    if infile:
        with open(infile, 'rb') as f:
            plaintext = f.read()
    else:
        plaintext = sys.stdin.buffer.read()
    nonce = os.urandom(8)
    ctr = Counter.new(64, prefix=nonce, initial_value=0)
    cipher = AES.new(final_key, AES.MODE_CTR, counter=ctr)
    ciphertext = cipher.encrypt(plaintext)
    eph_pub_bytes = eph_vk.encode()
    outdata = eph_pub_bytes + salt + nonce + ciphertext
    outdata_b64 = base64.b64encode(outdata).decode('ascii').rstrip("=")
    if outfile:
        with open(outfile, 'w') as f:
            f.write(outdata_b64)
        print(f"Encryption complete. Output written to {outfile}")
    else:
        sys.stdout.write(outdata_b64)

def decrypt_file(private_key_file, infile, outfile):
    sk = load_private_key_file(private_key_file)
    vk = sk.verify_key
    if infile:
        with open(infile, 'r') as f:
            b64_data = f.read()
    else:
        b64_data = sys.stdin.read()
    missing_padding = len(b64_data) % 4
    if missing_padding:
        b64_data += '=' * (4 - missing_padding)
    data = base64.b64decode(b64_data)
    if len(data) < 32 + 16 + 8:
        raise ValueError("Input file too short or corrupted")
    eph_pub_bytes = data[:32]
    eph_vk = VerifyKey(eph_pub_bytes)
    salt = data[32:32+16]
    nonce = data[32+16:32+16+8]
    ciphertext = data[32+16+8:]
    shared_key = derive_shared_key(sk, eph_vk)
    final_key = argon2id_kdf(shared_key, salt, hash_len=16)
    ctr = Counter.new(64, prefix=nonce, initial_value=0)
    cipher = AES.new(final_key, AES.MODE_CTR, counter=ctr)
    plaintext = cipher.decrypt(ciphertext)
    if outfile:
        with open(outfile, 'wb') as f:
            f.write(plaintext)
        print(f"Decryption complete. Output written to {outfile}")
    else:
        sys.stdout.buffer.write(plaintext)

def generate_public(private_key_file):
    sk = load_private_key_file(private_key_file)
    vk = sk.verify_key
    pub_b64 = base64.b64encode(vk.encode()).decode('ascii').rstrip("=")
    print("Exactracted public key: ", end="")
    print(pub_b64)

def main():
    parser = argparse.ArgumentParser(
        description="Ed25519 key generation and ECIES-like encryption/decryption X25519 with Argon2id KDF."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-g", "--generate", action="store_true")
    group.add_argument("-r", "--recipient", type=str)
    group.add_argument("-k", "--private", type=str)
    group.add_argument("-p", "--public", type=str)
    parser.add_argument("-i", "--infile", type=str)
    parser.add_argument("-o", "--outfile", type=str)
    parser.add_argument("-f", "--force", action="store_true")
    args = parser.parse_args()
    if args.generate:
        if not args.outfile:
            args.outfile = False
        if not args.force and args.outfile != False:
            if os.path.exists(args.outfile):
                print("Output file exists. Use -f to overwrite", file=sys.stderr)
                sys.exit(1)
        generate_keys(args.outfile)
    elif args.recipient:
        if not args.infile and sys.stdin.isatty():
            print("Encryption mode requires input", file=sys.stderr)
            sys.exit(1)
        infile = args.infile if args.infile else None
        encrypt_file(args.recipient, infile, args.outfile)
    elif args.private:
        if not args.infile and sys.stdin.isatty():
            print("Decryption mode requires input", file=sys.stderr)
            sys.exit(1)
        infile = args.infile if args.infile else None
        decrypt_file(args.private, infile, args.outfile)
    elif args.public:
        generate_public(args.public)

if __name__ == "__main__":
    main()
