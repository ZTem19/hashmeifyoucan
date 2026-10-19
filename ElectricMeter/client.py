# From the documentation webpage, under THE HAZARDOUS MATERIALS LAYER on the left
# of the webpage, we will use:
# Primitives -> Asymmetric algorithms -> RSA for key generation, digital signature, and
#   encryption/decryption.
# Primitives -> Message digests (Hashing) for providing a hash function to digital signatures.
# Primitives -> Asymmetric algorithms -> Diffie-Hellman key exchange (with forward secrecy)
#   to generate a shared secret over an insecure communication channel.
# Primitives -> Authenticated encryption -> AESGCM for symmetric encryption and decryption using
#   AES with GCM mode of operation.
# Primitives -> Serialization for creating raw bytes from objects. These raw bytes can be transmitted
#   over insecure communication channel.

import socket
import struct
import json
import base64
import time
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_der_public_key
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ===================================================================
# Setup Phase: Using pre-defined Diffie-Hellman parameters for both
#              the server and the client
#              RFC 3526 , 2048-bit MODP Group
# ===================================================================
known_g = 2     # Standard generator
known_p = int(  # known prime
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16
    )

# ============================================================================
# This function derives a shared secret key between the server and the client
#     using Diffie-Hellmen.
#
# Inputs:
#     private_key: The DH private key of the client
#     peer_raw_dh_public_key: The DH public key of the server in raw bytes
#
# Returns:
#     Derived shared secret key
# ============================================================================
def generate_diffie_hellman_secret_key(private_key, peer_raw_dh_public_key):
    
    # Load the DER bytes into a public key object
    peer_public_key = load_der_public_key(peer_raw_dh_public_key)

    shared_key = private_key.exchange(peer_public_key)

    # From the generated shared key, we want to use a hash function to generate
    # a 32-byte secret key
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=None
    ).derive(shared_key)

    return derived_key

# =======================================================
# This is the main entry point of the client's operations
#
# Use the following function to send a message to the server:
#     client_socket.sendall()
#
# Use the following function to receive a message from the server:
#     client_socket.recv()
#
# =======================================================
def run_client():
    # Connect to server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', 8080))
    print("Connected to server.")

    # Your Code is here
 
    while True:
        # Client is waiting to receive next message
        print("Client is waiting...")

        # Your Code is here


    client_socket.close()

if __name__ == "__main__":
    run_client()
