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
import time
import json
import base64
import os
import select
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_der_public_key
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# h. Add freshness fields BEFORE signing/encrypting the message.
# The timestamp and nonce must be authenticated along with the message.
def add_freshness(message):
    return dict(message, timestamp=time.time(), nonce=os.urandom(16).hex())


def check_replay(message, seen_nonces):
    # Call AFTER signature verification or authenticated AES decryption.
    # Keep the same set for all received messages; clocks must agree within 60s.
    # Do not clear it while old authenticated messages can still be accepted.
    if not abs(time.time() - message["timestamp"]) <= 60:
        raise ValueError("Message timestamp is outside the allowed window")
    if message["nonce"] in seen_nonces:
        raise ValueError("Replay detected")
    seen_nonces.add(message["nonce"])


# i. Convert byte values (keys, signatures, IVs, ciphertext) to Base64 strings.
# Accepts a flat dictionary; text and numeric values stay unchanged.
def send_json(sock, message):
    json_dict = {
        key: base64.b64encode(value).decode('utf-8')
        if isinstance(value, bytes) else value
        for key, value in message.items()
    }
    message_bytes = json.dumps(json_dict).encode('utf-8')
    sock.sendall(struct.pack('!I', len(message_bytes)) + message_bytes)


# j. TCP may split a message across multiple recv() calls.
def receive_exact(sock, length):
    data = b''
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError("Peer disconnected")
        data += chunk
    return data


def receive_json(sock, byte_fields=()):
    # Supply the binary field names, e.g. byte_fields=("server_public_key",).
    # Parsing does not authenticate a message; verify/decrypt before using it.
    length = struct.unpack('!I', receive_exact(sock, 4))[0]
    message = json.loads(receive_exact(sock, length).decode('utf-8'))
    if not isinstance(message, dict):
        raise ValueError("Expected a JSON dictionary")
    for key in byte_fields:
        message[key] = base64.b64decode(message[key], validate=True)
    return message


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
#     private_key: The DH private key of the server
#     peer_raw_dh_public_key: The DH public key of the client in raw bytes
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


# ============================================================================
# This function encrypts a plaintext message using AES-256-GCM.
#
# Inputs:
#     key: 32-byte (256-bit) AES key, derived from generate_diffie_hellman_secret_key
#     plaintext: the message to encrypt, as bytes
#     associated_data: optional bytes to authenticate but not encrypt
#                       (e.g. a command type, so it can't be swapped undetected)
#
# Returns:
#     (iv, ciphertext) tuple, both as bytes.
#     ciphertext includes the GCM authentication tag appended at the end.
# ============================================================================
def aes_encrypt(key, plaintext, associated_data=None):
    if len(key) != 32:
       raise ValueError("AES-256 key must be 32 bytes")
    iv = os.urandom(12)  # 12-byte IV, required for AES-GCM
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, plaintext, associated_data)
    return iv, ciphertext

# ============================================================================
# This function decrypts an AES-256-GCM ciphertext and verifies its
#     integrity and authenticity.
#
# Inputs:
#     key: 32-byte (256-bit) AES key, same key used for encryption
#     iv: the 12-byte IV used during encryption
#     ciphertext: the encrypted data (includes GCM tag)
#     associated_data: must exactly match what was used during encryption
#
# Returns:
#     The original plaintext as bytes.
#     Raises cryptography.exceptions.InvalidTag if ciphertext or
#     associated_data was tampered with.
# ============================================================================
def aes_decrypt(key, iv, ciphertext, associated_data=None):
    if len(key) != 32:
       raise ValueError("AES-256 key must be 32 bytes")
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(iv, ciphertext, associated_data)
    return plaintext
  
#### RSA SECTION ####
rsa_priv_key: rsa.RSAPrivateKey
rsa_pub_key: rsa.RSAPublicKey
    
def send_rsa_pub_key(connection: socket.socket, data: dict) -> None:
    # Convert the dictionary to a JSON string
    json_data = json.dumps(data)
    json_length = len(json_data)
    connection.sendall(struct.pack('!I', json_length) + json_data.encode())

def send_json_signed(connection: socket.socket, json_data: dict) -> None:
    # Convert the dictionary to a JSON string
    payload_bytes = json.dumps(json_data, sort_keys=True).encode('utf-8')
    
    # Sign the json payload
    signature = rsa_priv_key.sign(
        payload_bytes, 
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
            ), 
        hashes.SHA256()
    )   
    
    b64_signature = base64.b64encode(signature).decode('utf-8')
    
    message = {
        "payload": payload_bytes.decode('utf-8'),
        "signature": b64_signature
    }
    
    # Send the length of the JSON string, the JSON string, and the signature
    data = json.dumps(message).encode('utf-8')
    connection.sendall(struct.pack('!I', len(data)) + data)

#### HELPER FUNCTIONS ####

def send_command(connection: socket.socket, command: str) -> None:
    """Send a command to the client. The command is a string."""
    payload = {
        "command": command,
        "timestamp": time.time()
    }
    send_json_signed(connection, payload)


# ================================================================
# This is the main entry point of the server's operations
#
# Use the following function to send a message to the client:
#     connection.sendall()
#
# Use the following function to receive a message from the client:
#     connection.recv()
#
# ================================================================
def run_server():
    # Setup network socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('127.0.0.1', 8080))
    server_socket.listen(1)
    print("Server is listening on port 8080 ... Press Ctrl+C to stop.")

    connection = None
    addr = None

    try:
        while True:
            # Check if server is ready to be read. Timeout is 1 second
            ready_for_reading, ready_for_writing, exceptional_condition = select.select([server_socket], [], [], 1.0)

            if server_socket in ready_for_reading:
                connection, addr = server_socket.accept()
                print(f"Connection accepted from {addr}")
                break

        # Your code is here
        
        # RSA CODE HERE
        # Generate RSA key pair for the server
        global rsa_priv_key
        global rsa_pub_key
        rsa_priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rsa_pub_key = rsa_priv_key.public_key() 
    
        # Send public key to the client
        pub_key_json = {
            "rsa_public_key": rsa_pub_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode('utf-8')
        }
        send_rsa_pub_key(connection, pub_key_json)
        
        # ==========================================
        # DIFFIE-HELLMAN KEY EXCHANGE (SERVER SIDE)
        # ==========================================

        # Initialize DH parameters using pre-defined known_p and known_g
        parameters = dh.DHParameterNumbers(known_p, known_g).parameters()

        #Generate server ephemeral private and public key pair
        server_dh_priv = parameters.generate_private_key()
        server_dh_pub = server_dh_priv.public_key()

        #Serialize server DH public key to DER and base64 encode
        server_dh_pub_der = server_dh_pub.public_bytes(
            encoding=Encoding.DER,
            format=PublicFormat.SubjectPublicKeyInfo
        )
        server_dh_pub_b64 = base64.b64encode(server_dh_pub_der).decode('utf-8')

        #Send server DH public key to client (unprotected)
        dh_payload = {"dh_public_key": server_dh_pub_b64}
        send_rsa_pub_key(connection, dh_payload)

        #Receive client DH public key response
        client_dh_response = rcv_json(connection)
        client_dh_pub_b64 = client_dh_response.get("dh_public_key")
        client_dh_pub_der = base64.b64decode(client_dh_pub_b64)

        #Compute shared secret and derive the 32-byte AES key using HKDF
        server_aes_key = generate_diffie_hellman_secret_key(server_dh_priv, client_dh_pub_der)
        print("Server successfully established DH shared secret and derived AES key.")

        while True:
            # Display the commands
            print("**** Main Menu ****")
            print("1. GET READING")
            print("2. SHUTDOWN")
            print("3. START SERVICE")
            print("4. Exit")

            # Get the controller's input
            choice = input("Select an option (1-4): ").strip()

            if choice == "1":                
                # Your code is here
                send_command(connection, "GET_READING")
                # I added the following line to avoid errors in this starter code. You can remove it.
                continue
            elif choice == "2":
                # Your code is here
                send_command(connection, "SHUTDOWN")
                # I added the following line to avoid errors in this starter code. You can remove it.
                continue
            elif choice == "3":
                # Your code is here
                send_command(connection, "START_SERVICE")
                # I added the following line to avoid errors in this starter code. You can remove it.
                continue
            elif choice == "4":
                print("Exiting program.")
                break
            else:
                print("Invalid choice.")

    except KeyboardInterrupt:
        print("Server is shutting down")
    finally:
        if connection:
            connection.close()
        server_socket.close()
        print("Socket is closed")

if __name__ == "__main__":
    run_server()
