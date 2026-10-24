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
import math
import binascii
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
# ============================================================
# Parts h, i, j: replay protection and JSON message transport
# ============================================================

MAX_MESSAGE_SIZE = 65536


def create_payload(data):
    """h: Add freshness information BEFORE signing/encrypting the payload."""
    return {
        "timestamp": time.time(),
        "message_id": os.urandom(16).hex(),
        "data": data
    }


class ReplayProtection:
    """h: Reject stale/duplicate authenticated messages.

    Keep one instance across all received messages. Assumes synchronized
    clocks; this in-memory cache is lost on restart. Cross-restart protection
    requires persistent state or an authenticated fresh session identifier.
    """

    def __init__(self, max_age=30, future_tolerance=5):
        self.max_age = max_age
        self.future_tolerance = future_tolerance
        self.seen_ids = {}

    def check(self, payload):
        """Record an accepted ID or raise ValueError. Authenticate first."""
        if not isinstance(payload, dict):
            raise ValueError("Payload must be a dictionary")
        timestamp = payload.get("timestamp")
        message_id = payload.get("message_id")
        if type(timestamp) not in (int, float):
            raise ValueError("Invalid timestamp")
        try:
            finite = math.isfinite(timestamp)
        except OverflowError:
            finite = False
        if not finite:
            raise ValueError("Timestamp must be finite")
        if (not isinstance(message_id, str) or len(message_id) != 32
                or any(c not in "0123456789abcdef" for c in message_id)):
            raise ValueError("Invalid message ID")
        if "data" not in payload:
            raise ValueError("Missing application data")
        now = time.time()
        if timestamp < now - self.max_age:
            raise ValueError("Message has expired")
        if timestamp > now + self.future_tolerance:
            raise ValueError("Message timestamp is too far in the future")
        self.seen_ids = {
            old_id: expiry for old_id, expiry in self.seen_ids.items()
            if expiry >= now
        }
        if message_id in self.seen_ids:
            raise ValueError("Replay detected: duplicate message ID")
        self.seen_ids[message_id] = timestamp + self.max_age


def encode_base64(raw_bytes):
    """i: Convert binary keys, signatures, IVs or ciphertext to JSON strings."""
    return base64.b64encode(raw_bytes).decode("utf-8")


def json_to_bytes(dictionary):
    """i: Serialize once; sign and send these same bytes."""
    return json.dumps(dictionary, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def send_json(sock, dictionary):
    """i: Send UTF-8 JSON preceded by its 4-byte network-order length."""
    if not isinstance(dictionary, dict):
        raise ValueError("Outgoing message must be a dictionary")
    message_bytes = json_to_bytes(dictionary)
    if not 0 < len(message_bytes) <= MAX_MESSAGE_SIZE:
        raise ValueError("Outgoing message exceeds size limit")
    sock.sendall(struct.pack("!I", len(message_bytes)) + message_bytes)


def receive_exactly(sock, byte_count):
    """j: Loop because TCP recv() can return only part of a message."""
    received = bytearray()
    while len(received) < byte_count:
        chunk = sock.recv(byte_count - len(received))
        if not chunk:
            raise ConnectionError("Connection closed while receiving")
        received.extend(chunk)
    return bytes(received)


def json_from_bytes(raw_bytes):
    """j: Parse UTF-8 JSON and require an object/dictionary."""
    try:
        result = json.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as error:
        raise ValueError("Invalid JSON message") from error
    if not isinstance(result, dict):
        raise ValueError("JSON message must contain a dictionary")
    return result


def receive_json(sock):
    """j: Read one complete frame. Close connection on framing errors."""
    header = receive_exactly(sock, 4)
    message_length = struct.unpack("!I", header)[0]
    if not 0 < message_length <= MAX_MESSAGE_SIZE:
        raise ValueError("Invalid incoming message length")
    return json_from_bytes(receive_exactly(sock, message_length))


def decode_base64(value):
    """j: Validate and recover bytes for verification or decryption."""
    if not isinstance(value, str):
        raise ValueError("Base64 field must be a string")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValueError("Invalid Base64 field") from error


def require_fields(message, expected_type, fields):
    """j: Check a received envelope before accessing its fields."""
    if message.get("type") != expected_type:
        raise ValueError("Unexpected message type")
    for field in fields:
        if field not in message:
            raise ValueError(f"Missing field: {field}")


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

    # Parts a-g: receive/exchange RSA/DH keys here with your teammates.
    # Keep one checker alive between received commands.
    replay_checker = ReplayProtection()
 
    while True:
        # Client is waiting to receive next message
        print("Client is waiting...")

        # Integration example: uncomment when your teammate's verifier is ready.
        # message = receive_json(client_socket)
        # require_fields(message, "signed_command", ["payload", "signature"])
        # payload_bytes = decode_base64(message["payload"])
        # signature = decode_base64(message["signature"])
        # if not verify_signature(server_public_key, payload_bytes, signature):
        #     raise ValueError("Invalid signature")
        # payload = json_from_bytes(payload_bytes)
        # Validate payload["data"] and its command before recording the ID.
        # replay_checker.check(payload)
        # Only now execute payload["data"]["command"].
        # This example assumes verify_signature returns True/False; if it raises
        # InvalidSignature instead, catch that exception and reject the message.
        #
        # For the reply, encrypt json_to_bytes(create_payload({"reading": 123}))
        # using your teammate's AES-GCM function, then send_json(client_socket,
        # {"type": "meter_response", "iv": encode_base64(iv),
        #  "ciphertext": encode_base64(ciphertext)}).
        # Close the connection on receive/framing errors. Never act on a failed
        # signature, failed GCM authentication, or rejected replay check.
        print("Parts h/i/j are ready; connect RSA/DH/AES functions to continue.")
        break


    client_socket.close()

if __name__ == "__main__":
    run_client()