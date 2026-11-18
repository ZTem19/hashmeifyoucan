# hashmeifyoucan

## AES encryption and decryption

The server uses `AESGCM` from the `cryptography` package for authenticated
encryption. AES-GCM protects both:

* **Confidentiality:** the plaintext cannot be read without the shared key.
* **Integrity and authenticity:** changing the nonce, ciphertext, or associated
  data causes decryption to fail.

`generate_diffie_hellman_secret_key` derives a 32-byte key, so the current
handshake uses AES-256-GCM. The helper functions are in
[`ElectricUtilityCompany/server.py`](ElectricUtilityCompany/server.py):

```python
from ElectricUtilityCompany.server import decrypt_message, encrypt_message

key = ...  # 32-byte key derived from the DH handshake
metadata = b"electric-meter-v1"

envelope = encrypt_message(
    b"meter reading: 123.4 kWh",
    key,
    associated_data=metadata,
)

plaintext = decrypt_message(
    envelope,
    key,
    associated_data=metadata,
)
assert plaintext == b"meter reading: 123.4 kWh"
```

### Wire format

`encrypt_message` returns a JSON-serializable dictionary:

```json
{
  "nonce": "<base64>",
  "ciphertext": "<base64>"
}
```

The ciphertext value includes the 16-byte GCM authentication tag produced by
`AESGCM`. The nonce is not secret and must be sent with the ciphertext. It is
generated randomly for every message and must never be reused with the same
key.

### Decryption rules

Call `decrypt_message` with the exact key and associated data used for
encryption. A malformed envelope raises `ValueError`. If authentication
fails—because the ciphertext, nonce, key, or associated data is wrong—the
`cryptography` library raises `InvalidTag`. Treat that failure as an
unauthenticated message and do not process any plaintext.

Keep the derived key in memory only as long as needed, never log it, and do not
hard-code keys in source code. The key exchange and socket protocol still need
to be wired into `run_server` and `run_client`; these helpers provide the
encryption/decryption layer for that integration.