# THIS IS DOCUMENTATION FOR THE PROJECT


## Communication Flowchart
```
[Utility Company Server]                                         [Residential Meter Client]
          |                                                                   |
          | --- 1. Send Server RSA Public Key (No security) ----------------> |
          |                                                                   |
          | --- 2. Send Server DH Ephemeral Public Key (No security) -------> |
          |                                                                   |
          | <--- 3. Send Client DH Ephemeral Public Key (No security) ------- |
          |                                                                   |
[Derive AES Key]                                                    [Derive AES Key]
Use HKDF(SHA-256) on the DH                                         Use HKDF(SHA-256) on the DH 
shared secret to create the                                         shared secret to create the
32-byte AES key.                                                    32-byte AES key.
          |                                                                   |
[Prepare Server Command]
1. Create JSON dictionary: 
   { "command": "SEND DATA", 
     "timestamp": <value> }
2. Encrypt JSON with AES-GCM
   (using 12-byte random IV).
3. Sign the ciphertext/message 
   using RSA-PSS (SHA-256).
4. Encode to Base64.
          |                                                                   |
          | --- 4. Transmit Base64 Encrypted & Signed Command --------------> |
          |                                                                   |
                                                                    [Verify & Process]
                                                                    1. Decode Base64.
                                                                    2. Verify RSA-PSS signature
                                                                       using Server's RSA Public Key.
                                                                    3. Decrypt payload using AES-GCM.
                                                                    4. Check Timestamp/Nonce to 
                                                                       prevent replay attacks.
                                                                    5. Execute SEND DATA command.
                                                                              |
                                                                    [Prepare Client Response]
                                                                    1. Create JSON dictionary:
                                                                       { "reading": <random_value>,
                                                                         "timestamp": <value> }
                                                                    2. Encrypt JSON with AES-GCM.
                                                                    3. Encode to Base64.
          |                                                                   |
          | <--- 5. Transmit Base64 Encrypted Response ---------------------- |
          |                                                                   |
[Process Response]
1. Decode Base64.
2. Decrypt payload using AES-GCM.
3. Check Timestamp/Nonce to 
   prevent replay attacks.
4. Read meter data.
```

