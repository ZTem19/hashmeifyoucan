# Hint #1
# Generating RSA public-private key pair for the server

server_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

server_public_key = server_private_key.public_key()



# Get the public key bytes in DER encoding

raw_public_key = server_public_key.public_bytes(encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo)



# Create JSON dictionary:

# First, encode the dictionary value into Base64, which contains ASCII characters

#    A-Z, a-z, 0-9, +, /, =.

#    b64encode() still returns the result as bytes.

#    b64encode() accepts byte-like object. So, if the input is a string, convert

#          it to bytes using .encode('utf-8')

# Second, decode Base64 into UTF-8. decode() returns the result as string because JSON

#    expects strings and not bytes.

json_dict = {

  "server_public_key": base64.b64encode(raw_public_key).decode('utf-8')

}



# Serialize JSON dictionary to JSON string that is ready for transmission

json_payload = json.dumps(json_dict)



# Sockets expects bytes for transmission. But the message is JSON string. So,

# Convert JSON string to bytes!

message_bytes = json_payload.encode('utf-8')



# We need to add the length of the message so the client knows the number of transmitted bytes

# One option is to add another key-value pair in the dictionary. For example:

# json_dict = {

#  "server_public_key": base64.b64encode(raw_public_key).decode('utf-8')

#  "public_key_length": len(raw_public_key)

# }

# Another approach is to use struct.pack() as follows:

# ! means big-endian (most significant byte first. This is called network byte order)

# I means unsigned 32-bit integer (4 bytes)

message_length = struct.pack('!I', len(message_bytes))



# Send the message length followed by the message itself

connection.sendall(message_length+message_bytes)