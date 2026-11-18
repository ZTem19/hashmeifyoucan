# Hint #2
# =================================================================

# This function generates an ephemeral DH public-private key pair.

# A pre-defined DH parameters are used when generating the key pair.

#

# Returns:

# - Private key as an instance/object

# - Public key in bytes. These raw bytes in DER format will be sent

#  to the peer. The public key has a structure known as

#  SubjectPublicKeyInfo (see RFC 5280 to learn more about this

#  structure)

# ==================================================================

def generate_ephemeral_dh():

  # Generate ephemeral DH public-private key pair

  private_key = parameters.generate_private_key()

  public_key = private_key.public_key()



  # Get the bytes of the public key in preparation to be

  # sent to the peer.

  # use public_key.public_bytes()

  raw_dh_public_key = public_key.public_bytes(encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo)

  return private_key, raw_dh_public_key

