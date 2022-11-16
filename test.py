import hashlib
from ecdsa import ECDH, NIST256p, Ed25519, SigningKey
import base64
from ecdsa.util import sigdecode_der, sigencode_der


# sk = SigningKey.generate(curve=NIST256p)
# ecdh = ECDH(curve=NIST256p, private_key = sk)
# pubk = ecdh.generate_private_key()
# local_public_key = ecdh.get_public_key()
# # sk = ecdh.load_private_key()
# with open("remote_priv_key3.pem", "wb") as f:
#     f.write(sk.to_pem())
    
# with open("remote_pub_key3.pem", "wb") as f:
#     f.write(local_public_key.to_pem())


#send `local_public_key` to remote party and receive `remote_public_key` from remote party
with open("remote_priv_key3.pem", "rb") as e:
    sk = SigningKey.from_pem(e.read())
    
ecdh = ECDH(curve=NIST256p, private_key = sk)
local_public_key = ecdh.get_public_key()

with open("remote_pub_key3.pem", "wb") as f:
    f.write(local_public_key.to_pem())
# sk = ecdh.generate_private_key()
local_public_key = ecdh.get_public_key()

with open("pub_key.pem", "rb") as e:
    remote_public_key = e.read()
ecdh.load_received_public_key_pem(remote_public_key)
# secret = ecdh.generate_sharedsecret_bytes()

secret = ecdh.generate_sharedsecret()

print(secret)


sk.to_pem()

print("signature")

sig = sk.sign(bytes("suii", encoding="UTF-8"), sigencode=sigencode_der)
vk = sk.get_verifying_key()

print(sig)

print(vk.verify(sig, bytes("suii", encoding="UTF-8"), sigdecode=sigdecode_der))