from cryptography.hazmat.primitives.asymmetric import x25519
# from ecdsa import sign
from ecdsa import SigningKey, NIST384p, Ed25519
from ecdsa.util import sigdecode_der, sigencode_der
import hashlib
import pickle
import requests
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
from ecdsa import ECDH, NIST256p, Ed25519


def sign(skin, data):
    new_signature = skin.sign(bytes("suii", encoding="UTF-8"), sigencode=sigencode_der)
    return new_signature

def verify(vk, sig, data):
    return vk.verify(sig, bytes(data, encoding="UTF-8"), sigdecode=sigdecode_der)
    


def KDF(inp):
    salt = os.urandom(16)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    key = kdf.derive(bytes(inp))
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    kdf.verify(b"my great password", key)
    print("                ")
    print(key)
    return key





class User():
    
    


    def __init__(self, name, MAX_OPK_NUM):
        
        self.name = name
        with open("private.pem") as f:
            sk = SigningKey.from_pem(f.read(), hashlib.sha256)
        self.IK_s = sk
        self.IK_p = self.IK_s.verifying_key
        self.SPK_s = SigningKey.generate()
        self.SPK_p = self.SPK_s.verifying_key
        self.SPK_sig = sign(self.IK_s, pickle.dumps(self.SPK_p))
        self.OKPs = []
        self.OPKs_p = []
        for i in range(MAX_OPK_NUM):
            sk = SigningKey.generate()
            pk = sk.verifying_key
            self.OPKs_p.append(pk)
            self.OKPs.append((sk, pk))
            # for later steps
            self.key_bundles = {}
            self.dr_keys= {}

        def publish(self):
            return {
                'IK_p': self.IK_p,
                'SPK_p': self.SPK_p,
                'SPK_sig': self.SPK_sig,
                'OPKs_p': self.OPKs_p
                }
    def get_server_keys(self, address = 'http://127.0.0.1:8000/getserversk'):
        headers = {
        'accept': 'application/json',
    }

        response = requests.get(address, headers=headers)
        if response.status_code == 200:
            res = response.json()
            ser_pubK = pickle.loads(base64.b64decode(res['Server_public_K']))
            return ser_pubK
    def get_key_bundle(self, server, user_name):
        if user_name in self.key_bundles and user_name in self.dr_keys:
            print("Already stored")
          
      	    # print('Already stored ' + user_name + ' locally, no need handshake again')
            return False
       

        self.key_bundles[user_name] = server.get_key_bundle(user_name)
        return True
    
    def initial_handshake(self, server, user_name):
    	if self.get_key_bundle(server, user_name):
         sk = SigningKey.generate()
         self.key_bundles[user_name]['EK_s'] = sk
         self.key_bundles[user_name]['EK_p'] = sk.verifying_key

              
    

# Continue in Class Client
    def x3dh_KDF(key_material):
        salt = os.urandom(16)
# derive
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=390000,
            )
        key = kdf.derive(b"my great password")
        return key


    def generate_send_secret_key(self, user_name):

        key_bundle = self.key_bundles[user_name]
        
        ecdh = ECDH(curve=NIST256p, private_key = self.IK_s) 
        ecdh.load_received_public_key_pem(key_bundle['SPK_p'])
        DH_1 = ecdh.generate_sharedsecret()
        
        ecdh2 = ECDH(curve=NIST256p, private_key = key_bundle['EK_s']) 
        ecdh2.load_received_public_key_pem(key_bundle['IK_p'])
        DH_2 = ecdh2.generate_sharedsecret()
        
        ecdh2 = ECDH(curve=NIST256p, private_key = key_bundle['EK_s']) 
        ecdh2.load_received_public_key_pem(key_bundle['SPK_p'])
        DH_3 = ecdh2.generate_sharedsecret()
        

        
        if not verify(self.IK_s, key_bundle['SPK_sig']):
            print('Unable to verify Signed Prekey')
            
        else:
            return KDF(DH_1+ DH_2 + DH_3)
        

        # create SK
        key_bundle['SK'] = KDF(DH_1 + DH_2 + DH_3 + "DH_4")

              
              
              
              
              
siem = User("Siem", 100)
print(siem.SPK_sig)




#openssl genpkey -algorithm ed25519 -out private.pem


# salt = os.urandom(16)
# # derive
# kdf = PBKDF2HMAC(
#     algorithm=hashes.SHA256(),
#     length=32,
#     salt=salt,
#     iterations=390000,
# )
# key = kdf.derive(b"my great password")
# # verify
# kdf = PBKDF2HMAC(
#     algorithm=hashes.SHA256(),
#     length=32,
#     salt=salt,
#     iterations=390000,
# )
# kdf.verify(b"my great password", key)
# print("                ")
# print(key)


# ecdh = ECDH(curve=NIST256p)
# ecdh.generate_private_key()
# local_public_key = ecdh.get_public_key()
# ecdh
# #send `local_public_key` to remote party and receive `remote_public_key` from remote party
# with open("remote_public_key2.pem") as e:
#     remote_public_key = e.read()
# ecdh.load_received_public_key_pem(remote_public_key)
# secret = ecdh.generate_sharedsecret_bytes()

# with open("secret" , "ab") as f:
#     f.write(secret)





#&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&


# sk = SigningKey.generate(curve=NIST256p)
# ecdh = ECDH(curve=NIST256p, private_key = sk)
# pubk = ecdh.generate_private_key()

# with open("priv_key.pem", "wb") as f:
#     f.write(sk.to_pem())

with open("priv_key.pem", "rb") as e:
    sk = SigningKey.from_pem(e.read())
    
ecdh = ECDH(curve=NIST256p, private_key = sk)
local_public_key = ecdh.get_public_key()

with open("pub_key.pem", "wb") as f:
    f.write(local_public_key.to_pem())
# sk = ecdh.generate_private_key()
local_public_key = ecdh.get_public_key()

with open("remote_pub_key3.pem", "rb") as e:
    remote_public_key = e.read()
ecdh.load_received_public_key_pem(remote_public_key)
# secret = ecdh.generate_sharedsecret_bytes()

secret = ecdh.generate_sharedsecret()

print(secret)
