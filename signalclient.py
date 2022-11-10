from cryptography.hazmat.primitives.asymmetric import x25519
from XEdDSA import sign

class User():

  def __init__(self, name, MAX_OPK_NUM):
      self.name = name
      self.IK_s = x25519.X25519PrivateKey.generate()
      self.IK_p = self.IK_s.public_key()
      self.SPK_s = x25519.X25519PrivateKey.generate()
      self.SPK_p = self.IK_s.public_key()
      self.SPK_sig = sign(IK_s, SPK_p)
      self.OKPs = []
      self.OPKs_p = []
      for i in range(MAX_OPK_NUM):
          sk = x25519.X25519PrivateKey.generate()
          pk = sk.public_key()
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