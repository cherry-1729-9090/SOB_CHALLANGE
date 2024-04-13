from pycoin.ecdsa import generator_secp256k1, sign, verify
import hashlib, secrets

def verifyECDSAsecp256k1(msg, signature, pubKey):
    msgHash = sha3_256Hash(msg)
    valid = verify(generator_secp256k1, pubKey, msgHash, signature)
    return valid