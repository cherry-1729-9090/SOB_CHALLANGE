import ecdsa.util
from ecdsa.keys import VerifyingKey
import binascii

def remove_trailing_junk(signature_bytes):
    try:
        r, s = ecdsa.util.sigdecode_der(signature_bytes, ecdsa.SECP256k1.order)
        return ecdsa.util.sigencode_der(r, s, ecdsa.SECP256k1.order)
    except ecdsa.der.UnexpectedDER as e:
        print(f"Error decoding DER: {e}")
        raise

def verify_signature(pubkey_hex, signature_der_hex, message_hex):
    pubkey_bytes = binascii.unhexlify(pubkey_hex)
    signature_der_bytes = binascii.unhexlify(signature_der_hex)
    message_hash_bytes = binascii.unhexlify(message_hex)  # Assuming this is the double SHA-256 hash
    
    # Remove trailing junk from the signature
    signature_bytes = remove_trailing_junk(signature_der_bytes)
    
    # Create a VerifyingKey object
    vk = VerifyingKey.from_string(pubkey_bytes, curve=ecdsa.SECP256k1)
    
    # Verify the signature
    try:
        is_valid = vk.verify(signature_bytes, message_hash_bytes, hashfunc=ecdsa.util.sha256, sigdecode=ecdsa.util.sigdecode_string)
        return is_valid
    except ecdsa.BadSignatureError:
        return False

print(verify_signature("0227ce4c39213f865f1c18987079557548748e83126fcc11293fbd8eac4b0671eb",
                       "304402202bce610e94ec86bcdda2622158bd021640722acbbbb506cc11fb3c1a10b5d562022014bd28a276f44a86b9987daa0555525d60f602b2f52ef4bd4e07f9bad8041b6c",
                       "1d06545d4ec1964b10f97442998fb070a4edd5b7c7c4c19241ec8209f79bb6e4"))
