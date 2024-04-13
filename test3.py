import ecdsa
import ecdsa.util
import binascii

def verify_ecdsa_signature(public_key_hex, signature_hex, message_hex):
    # Parse the public key
    public_key_bytes = bytes.fromhex(public_key_hex)
    curve = ecdsa.SECP256k1
    verify_key = ecdsa.VerifyingKey.from_string(public_key_bytes, curve=curve)

    # Parse the DER-encoded signature
    signature_bytes = bytes.fromhex(signature_hex)

    # Print the decoded signature before attempting to remove trailing junk
    print("Decoded Signature:", signature_bytes.hex())

    # Parse the message
    message_bytes = bytes.fromhex(message_hex)

    # Verify the signature
    try:
        verify_key.verify(signature_bytes, message_bytes)
        return True
    except ecdsa.BadSignatureError:
        return False

dicti = {
    'pk': '0227ce4c39213f865f1c18987079557548748e83126fcc11293fbd8eac4b0671eb',
    'sign': '304402202bce610e94ec86bcdda2622158bd021640722acbbbb506cc11fb3c1a10b5d562022014bd28a276f44a86b9987daa0555525d60f602b2f52ef4bd4e07f9bad8041b6c01',
    'msg_hex': '0b09e4f0fc368b45902dd3364bec0ee7dbd728a6792f93813bb967ee0fcbebc0'
}
print(verify_ecdsa_signature(dicti['pk'], dicti['sign'], dicti['msg_hex']))
