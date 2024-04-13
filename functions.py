import hashlib
import json
import os
from pyasn1.codec.der import decoder as der_decoder
from binascii import unhexlify
from ecdsa import VerifyingKey, SECP256k1, BadSignatureError
import ecdsa

def to_hex(value):
  value_bytes = value.to_bytes((value.bit_length() + 7) // 8, 'big')
  return value_bytes.hex() 


def little_endian(data):
  pairs = [data[i:i+2] for i in range(0, len(data), 2)]  
  pairs.reverse()  
  return ''.join(pairs) 



def conc_vin(transaction):
  concat_str = ""
  for vin in transaction['vin']:
    # little endian format of transaction
    # 4 bytes little endian form of vout in each vin
    # script signature of each vin
    # little endain format of hexadecimal of value
    # little endain format of sequence 
    sigsize = len(vin['scriptsig'])//2
    if sigsize == 0:
       sigsize = "00"
    else:
       sigsize = str(to_hex(sigsize))
    concat_str += little_endian(vin['txid']) +  little_endian(str(to_hex(vin['vout'])).zfill(8)) +  sigsize + vin['scriptsig'] +  little_endian(str(to_hex(vin['sequence'])))  
  return concat_str



def conc_vout(transaction):
    concat_str = ""
    for vout in transaction['vout']:
        # little endian format of hexadecimal number of value
        # number of bytes of each scriptpubkey
        # scriptpubkey of each vout
        concat_str += little_endian(hex(vout['value']).replace('0x', '').zfill(16))  +  str(to_hex(len(vout['scriptpubkey']) // 2))  + vout['scriptpubkey'] 

    
    return concat_str



def serialize_p2pkh(transaction):
  # 4 byte little endian format of verison +
  # 1 byte vin length +
  # concatination of vin part
  # concation of vout part
  # little endain format of locktime
  serialize_p2pkh = little_endian("{:08x}".format(transaction['version']))  + "  "  +"{:02x}".format(len(transaction['vin']))  + "  " +  conc_vin(transaction)  + "  " + "{:02d}".format(len(transaction['vout']))  + "  " + conc_vout(transaction) + "  "  +little_endian(to_hex(transaction['locktime'])).ljust(8,'0')
  return serialize_p2pkh



def double_hash(data_hex):
    # Decode hexadecimal string to bytes
    data_bytes = bytes.fromhex(data_hex)
    
    # First hash
    first_hash = hashlib.sha256(data_bytes).digest()
    
    # Second hash
    second_hash = hashlib.sha256(first_hash).digest()
    
    # Convert second hash to hexadecimal
    double_hashed_data = second_hash.hex()
    
    return double_hashed_data



def verify_files(data):
   data1 = serialize_p2pkh(data)
   data2 = little_endian(double_hash(data1))
   data_bytes = bytes.fromhex(data2)
   return hashlib.sha256(data_bytes).digest().hex()



def convert_bool(value):
    if isinstance(value, str):
        # Convert string representation of boolean to Python boolean
        if value.lower() == "true":
            return True
        elif value.lower() == "false":
            return False
    # Return non-string values as is
    return value



def open_all_files(directory):
   for filename in os.listdir(directory):
    # Construct the full path to the file
    filepath = os.path.join(directory, filename)
    
    # Check if the file is a regular file
    if os.path.isfile(filepath):
        # Load the JSON file with custom boolean conversion
        with open(filepath, 'r') as file:
            data = json.load(file, object_hook=lambda d: {k: convert_bool(v) for k, v in d.items()})
        
        # Now you can work with the data dictionary, where boolean values are Python boolean values
        # For example, you can print the filename and the contents of the data dictionary
        print("File:", filename)
        print("Data:", data)



def extract_rs_from_script_signature(serialized):
    # Extract the length of the R element
    r_length = int(serialized[6:8], 16) * 2
    # Calculate the start and end positions of R
    r_start = 8
    r_end = r_start + r_length
    # Extract R
    r = serialized[r_start:r_end]

    # Extract the length of the S element
    s_length = int(serialized[r_end + 2:r_end + 4], 16) * 2
    # Calculate the start and end positions of S
    s_start = r_end + 4
    s_end = s_start + s_length
    # Extract S
    s = serialized[s_start:s_end]

    # Convert R and S to integers
    r_int = int(r, 16)
    s_int = int(s, 16)

    return {'r':r_int,'s': s_int}

def create_digest(transaction, index):
    vin = transaction['vin']  # Accessing the correct index of the vin list
    concat_str = ""
    concat_str += little_endian("{:08x}".format(transaction['version'])) + "{:02x}".format(len(transaction['vin'])) +  create_vin_digest(transaction, index) + "{:02d}".format(len(transaction['vout'])) + conc_vout(transaction) + little_endian(to_hex(transaction['locktime'])).ljust(8, '0') +  "01000000"
    return concat_str



def create_vin_digest(transaction, index):
    concat_str = ""
    vin = transaction['vin']
    for i in range(0, len(vin)):
        if i == index:
            concat_str += little_endian(vin[i]['txid']) + little_endian(str(to_hex(vin[i]['vout'])).zfill(8)) + little_endian("{:02x}".format(len(vin[i]['prevout']['scriptpubkey']) // 2)) + vin[i]['prevout']['scriptpubkey'] + little_endian(to_hex(vin[i]['sequence']))
        else:
            concat_str += little_endian(vin[i]['txid']) +  little_endian(str(to_hex(vin[i]['vout'])).zfill(8)) + '00' + little_endian(to_hex(vin[i]['sequence']))

    return concat_str



# def verify_transaction(transaction_data, r, s, public_key):
#     # Recreate the message hash
#     message_hash = hashlib.sha256(transaction_data.encode()).digest()
    
#     # Create a verifying key from the provided public key
#     vk = VerifyingKey.from_string(bytes.fromhex(public_key), curve=SECP256k1)
#     r = int(r,16)
#     s = int(s,16)

#     # Convert r and s to bytes
#     r_bytes = r.to_bytes((r.bit_length() + 7) // 8 or 1, 'big')
#     s_bytes = s.to_bytes((s.bit_length() + 7) // 8 or 1, 'big')
    
#     # Combine r and s into DER format
#     der_signature = bytes([0x30, len(r_bytes) + len(s_bytes), 0x02, len(r_bytes)]) + r_bytes + bytes([0x02, len(s_bytes)]) + s_bytes
    
#     # Verify the signature
#     try:
#         vk.verify(der_signature, message_hash)
#         print("Signature is valid for this transaction.")
#     except BadSignatureError:
#         print("Signature is not valid for this transaction.")
from ecdsa import util

def verify_ecdsa_signature(public_key_hex, signature_hex, message_hex):
    # Import the public key
    vk = VerifyingKey.from_string(bytes.fromhex(public_key_hex), curve=ecdsa.SECP256k1)

    # Parse the DER-encoded signature
    r, s = extract_rs_from_script_signature(signature_hex)

    # Encode r and s into DER format
    der_signature = util.sigencode_der(r, s, vk.pubkey.order)

    # Verify the signature
    try:
        vk.verify(signature=der_signature, data=bytes.fromhex(message_hex), hashfunc=hashlib.sha256)
        return True
    except ecdsa.BadSignatureError:
        return False

tx = {
  "version": 2,
  "locktime": 832539,
  "vin": [
    {
      "txid": "7c218cbf0fe023d15b71e401b34d6841f3cdf5617a42eddf32708fcf4c3236cb",
      "vout": 0,
      "prevout": {
        "scriptpubkey": "76a9144e30f8fd336a83e1d6910fb9713d21f6dda1ff5a88ac",
        "scriptpubkey_asm": "OP_DUP OP_HASH160 OP_PUSHBYTES_20 4e30f8fd336a83e1d6910fb9713d21f6dda1ff5a OP_EQUALVERIFY OP_CHECKSIG",
        "scriptpubkey_type": "p2pkh",
        "scriptpubkey_address": "188SNe6fRhVm2hd3PZ3TwsBSWchFZak2Th",
        "value": 36882
      },
      "scriptsig": "47304402202bce610e94ec86bcdda2622158bd021640722acbbbb506cc11fb3c1a10b5d562022014bd28a276f44a86b9987daa0555525d60f602b2f52ef4bd4e07f9bad8041b6c01210227ce4c39213f865f1c18987079557548748e83126fcc11293fbd8eac4b0671eb",
      "scriptsig_asm": "OP_PUSHBYTES_71 304402202bce610e94ec86bcdda2622158bd021640722acbbbb506cc11fb3c1a10b5d562022014bd28a276f44a86b9987daa0555525d60f602b2f52ef4bd4e07f9bad8041b6c01 OP_PUSHBYTES_33 0227ce4c39213f865f1c18987079557548748e83126fcc11293fbd8eac4b0671eb",
      "is_coinbase": False,
      "sequence": 4294967293
    },
    {
      "txid": "869b62369426bac43369b49e62f5611f94f808a7c670875831c7f593eb7b5ba9",
      "vout": 0,
      "prevout": {
        "scriptpubkey": "76a914d74bce8fd3488eed4d449351feafdaca1d03b7d688ac",
        "scriptpubkey_asm": "OP_DUP OP_HASH160 OP_PUSHBYTES_20 d74bce8fd3488eed4d449351feafdaca1d03b7d6 OP_EQUALVERIFY OP_CHECKSIG",
        "scriptpubkey_type": "p2pkh",
        "scriptpubkey_address": "1LdP6Q62wHkZwoBE62Gy4y2tuw9kZhTqmv",
        "value": 328797
      },
      "scriptsig": "473044022019d625e3d2a77df31515113790c90c2f00e9200b22010717329a878246c9881e02203970dafda92f72cf3d8579509907e41099e9bdd6f3541eb46a6806697f407dd2012102a17743cdc1bf0f9adab350bba42658fca42c0d486ab0cc49e2451bb5be2295a7",
      "scriptsig_asm": "OP_PUSHBYTES_71 3044022019d625e3d2a77df31515113790c90c2f00e9200b22010717329a878246c9881e02203970dafda92f72cf3d8579509907e41099e9bdd6f3541eb46a6806697f407dd201 OP_PUSHBYTES_33 02a17743cdc1bf0f9adab350bba42658fca42c0d486ab0cc49e2451bb5be2295a7",
      "is_coinbase": False,
      "sequence": 4294967293
    },
    {
      "txid": "c0f0cf3896308fabf365f9430a5d42265efe4b9bda12f61e5146c21aed1b88f6",
      "vout": 0,
      "prevout": {
        "scriptpubkey": "76a9143b5428c5c51348a788afd5cc362f227d4c04c66288ac",
        "scriptpubkey_asm": "OP_DUP OP_HASH160 OP_PUSHBYTES_20 3b5428c5c51348a788afd5cc362f227d4c04c662 OP_EQUALVERIFY OP_CHECKSIG",
        "scriptpubkey_type": "p2pkh",
        "scriptpubkey_address": "16Qhgomq9Jnh247Q5KCzXvLXhZv1VBzTrS",
        "value": 34100
      },
      "scriptsig": "473044022034fdb2fdcf5b147f81c4a13350e9ee8c9f5de08d27103cf65e6a7c3b96042d2202206186ce4aa966c16e4671a35f766c17382c9c758d1622ef59bba6ef571c679f7a012103d23ad1dccc41cf313e2355fe220238260efde1fc156a9c4f7211898229db1139",
      "scriptsig_asm": "OP_PUSHBYTES_71 3044022034fdb2fdcf5b147f81c4a13350e9ee8c9f5de08d27103cf65e6a7c3b96042d2202206186ce4aa966c16e4671a35f766c17382c9c758d1622ef59bba6ef571c679f7a01 OP_PUSHBYTES_33 03d23ad1dccc41cf313e2355fe220238260efde1fc156a9c4f7211898229db1139",
      "is_coinbase": False,
      "sequence": 4294967293
    },
    {
      "txid": "f4482b2a061a321965c7ad1768fc80599ce36fbf693cfd95d23dd708e22c45cc",
      "vout": 0,
      "prevout": {
        "scriptpubkey": "76a914529a520fba93f9940fc113c803e04fb8e378af1c88ac",
        "scriptpubkey_asm": "OP_DUP OP_HASH160 OP_PUSHBYTES_20 529a520fba93f9940fc113c803e04fb8e378af1c OP_EQUALVERIFY OP_CHECKSIG",
        "scriptpubkey_type": "p2pkh",
        "scriptpubkey_address": "18XmH7PEgjmBLqeee2nSSV6Qm5C5x2JNxs",
        "value": 41184
      },
      "scriptsig": "47304402207d9a086b835659c2f45de8d2d85292f04ce8b833969cdd4f352b679a7b3775940220050cfec89f5a309799f3dc0628ff20fb696c43b1c6bee93066dfdab089da50b301210281e3301ea2655d695a1950f59456b27f8f3fbc0bbe6349cedc4121052a36b816",
      "scriptsig_asm": "OP_PUSHBYTES_71 304402207d9a086b835659c2f45de8d2d85292f04ce8b833969cdd4f352b679a7b3775940220050cfec89f5a309799f3dc0628ff20fb696c43b1c6bee93066dfdab089da50b301 OP_PUSHBYTES_33 0281e3301ea2655d695a1950f59456b27f8f3fbc0bbe6349cedc4121052a36b816",
      "is_coinbase": False,
      "sequence": 4294967293
    }
  ],
  "vout": [
    {
      "scriptpubkey": "76a914090a212ddb7211158409534bce9f6d553bcd028788ac",
      "scriptpubkey_asm": "OP_DUP OP_HASH160 OP_PUSHBYTES_20 090a212ddb7211158409534bce9f6d553bcd0287 OP_EQUALVERIFY OP_CHECKSIG",
      "scriptpubkey_type": "p2pkh",
      "scriptpubkey_address": "1poDYYTsXhXimWRiKRjVCokoLzzbjR25q",
      "value": 24200
    },
    {
      "scriptpubkey": "a914f15ac47ae6eb8f8da450ba7787b6a8c0059b076087",
      "scriptpubkey_asm": "OP_HASH160 OP_PUSHBYTES_20 f15ac47ae6eb8f8da450ba7787b6a8c0059b0760 OP_EQUAL",
      "scriptpubkey_type": "p2sh",
      "scriptpubkey_address": "3PhBWQp766Lr5p4HqWFkEsMraLW2h918LV",
      "value": 410000
    }
  ]
}


serialized_msg = create_digest(tx,0)
script_sig = tx['vin'][0]['scriptsig_asm'].split(" ")[1]
public_key = tx['vin'][0]['scriptsig_asm'].split(" ")[3]
r,s = extract_rs_from_script_signature(script_sig)
digested_msg = hashlib.sha256(serialized_msg.encode()).hexdigest()
# print(double_hash(serialized_msg))
print(digested_msg)
# # # print(digested_msg)
# # # print(extract_rs_from_script_signature(script_sig))
# # # print(public_key)
# # if verify_ecdsa_signature(public_key,script_sig,digested_msg):
# #    print("valid transaction")
# # else:
# #    print("not valid")

# # print(serialized_msg)
# print(script_sig)
# print(public_key)
# print({'pk':public_key,'sign':script_sig,'msg_hex':digested_msg})



# 19814092846943214347799365679902145557165683579556192872674615440980693079394
# 9380471516801020060696912388895860016946678717987873065765707535476295211884
# 0b09e4f0fc368b45902dd3364bec0ee7dbd728a6792f93813bb967ee0fcbebc0
# 0227ce4c39213f865f1c18987079557548748e83126fcc11293fbd8eac4b0671eb