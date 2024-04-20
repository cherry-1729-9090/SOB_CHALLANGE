const { createHash } = require('crypto');
const { sha256, ripemd160, OP_HASH160,doubleHash } = require('./hashes.js');
const crypto = require('crypto');
const { verifyECDSASignature } = require('./functions.js');

function littleEndian(data) {
  const pairs = [];
  for (let i = 0; i < data.length; i += 2) {
    pairs.unshift(data.substring(i, i + 2));
  }
  return pairs.join('');
}


function hashPrevouts(transaction) {
    const vin = transaction.vin;
    let concStr = "";
    for (const vinEntry of vin) {
      const voutString = vinEntry.vout.toString(16).padStart(8, '0');
      concStr += littleEndian(vinEntry.txid) + littleEndian(voutString);
    }
    return doubleHash(concStr);
  }
  
function hashSequences(transaction) {
  const vin = transaction.vin;
  let concStr = "";
  for (const vinEntry of vin) {
    const sequenceString = vinEntry.sequence
                            .toString(16)
                            .padStart(8, '0');
    concStr += littleEndian(sequenceString);
  }
  return doubleHash(concStr);
}

function hashOutputs(transaction) {
  const vout = transaction.vout;
  let concBytes = ""
  for (const voutEntry of vout) {
      concBytes += littleEndian(voutEntry.value.toString(16).padStart(16, '0')) ;
      concBytes += (voutEntry.scriptpubkey.length / 2).toString(16).padStart(2,'0');
      concBytes += voutEntry.scriptpubkey ;
  }
  return doubleHash(concBytes);
}



function outpoints(transaction,index) {
  const vin = transaction.vin;
  let concStr = "";
  vinEntry = vin[index]
  concStr += littleEndian(vinEntry.txid) + 
            littleEndian((vinEntry.vout).toString(16).padStart(8, '0'));
  return concStr;
}


function scriptCode(transaction,inputIndex) {
  return "1976a914" +
  transaction.vin[inputIndex].prevout.scriptpubkey.slice(4) +
  "88ac"; //script code for p2wpkh
}

function amount(transaction,index) {
  return littleEndian(transaction.vin[index].prevout.value.toString(16).padStart(16, '0'));
}

function nsequence(transaction,index) {
  return littleEndian(transaction.vin[index].sequence.toString(16).padStart(8, '0'));
}

function serializeP2WPKH(transaction,index) {
  const serializedTxn = littleEndian(transaction.version.toString(16).padStart(8, '0')) +
    hashPrevouts(transaction) +
    hashSequences(transaction) +
    outpoints(transaction,index) +
    scriptCode(transaction,index) +
    amount(transaction,index) +
    nsequence(transaction,index)+
    hashOutputs(transaction) +
    littleEndian(transaction.locktime.toString(16).padStart(8,'0')) +
    "01000000";
  return doubleHash(serializedTxn);
  // return serializedTxn;
}

function checkSig_p2wpkh(transaction){
  for (let i = 0; i < transaction.vin.length; i++) {
    serialization = serializeP2WPKH(transaction,i);
    pubkey = transaction.vin[i].witness[1];
    sig = transaction.vin[i].witness[0];
    if (!verifyECDSASignature(pubkey, sig, serialization)) {
      return false;
    }
    return true;
  }
}

tx ={
  "version": 2,
  "locktime": 0,
  "vin": [
    {
      "txid": "c408dc3e715747d8566d94473a2111f0c3c18e14ad13ef405996584d7851a66d",
      "vout": 1,
      "prevout": {
        "scriptpubkey": "00145a73cc23f450a1516db223398f46f72d46908c21",
        "scriptpubkey_asm": "OP_0 OP_PUSHBYTES_20 5a73cc23f450a1516db223398f46f72d46908c21",
        "scriptpubkey_type": "v0_p2wpkh",
        "scriptpubkey_address": "bc1qtfeucgl52zs4zmdjyvuc73hh94rfprppp45wh0",
        "value": 1849514
      },
      "scriptsig": "",
      "scriptsig_asm": "",
      "witness": [
        "3044022005cb9034b8e2230655464c144c4ec1e9f8222fe8dc9a4da435975eb99451206a022072112aa0bc71b8fd592d4a8c8df59af46c1e077c7720c97e7756b43cc136efb501",
        "037207cd7a533ce42f9c11bfbe97c7c2c9f629545a8a4e3f878fc31ea292fa204a"
      ],
      "is_coinbase": false,
      "sequence": 4294967295
    }
  ],
  "vout": [
    {
      "scriptpubkey": "0014b28ebd04107106f70f0434bf8b4d0cb335dbb964",
      "scriptpubkey_asm": "OP_0 OP_PUSHBYTES_20 b28ebd04107106f70f0434bf8b4d0cb335dbb964",
      "scriptpubkey_type": "v0_p2wpkh",
      "scriptpubkey_address": "bc1qk28t6pqswyr0wrcyxjlckngvkv6ahwtywx8zep",
      "value": 100778
    },
    {
      "scriptpubkey": "0014f09779d2e346180f80f10560e7d6de9d98c91359",
      "scriptpubkey_asm": "OP_0 OP_PUSHBYTES_20 f09779d2e346180f80f10560e7d6de9d98c91359",
      "scriptpubkey_type": "v0_p2wpkh",
      "scriptpubkey_address": "bc1q7zthn5hrgcvqlq83q4sw04k7nkvvjy6en9cg6v",
      "value": 1746639
    }
  ]
}

module.exports = { checkSig_p2wpkh };