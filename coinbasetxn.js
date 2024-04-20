const { serializeP2pkh, littleEndian, verifyFiles, doubleHash } = require("./functions");
const { create_wtxid } = require('./wtxid.js');
const {sha256} = require('./hashes.js');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');



let txns = [];
let wtxns = [];

// directory where the files are stored
const directory = 'code-challenge-2024-cherry-1729-9090/mempool';


// function to generate the merkle root
const generateMerkleRoot = (txids) => {
    if (txids.length === 0) return null;
  
    // reverse the txids
    let level = txids.map((txid) =>
      Buffer.from(txid, "hex").reverse().toString("hex")
    );
  
    while (level.length > 1) {
      const nextLevel = [];
  
      for (let i = 0; i < level.length; i += 2) {
        let pairHash;
        if (i + 1 === level.length) {
          // In case of an odd number of elements, duplicate the last one
          pairHash = doubleHash(level[i] + level[i]);
        } else {
          pairHash = doubleHash(level[i] + level[i + 1]);
        }
        nextLevel.push(pairHash);
      }
  
      level = nextLevel;
    }
  
    return level[0];
  };



// read all the files in the directory
try {
    const files = fs.readdirSync(directory);

    for (const filename of files) {
        const filepath = path.join(directory, filename);
        const fileData = fs.readFileSync(filepath, 'utf8');
        const data = JSON.parse(fileData);
        const transactionType = data.vin[0].prevout.scriptpubkey_type;
        const fileVerification = verifyFiles(data);
        if (transactionType === "p2pkh") {
            if (filename === fileVerification) {
                txns.push(littleEndian(doubleHash(serializeP2pkh(data)))); //pushing the little endain form of the normal txid
            }
        }

        if (transactionType === "v0_p2wpkh") {
            if (filename === fileVerification) {
                wtxns.push(littleEndian(create_wtxid(data))); //pushing the little endain form of the wtxid
            }

        }
    }


} catch (err) {
    console.error('Error:', err);
}



// write all the wtxns to a file
const fileName = 'wtxns.txt';
const fileContent = `wtxns:\n[${wtxns.map(item => `\n  "${item}"`).join(',')}\n]`;
fs.writeFile(fileName, fileContent, (err) => {
    if (err) {
        console.error('Error writing to file:', err);
    } else {
        // console.log(`File "${fileName}" created successfully with wtxins as list.`);
    }
});

//write all the txns to a file
const fileName2 = 'txns.txt';
const fileContent2 = `txns:\n[${txns.map(item => `\n  "${item}"`).join(',')}\n]`;
fs.writeFile(fileName2, fileContent2, (err) => {
    if (err) {
        console.error('Error writing to file:', err);
    } else {
        // console.log(`File "${fileName2}" created successfully with txins as list.`);
    }
});



// function to generate the coinbase transaction
function generate_coinbase_tx(wtxns){
    const witness_commitment = generate_witness_commitment(generateMerkleRoot(wtxns));
    const scriptpubkey = '6a24aa21a9ed' + witness_commitment.toString('hex'); // Concatenate with the hexadecimal string of witness_commitment
    const scriptsig = "49366144657669436872616E496C6F7665426974636F696E4D696E696E67"

    let coinbase_tx = "";
    coinbase_tx += "01000000"; // version
    coinbase_tx += "0010"; // marker + flag
    coinbase_tx += "01"; // number of inputs
    coinbase_tx += "0000000000000000000000000000000000000000000000000000000000000000"
    coinbase_tx += "ffffffff"; // previous output
    coinbase_tx += scriptsig.toString(16).length/2 + scriptsig; // scriptsig
    coinbase_tx += "ffffffff"; // sequence
    coinbase_tx += "02"; // number of outputs
    coinbase_tx += "00f2052a01000000"; // value - 1
    coinbase_tx += "19" // size of scriptpubkey
    coinbase_tx += "76a914edf10a7fac6b32e24daa5305c723f3de58db1bc888ac"; // scriptpubkey
    coinbase_tx += "0000000000000000" // value - 2
    coinbase_tx += scriptpubkey.length/2 + scriptpubkey; // scriptpubkey
    coinbase_tx += "01"; // number of witnesses
    coinbase_tx += "20"; // size of witness commitment
    coinbase_tx += "0000000000000000000000000000000000000000000000000000000000000000";
    coinbase_tx += "00000000"; // locktime
    return coinbase_tx;
}

function generate_witness_commitment(wtxidhash){
    return doubleHash("0000000000000000000000000000000000000000000000000000000000000000" + wtxidhash)
}

const coinbase_tx = generate_coinbase_tx(wtxns); //created coinbase transaction
txns.unshift(coinbase_tx); // added the coinbase transaction to the txns array

const merkleroot = generateMerkleRoot(txns); // merkle root of the txns array
const witnesscommitment = generate_witness_commitment(merkleroot); // witness commitment of the merkle root

module.exports = {merkleroot,txns,coinbase_tx}; //exporting the merkle root and txns array