// Code Challenge 2024 - Cherry 1729 9090
const fs = require('fs').promises;
const path = require('path');

const { verifyFiles, checkStack } = require('./functions.js');
const {checkSig_p2wpkh} = require('./p2wpkh.js');
const directory = 'code-challenge-2024-cherry-1729-9090/mempool';

(async () => {
    let valid_p2pkh = 0;
    let count_p2pkh = 0;
    let count_p2pwkh = 0;
    let valid_p2pwkh = 0;
    let abnormal = 0;
    try {
        const files = await fs.readdir(directory);

        for (const filename of files) {
            const filepath = path.join(directory, filename);
            const fileData = await fs.readFile(filepath, 'utf8');
            const data = JSON.parse(fileData);
            const transactionType = data.vin[0].prevout.scriptpubkey_type;
            
            const fileVerification = verifyFiles(data);
            if (transactionType === "p2pkh") {
                count_p2pkh++;
                if (filename === fileVerification && checkStack(data)) {
                    valid_p2pkh++;
                }
            }

            if(transactionType === "v0_p2wpkh"){
                count_p2pwkh ++;
                if(filename ===fileVerification && checkSig_p2wpkh(data)){
                    valid_p2pwkh++;
                }
                if(!checkSig_p2wpkh(data)){
                    // console.log(`INVALID P2WPKH TRANSACTION : ${filename}`);
                    abnormal++;
                }
            }
        }
        console.log(`TOTAL ABNORMAL P2WPKH TRANSACTIONS : ${abnormal}`);
        console.log(`TOTAL P2PKH  TRANSACTIONS : ${count_p2pkh} || VALID P2PKH TRANSACTIONS : ${valid_p2pkh}`);
        console.log(`TOTAL P2WPKH TRANSACTIONS : ${count_p2pwkh} || VALID P2WPKH TRANSACTIONS : ${valid_p2pwkh}`);
    } catch (error) {
        console.error('Error reading directory:', error);
    }
})();
