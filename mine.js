const { block_header} = require('./block.js');
const { doubleHash } = require('./hashes.js');
const { littleEndian } = require('./functions.js');
const {txns,coinbase_tx} = require('./coinbasetxn.js');

// Implement the mine function that takes a block header as input and returns the mined block
function mine(block_header) {
    let nonce = 0;
    const target = Buffer.from("0000ffff00000000000000000000000000000000000000000000000000000000"); // Convert target to buffer
    let paddedNonce = nonce.toString(16).padStart(8, '0'); // Pad nonce with leading zeros to make it 4 bytes

    while (true) {
        const hash = Buffer.from(littleEndian(doubleHash(block_header + littleEndian(paddedNonce))), 'hex'); // Convert hash to buffer
        if (hash.compare(target) < 0) { // Compare hashes using buffer compare method
            return block_header + littleEndian(paddedNonce);
        }
        nonce++;
        paddedNonce = nonce.toString(16).padStart(8, '0'); // Update nonce with leading zeros
    }
}

let mined_block = mine(block_header);
// console.log(mined_block);





const fs = require('fs');
function writeToOutputFile() {
    const outputData = [];
    outputData.push(mined_block);
    outputData.push(...txns);

    // Join data with newline character
    const outputContent = outputData.join('\n');

    // Write data to output.txt file
    fs.writeFile('output.txt', outputContent, (err) => {
        if (err) {
            console.error('Error writing to file:', err);
        } else {
            console.log('Data written to output.txt successfully.');
        }
    });
}

// Call function to write data to file
writeToOutputFile();





