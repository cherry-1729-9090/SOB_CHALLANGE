const { merkleroot } = require('./coinbasetxn.js');
const { doubleHash } = require('./hashes.js');
const { littleEndian } = require('./functions.js');
function generate_block(){
    let block_header = "";
    block_header += "01000000";  // version
    block_header += "0000000000000000000000000000000000000000000000000000000000000000"; // prev block
    block_header += merkleroot; // merkle root
    const currentTimestampInSeconds = Math.floor(Date.now() / 1000);
    block_header += littleEndian(currentTimestampInSeconds.toString(16)); // timestamp
    block_header += "ffff001f"; // bits
    return block_header;
}
block_header = generate_block();
module.exports = {block_header}
