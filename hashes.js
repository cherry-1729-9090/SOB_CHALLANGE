const { createHash } = require('crypto');
function doubleHash(value) {
  return sha256(sha256(value));
}
function sha256(value) {
  return createHash('sha256').update(Buffer.from(value, 'hex')).digest('hex');
}
function ripemd160(value) {
  return createHash('ripemd160').update(value, 'hex').digest('hex');
}
function OP_HASH160(value) {
  return ripemd160(sha256(value));
}
module.exports = {doubleHash, sha256, ripemd160, OP_HASH160};