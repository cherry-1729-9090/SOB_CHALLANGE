function parseDER(serialized) {
    // Extract the length of the R element
    const rLength = parseInt(serialized.substring(6, 8), 16) * 2;
    // Calculate the start and end positions of R
    const rStart = 8;
    const rEnd = rStart + rLength;
    // Extract R
    const r = serialized.substring(rStart, rEnd);
  
    // Extract the length of the S element
    const sLength = parseInt(serialized.substring(rEnd + 2, rEnd + 4), 16) * 2;
    // Calculate the start and end positions of S
    const sStart = rEnd + 4;
    const sEnd = sStart + sLength;
    // Extract S
    const s = serialized.substring(sStart, sEnd);
    return { r, s };
  }

console.log(parseDER("47304402202bce610e94ec86bcdda2622158bd021640722acbbbb506cc11fb3c1a10b5d562022014bd28a276f44a86b9987daa0555525d60f602b2f52ef4bd4e07f9bad8041b6c01210227ce4c39213f865f1c18987079557548748e83126fcc11293fbd8eac4b0671eb"))