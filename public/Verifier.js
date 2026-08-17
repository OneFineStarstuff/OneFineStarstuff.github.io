const { groth16 } = require('snarkjs');
const fs = require('fs');

async function verifyProof(proof, publicSignals) {
    const vKey = JSON.parse(fs.readFileSync('verification_key.json'));

    const res = await groth16.verify(vKey, publicSignals, proof);

    if (res === true) {
        console.log("Verification OK");
        return true;
    } else {
        console.log("Invalid proof");
        return false;
    }
}

// Example usage:
async function main() {
    // These would be provided by the SCP's audit log
    const proof = JSON.parse(fs.readFileSync('proof.json'));
    const publicSignals = JSON.parse(fs.readFileSync('public.json'));

    await verifyProof(proof, publicSignals);
}

// main();

module.exports = { verifyProof };
