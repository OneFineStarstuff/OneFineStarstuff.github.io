const { groth16 } = require('snarkjs');
const fs = require('fs');
const express = require('express');

const app = express();
app.use(express.json());

const circuitWasm = 'gsm_transition_circuit_js/gsm_transition_circuit.wasm';
const provingKey = 'proving_key.json';

async function generateProof(input) {
    const { proof, publicSignals } = await groth16.fullProve(input, circuitWasm, provingKey);

    return { proof, publicSignals };
}

app.post('/generate-proof', async (req, res) => {
    const input = req.body;

    try {
        const { proof, publicSignals } = await generateProof(input);
        res.json({ proof, publicSignals });
    } catch (err) {
        console.error(err);
        res.status(500).send('Error generating proof');
    }
});

app.listen(3000, () => {
    console.log('Prover service listening on port 3000');
});
