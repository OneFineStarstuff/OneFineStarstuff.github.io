# Use a standard Node.js runtime as the base image
FROM node:16

# Set the working directory in the container
WORKDIR /usr/src/app

# Install circom and snarkjs globally
RUN npm install -g circom snarkjs

# Copy the circuit and key files into the container
COPY gsm_transition_circuit.circom .
COPY proving_key.json .
COPY verification_key.json .

# Copy the Prover service code
COPY Prover.js .

# The command to run the Prover service
CMD [ "node", "Prover.js" ]
