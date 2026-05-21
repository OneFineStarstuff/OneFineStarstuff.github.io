# Kafka-based Post-Quantum Cryptographic WORM Audit Architecture

## 1. Architecture Summary
Write-Once-Read-Many (WORM) audit logging system resistant to Shor's algorithm, utilizing Kafka as the streaming backbone.

## 2. Core Components
*   **Producer:** GAI-SOC Telemetry Agents using Liboqs for CRYSTALS-Dilithium signing.
*   **Stream Processing:** Flink jobs maintaining Merkle-tree state of the audit log.
*   **Storage:** S3 Object Lock or Azure WORM storage with periodic Merkle-root anchors to Ethereum/Sentinel-Chain.

## 3. Cryptographic Primitives
| Operation | Algorithm | Reference |
| :--- | :--- | :--- |
| **KEM** | CRYSTALS-Kyber | NIST PQC Standard |
| **Digital Signature** | CRYSTALS-Dilithium | FIPS 204 |
| **Hashing** | SHA-3 / Keccak | Hardware-accelerated |

## 4. Retention Policy
*   Standard Governance Events: 10 years (WORM).
*   High-Risk Breaks: Perpetual (WORM).
