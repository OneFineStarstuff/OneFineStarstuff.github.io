# G-SRI: Governance Systemic Risk Index Methodology (v1)

## 1. Definition
The G-SRI is a quantitative metric representing an institution's contribution to civilizational AI risk, ranging from 0.00 (Minimal) to 1.00 (Catastrophic).

## 2. Component Weights
| Component | Weight | Source |
| :--- | :--- | :--- |
| **Capability (C)** | 40% | Standardized Benchmarks (MMLU, HumanEval) |
| **Connectivity (K)** | 30% | Number of inter-institutional API dependencies |
| **Containment (H)** | -20% | Quality of Omni-Sentinel hardware gating (Negative risk) |
| **Drift (D)** | 20% | Semantic drift rate measured by GAI-SOC |

## 3. Calculation Formula
$$ G-SRI = \max(0, (0.4C + 0.3K + 0.2D) - 0.2H) $$

## 4. Institutional Action Levels
- **0.00 - 0.40:** Low Risk (Standard Tier-1 controls).
- **0.41 - 0.70:** Elevated Risk (Mandatory Red Dawn simulations).
- **0.71 - 0.90:** High Risk (Dual-ASA authorization required).
- **> 0.90:** Systemic Critical (Mandatory hardware compute caps).
