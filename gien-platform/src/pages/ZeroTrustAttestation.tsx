import { Page, Card } from '../components/ui';
import { AttestationHeatmap, MerkleChainVisualizer } from '../components/charts';
import { attestationNodes } from '../data';

export default function ZeroTrustAttestation() {
  const valid = attestationNodes.filter(n => n.valid).length;
  const byAlgo = attestationNodes.reduce<Record<string, number>>((acc, n) => { acc[n.algorithm] = (acc[n.algorithm] || 0) + 1; return acc; }, {});
  return (
    <Page title="Zero Trust & Attestation" subtitle="TEE/TPM/vTPM · PQC Merkle-DAG · zkML pipeline · Kubernetes/GitOps">
      <div className="grid md:grid-cols-2 gap-4">
        <Card title={`Attestation density — ${valid}/${attestationNodes.length} (${((valid / attestationNodes.length) * 100).toFixed(2)}%)`}>
          <AttestationHeatmap nodes={attestationNodes} />
        </Card>
        <Card title="PQC algorithm mix">
          <div className="space-y-2">
            {Object.entries(byAlgo).map(([alg, count]) => (
              <div key={alg} className="flex justify-between text-sm">
                <span className="font-mono">{alg}</span>
                <span>{count} ({((count / attestationNodes.length) * 100).toFixed(0)}%)</span>
              </div>
            ))}
          </div>
        </Card>
      </div>

      <Card title="Merkle-DAG — last 8 leaves + root">
        <MerkleChainVisualizer leaves={8} />
        <div className="text-xs text-slate-500 text-center font-mono">root sha3-512:62af…d18c · validated 08:30 UTC</div>
      </Card>

      <div className="grid md:grid-cols-2 gap-4">
        <Card title="zkML pipeline">
          <ul className="space-y-2 text-sm">
            <li className="flex justify-between"><span>Proofs generated (24h)</span><span className="font-mono">1,902</span></li>
            <li className="flex justify-between"><span>Verification accept rate</span><span className="font-mono">100.0%</span></li>
            <li className="flex justify-between"><span>P99 latency</span><span className="font-mono">3.8s / 8s SLO</span></li>
            <li className="flex justify-between"><span>Fairness delta (max axis)</span><span className="font-mono">0.03 / 0.05</span></li>
            <li className="flex justify-between"><span>vkFMv3 in use</span><span className="font-mono">100%</span></li>
          </ul>
        </Card>
        <Card title="Kubernetes/GitOps posture">
          <ul className="space-y-2 text-sm">
            <li className="flex justify-between"><span>Clusters reconciled</span><span className="font-mono">100%</span></li>
            <li className="flex justify-between"><span>Admission denials</span><span className="font-mono">0</span></li>
            <li className="flex justify-between"><span>Policy violations</span><span className="font-mono">0</span></li>
            <li className="flex justify-between"><span>Kill-switch heartbeat</span><span className="font-mono">08:59:59 UTC VALID</span></li>
          </ul>
        </Card>
      </div>
    </Page>
  );
}
