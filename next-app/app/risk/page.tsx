export const metadata = { title: 'AI Risk Navigator' } as const;
import { PULSE_SCRIPT } from './pulse-script';

export default function RiskPage() {
  return (
    <main className="space-y-4">
      <h1 className="text-2xl font-semibold">Interactive 10-Stage AI Risk Matrix <span id="pulse" className="ml-2 text-xs text-slate-500"></span></h1>
      <p className="text-sm text-slate-600">Filterable matrix and governance dashboard demos.</p>
      <iframe id="riskFrame" srcDoc={RISK_HTML} className="h-[80vh] w-full rounded border" />
      <script dangerouslySetInnerHTML={{__html: PULSE_SCRIPT}} />
    </main>
  );
}

const RISK_HTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>html,body{margin:0;padding:0}</style>
</head><body>
${MATRIX_SECTION}
${GOV_DASHBOARD}
<script>window.addEventListener('message',e=>{if(e.data&&e.data.type==='risk-pulse'){document.body.style.boxShadow='inset 0 0 0 3px rgba(234,179,8,.6)';setTimeout(()=>{document.body.style.boxShadow='none';},300);}})</script>
</body></html>`;

const MATRIX_SECTION = `
<div style="padding:16px;font-family:Segoe UI,Tahoma,Geneva,Verdana,sans-serif;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);">
  <div style="background:rgba(255,255,255,0.95);backdrop-filter:blur(10px);border-radius:16px;padding:16px;max-width:1400px;margin:0 auto;">
    <h2 style="margin:0 0 8px 0;color:#2c3e50;font-size:20px;font-weight:600;text-align:center">Interactive Cross-Stage AI Risk Matrix</h2>
    <div style="text-align:center;margin-bottom:8px">
      <button onclick="toggleColumn('persistent')" style="margin:0 4px;padding:6px 10px;border:none;border-radius:6px;background:#4a5568;color:#fff;cursor:pointer;font-size:12px">Toggle Persistent</button>
      <button onclick="toggleColumn('evolving')" style="margin:0 4px;padding:6px 10px;border:none;border-radius:6px;background:#4a5568;color:#fff;cursor:pointer;font-size:12px">Toggle Evolving</button>
      <button onclick="toggleColumn('emergent')" style="margin:0 4px;padding:6px 10px;border:none;border-radius:6px;background:#4a5568;color:#fff;cursor:pointer;font-size:12px">Toggle Emergent</button>
    </div>
    <table id="matrix" style="width:100%;border-collapse:collapse;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 10px 30px rgba(0,0,0,.1)">
      <thead>
        <tr>
          <th style="background:#1a202c;color:#fff;padding:10px;font-size:13px;border:1px solid #4a5568">Development Stage</th>
          <th class="persistent" style="background:#1a202c;color:#fff;padding:10px;font-size:13px;border:1px solid #4a5568">Persistent Risks</th>
          <th class="evolving" style="background:#1a202c;color:#fff;padding:10px;font-size:13px;border:1px solid #4a5568">Evolving Risks</th>
          <th class="emergent" style="background:#1a202c;color:#fff;padding:10px;font-size:13px;border:1px solid #4a5568">Emergent Risks</th>
        </tr>
      </thead>
      <tbody>
        ${[1,2,3,4,5,6,7,8,9,10].map(n=>`<tr>
          <td style="padding:10px;border:1px solid #e2e8f0;background:linear-gradient(135deg,#667eea,#764ba2);color:#fff;font-weight:600">Stage ${n}</td>
          <td class="persistent" style="padding:10px;border:1px solid #e2e8f0">Persistent risk ${n}</td>
          <td class="evolving" style="padding:10px;border:1px solid #e2e8f0">Evolving risk ${n}</td>
          <td class="emergent" style="padding:10px;border:1px solid #e2e8f0">Emergent risk ${n}</td>
        </tr>`).join('')}
      </tbody>
    </table>
    <div style="display:flex;gap:12px;justify-content:center;margin-top:8px;flex-wrap:wrap">
      <span style="display:flex;align-items:center;gap:6px;background:rgba(255,255,255,.8);padding:6px 10px;border-radius:16px"><span style="width:14px;height:14px;background:#38b2ac;border-radius:3px"></span>Persistent</span>
      <span style="display:flex;align-items:center;gap:6px;background:rgba(255,255,255,.8);padding:6px 10px;border-radius:16px"><span style="width:14px;height:14px;background:#ed8936;border-radius:3px"></span>Evolving</span>
      <span style="display:flex;align-items:center;gap:6px;background:rgba(255,255,255,.8);padding:6px 10px;border-radius:16px"><span style="width:14px;height:14px;background:#d53f8c;border-radius:3px"></span>Emergent</span>
    </div>
  </div>
</div>
<script>
  function toggleColumn(cls){
    const cells=[...document.querySelectorAll('#matrix .'+cls)];
    const isHidden=cells.every(td=>td.style.display==='none');
    cells.forEach(td=>td.style.display=isHidden?'table-cell':'none');
  }
</script>
`;

const GOV_DASHBOARD = `
<div style="padding:16px;font-family:Segoe UI,Tahoma,Geneva,Verdana,sans-serif;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);">
  <div style="background:rgba(255,255,255,0.95);backdrop-filter:blur(10px);border-radius:16px;padding:16px;max-width:1400px;margin:12px auto;">
    <h2 style="margin:0 0 8px 0;color:#2c3e50;font-size:20px;font-weight:600;text-align:center">AGI/ASI Governance Dashboard (Lite)</h2>
    <div id="status" style="text-align:center;color:#475569;font-size:13px;margin-bottom:8px">Design Phase Active • 4 checkpoints scheduled</div>
    <div style="display:grid;grid-template-columns:1fr 340px;gap:16px">
      <div style="position:relative;min-height:360px;background:#fff;border-radius:12px;box-shadow:0 8px 24px rgba(0,0,0,.08);padding:16px">
        <div id="rings" style="position:relative;width:320px;height:320px;margin:0 auto">
          <div data-layer="context" style="position:absolute;top:4px;left:4px;width:312px;height:312px;border-radius:50%;border:3px solid #667eea;display:flex;align-items:center;justify-content:center;background:linear-gradient(45deg,#55a3ff,#667eea);color:#fff;font-weight:700">Context & Safeguards</div>
          <div data-layer="operational" style="position:absolute;top:34px;left:34px;width:252px;height:252px;border-radius:50%;border:3px solid #0984e3;display:flex;align-items:center;justify-content:center;background:linear-gradient(45deg,#74b9ff,#0984e3);color:#fff;font-weight:700">Operational Framework</div>
          <div data-layer="core" style="position:absolute;top:94px;left:94px;width:132px;height:132px;border-radius:50%;border:3px solid #ee5a24;display:flex;align-items:center;justify-content:center;background:linear-gradient(45deg,#ff6b6b,#ee5a24);color:#fff;font-weight:700">Core Elements</div>
        </div>
      </div>
      <div style="background:#fff;border-radius:12px;box-shadow:0 8px 24px rgba(0,0,0,.08);padding:16px">
        <div style="font-size:14px;font-weight:700;margin-bottom:6px">Layer Detail</div>
        <div id="layerTitle" style="font-size:13px;color:#334155;margin-bottom:6px">System Overview</div>
        <div style="font-size:12px;color:#475569;margin-bottom:6px">Aggregated Risk: <span id="aggRisk" style="font-weight:700;color:#16a34a">Low</span></div>
        <div style="font-size:12px;color:#475569;margin-bottom:6px">Governance: <span id="govBody">Safety Oversight Board</span></div>
        <div style="display:flex;gap:8px;margin-top:8px">
          <button onclick="parent.postMessage({type:'risk-pulse'},'*')" style="flex:1;padding:8px 10px;border:none;border-radius:8px;background:#667eea;color:#fff;font-weight:600">Export Report</button>
          <button onclick="parent.postMessage({type:'risk-pulse'},'*')" style="flex:1;padding:8px 10px;border:none;border-radius:8px;background:#764ba2;color:#fff;font-weight:600">Schedule Review</button>
        </div>
      </div>
    </div>
  </div>
</div>
<script>
  const layerRisks={core:'Medium',operational:'Medium',context:'High'};
  const govBodies={core:'Model Review Board & Algorithm Ethics Panel',operational:'System Integration Board',context:'Safety Oversight Board'};
  document.querySelectorAll('#rings [data-layer]').forEach(el=>{
    el.addEventListener('click',()=>{
      const layer=el.getAttribute('data-layer');
      document.getElementById('layerTitle').textContent = layer.charAt(0).toUpperCase()+layer.slice(1)+' Layer';
      document.getElementById('aggRisk').textContent = layerRisks[layer];
      document.getElementById('aggRisk').style.color = layerRisks[layer]==='High'?'#e11d48':(layerRisks[layer]==='Medium'?'#f59e0b':'#16a34a');
      document.getElementById('govBody').textContent = govBodies[layer];
    })
  })
</script>
`;
