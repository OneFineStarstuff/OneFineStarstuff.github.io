export const PULSE_SCRIPT = `
(async function(){
  const pulseEl = document.getElementById('pulse');
  async function tick(){
    try{
      const res = await fetch('/api/risk/scores');
      const json = await res.json();
      const ctx = json.series.find((s:any)=>s.key==='context');
      const last = ctx?.points?.[ctx.points.length-1]?.v ?? 0;
      if(pulseEl){ pulseEl.textContent = 'Context risk: ' + Math.round(last); }
      const iframe = document.getElementById('riskFrame') as HTMLIFrameElement | null;
      iframe?.contentWindow?.postMessage({type:'risk-pulse'}, '*');
    }catch(e){ if(pulseEl) pulseEl.textContent = 'Risk: n/a'; }
    setTimeout(tick, 6000);
  }
  tick();
})();
`;
