import { useState } from 'react';
import {
  Activity,
  Calendar,
  Check,
  ChevronRight,
  Clock,
  FileText,
  Globe,
  Info,
  Layers,
  Play,
  Radio,
  RotateCcw,
  ShieldAlert,
  Sliders,
  TriangleAlert,
  Zap,
} from 'lucide-react';
import MetricCard from '../components/MetricCard';
import PageHeader from '../components/PageHeader';
import StatusBadge from '../components/StatusBadge';
import TaggedDocument from '../components/TaggedDocument';
import TimelineVisualization from '../components/TimelineVisualization';
import { GOVERNANCE_PHASES, INFINITY_PILLARS } from '../data/gienData';
import {
  DEFAULT_INVARIANT_STRESS_CONFIG,
  DEFAULT_INTERSTELLAR_HANDOFF_CONFIG,
  DEFAULT_OMEGA_GAR_CONFIG,
  DEFAULT_PHASE_TRANSITION_CONFIG,
  DEFAULT_PRIOR_RUNS,
  DEFAULT_REGULATORY_SHIFT_CONFIG,
  DEFAULT_SUCCESSOR_CODEX_CONFIG,
  MAJOR_FRAMEWORKS,
  SCENARIO_TYPES,
  runSimulation,
  type InvariantStressConfig,
  type InterstellarHandoffConfig,
  type OmegaGarDissolutionConfig,
  type PhaseTransitionConfig,
  type RegulatoryShiftConfig,
  type ScenarioConfig,
  type ScenarioHistoryRun,
  type ScenarioTypeId,
  type SimulationResult,
  type SuccessorCodexConfig,
} from '../data/scenarioData';

export default function ScenarioPlanner() {
  const [selectedScenarioId, setSelectedScenarioId] = useState<ScenarioTypeId>('phase_transition');

  // Individual scenario configs state
  const [phaseConfig, setPhaseConfig] = useState<PhaseTransitionConfig>(DEFAULT_PHASE_TRANSITION_CONFIG);
  const [omegaConfig, setOmegaConfig] = useState<OmegaGarDissolutionConfig>(DEFAULT_OMEGA_GAR_CONFIG);
  const [successorConfig, setSuccessorConfig] = useState<SuccessorCodexConfig>(DEFAULT_SUCCESSOR_CODEX_CONFIG);
  const [stressConfig, setStressConfig] = useState<InvariantStressConfig>(DEFAULT_INVARIANT_STRESS_CONFIG);
  const [regConfig, setRegConfig] = useState<RegulatoryShiftConfig>(DEFAULT_REGULATORY_SHIFT_CONFIG);
  const [handoffConfig, setHandoffConfig] = useState<InterstellarHandoffConfig>(DEFAULT_INTERSTELLAR_HANDOFF_CONFIG);

  // History & Results state
  const [history, setHistory] = useState<ScenarioHistoryRun[]>(DEFAULT_PRIOR_RUNS);
  const [currentResult, setCurrentResult] = useState<SimulationResult | null>(DEFAULT_PRIOR_RUNS[0].result);
  const [showReport, setShowReport] = useState<boolean>(false);

  // Construct current active ScenarioConfig
  const getActiveScenarioConfig = (): ScenarioConfig => {
    switch (selectedScenarioId) {
      case 'phase_transition':
        return { type: 'phase_transition', config: phaseConfig };
      case 'omega_gar_dissolution':
        return { type: 'omega_gar_dissolution', config: omegaConfig };
      case 'successor_codex':
        return { type: 'successor_codex', config: successorConfig };
      case 'invariant_stress_test':
        return { type: 'invariant_stress_test', config: stressConfig };
      case 'regulatory_shift':
        return { type: 'regulatory_shift', config: regConfig };
      case 'interstellar_handoff':
        return { type: 'interstellar_handoff', config: handoffConfig };
    }
  };

  const handleRunSimulation = () => {
    const activeCfg = getActiveScenarioConfig();
    const result = runSimulation(activeCfg);
    setCurrentResult(result);
    setShowReport(false);

    // Prepend to history
    const scenarioTypeInfo = SCENARIO_TYPES.find((s) => s.id === selectedScenarioId);
    let paramsSummary = '';

    if (activeCfg.type === 'phase_transition') {
      paramsSummary = `${activeCfg.config.sourcePhase} → ${activeCfg.config.targetPhase} (${activeCfg.config.timelineMonths} mo, ${activeCfg.config.invariantMode})`;
    } else if (activeCfg.type === 'omega_gar_dissolution') {
      paramsSummary = `${activeCfg.config.trigger} trigger, Epoch ${activeCfg.config.targetEpoch}`;
    } else if (activeCfg.type === 'successor_codex') {
      paramsSummary = `${activeCfg.config.targetCodexVersion}, ${activeCfg.config.migrationWindowMonths} mo window`;
    } else if (activeCfg.type === 'invariant_stress_test') {
      paramsSummary = `${activeCfg.config.attackVector} (${activeCfg.config.stressLoadMultiplier}x load)`;
    } else if (activeCfg.type === 'regulatory_shift') {
      paramsSummary = `${activeCfg.config.targetRegime} (${activeCfg.config.gracePeriodMonths} mo grace)`;
    } else {
      paramsSummary = `${activeCfg.config.targetConstellation} (latency ${activeCfg.config.signalLatencyHours}h)`;
    }

    const newHistoryRun: ScenarioHistoryRun = {
      id: `RUN-${Date.now()}`,
      scenarioType: selectedScenarioId,
      scenarioTitle: scenarioTypeInfo?.title ?? 'Simulation Run',
      paramsSummary,
      outcomeScore: result.outcomeScore,
      overallStatus: result.overallStatus,
      timestamp: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
      config: activeCfg,
      result,
    };

    setHistory((prev) => [newHistoryRun, ...prev]);
  };

  const handleReloadHistoryRun = (run: ScenarioHistoryRun) => {
    setSelectedScenarioId(run.scenarioType);
    if (run.config.type === 'phase_transition') setPhaseConfig(run.config.config);
    else if (run.config.type === 'omega_gar_dissolution') setOmegaConfig(run.config.config);
    else if (run.config.type === 'successor_codex') setSuccessorConfig(run.config.config);
    else if (run.config.type === 'invariant_stress_test') setStressConfig(run.config.config);
    else if (run.config.type === 'regulatory_shift') setRegConfig(run.config.config);
    else if (run.config.type === 'interstellar_handoff') setHandoffConfig(run.config.config);

    if (run.result) {
      setCurrentResult(run.result);
      setShowReport(false);
    }
  };

  // Helper to toggle framework carryover
  const toggleFramework = (fw: string) => {
    setPhaseConfig((prev) => {
      const exists = prev.frameworks.includes(fw);
      return {
        ...prev,
        frameworks: exists ? prev.frameworks.filter((f) => f !== fw) : [...prev.frameworks, fw],
      };
    });
  };

  // Helper to toggle pillar
  const togglePillar = (pillarId: string) => {
    setPhaseConfig((prev) => {
      const exists = prev.pillars.includes(pillarId);
      return {
        ...prev,
        pillars: exists ? prev.pillars.filter((p) => p !== pillarId) : [...prev.pillars, pillarId],
      };
    });
  };

  const renderScenarioIcon = (iconName: string) => {
    switch (iconName) {
      case 'Sliders':
        return <Sliders size={18} className="text-indigo-400" />;
      case 'Zap':
        return <Zap size={18} className="text-amber-400" />;
      case 'FileText':
        return <FileText size={18} className="text-cyan-400" />;
      case 'ShieldAlert':
        return <ShieldAlert size={18} className="text-red-400" />;
      case 'Globe':
        return <Globe size={18} className="text-emerald-400" />;
      case 'Radio':
        return <Radio size={18} className="text-violet-400" />;
      default:
        return <Activity size={18} className="text-gray-400" />;
    }
  };

  return (
    <div className="space-y-6 pb-12">
      <PageHeader
        title="Scenario Planner & Governance Arc Simulator"
        subtitle="Interactive transition, dissolution, and stress-testing simulation with deterministic risk trajectory modeling."
        crumbs={[{ label: 'GIEN Mesh', to: '/' }, { label: 'Scenario Planner' }]}
        actions={
          <button
            type="button"
            onClick={handleRunSimulation}
            className="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-md hover:bg-indigo-500 transition-colors"
          >
            <Play size={16} />
            Run Simulation
          </button>
        }
      />

      {/* STEP 1: SCENARIO TYPE SELECTION GRID (6 Cards) */}
      <section className="space-y-3">
        <h2 className="text-xs font-mono font-semibold uppercase tracking-wider text-gray-400">
          Step 1 — Select Simulation Arc Type
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {SCENARIO_TYPES.map((st) => {
            const isSelected = selectedScenarioId === st.id;
            return (
              <button
                key={st.id}
                type="button"
                onClick={() => setSelectedScenarioId(st.id)}
                className={`flex flex-col text-left p-4 rounded-xl border transition-all ${
                  isSelected
                    ? 'border-indigo-500 bg-indigo-950/40 shadow-lg ring-1 ring-indigo-500/50'
                    : 'border-gray-700/80 bg-gray-800/40 hover:bg-gray-800/80 hover:border-gray-600'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <div className="p-2 rounded-lg bg-gray-900 border border-gray-700/70">
                      {renderScenarioIcon(st.iconName)}
                    </div>
                    <span className="text-xs font-mono text-gray-400">{st.category}</span>
                  </div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-gray-900 text-indigo-300 border border-indigo-900/60">
                    {st.badge}
                  </span>
                </div>
                <h3 className="mt-3 text-sm font-semibold text-gray-100">{st.title}</h3>
                <p className="mt-1 text-xs text-gray-400 line-clamp-2">{st.description}</p>
              </button>
            );
          })}
        </div>
      </section>

      {/* STEP 2: CONFIGURATION PANEL */}
      <section className="rounded-xl border border-gray-700 bg-gray-800/50 p-5 space-y-5">
        <div className="flex items-center justify-between border-b border-gray-700/80 pb-3">
          <div>
            <h2 className="text-sm font-semibold text-gray-100 flex items-center gap-2">
              <Sliders size={16} className="text-indigo-400" />
              Step 2 — Configuration Parameters:{' '}
              <span className="text-indigo-300">
                {SCENARIO_TYPES.find((s) => s.id === selectedScenarioId)?.title}
              </span>
            </h2>
            <p className="text-xs text-gray-400 mt-0.5">
              Tune simulation inputs to evaluate invariant preservation and risk trajectories.
            </p>
          </div>
          <button
            type="button"
            onClick={handleRunSimulation}
            className="inline-flex items-center gap-1.5 rounded-md bg-indigo-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-indigo-500"
          >
            <Play size={14} /> Execute Arc
          </button>
        </div>

        {/* Phase Transition Config */}
        {selectedScenarioId === 'phase_transition' && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5 text-xs">
            <div>
              <label className="block font-medium text-gray-300 mb-1">Source Phase</label>
              <select
                value={phaseConfig.sourcePhase}
                onChange={(e) => setPhaseConfig((p) => ({ ...p, sourcePhase: e.target.value }))}
                className="w-full rounded-md border border-gray-700 bg-gray-900 px-3 py-2 text-gray-100 focus:border-indigo-500 focus:outline-none"
              >
                {GOVERNANCE_PHASES.map((ph) => (
                  <option key={ph.id} value={ph.id}>
                    Phase {ph.id} — {ph.name} ({ph.epoch})
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block font-medium text-gray-300 mb-1">Target Phase</label>
              <select
                value={phaseConfig.targetPhase}
                onChange={(e) => setPhaseConfig((p) => ({ ...p, targetPhase: e.target.value }))}
                className="w-full rounded-md border border-gray-700 bg-gray-900 px-3 py-2 text-gray-100 focus:border-indigo-500 focus:outline-none"
              >
                {GOVERNANCE_PHASES.filter((ph) => ph.id !== phaseConfig.sourcePhase).map((ph) => (
                  <option key={ph.id} value={ph.id}>
                    Phase {ph.id} — {ph.name} ({ph.epoch})
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block font-medium text-gray-300 mb-1">Invariant Preservation Mode</label>
              <div className="flex gap-2 mt-1">
                {(['STRICT', 'ADAPTIVE', 'EMERGENCY'] as const).map((mode) => (
                  <label
                    key={mode}
                    className={`flex-1 flex items-center justify-center gap-1 cursor-pointer rounded-md border px-2 py-1.5 text-center font-mono ${
                      phaseConfig.invariantMode === mode
                        ? 'border-indigo-500 bg-indigo-900/40 text-indigo-300 font-semibold'
                        : 'border-gray-700 bg-gray-900 text-gray-400 hover:text-gray-200'
                    }`}
                  >
                    <input
                      type="radio"
                      name="invariantMode"
                      checked={phaseConfig.invariantMode === mode}
                      onChange={() => setPhaseConfig((p) => ({ ...p, invariantMode: mode }))}
                      className="sr-only"
                    />
                    {mode}
                  </label>
                ))}
              </div>
            </div>

            <div>
              <label className="block font-medium text-gray-300 mb-1">Cryptographic Continuity</label>
              <div className="flex gap-2 mt-1">
                {(['FULL', 'PARTIAL', 'RESET'] as const).map((cc) => (
                  <label
                    key={cc}
                    className={`flex-1 flex items-center justify-center gap-1 cursor-pointer rounded-md border px-2 py-1.5 text-center font-mono ${
                      phaseConfig.cryptoContinuity === cc
                        ? 'border-indigo-500 bg-indigo-900/40 text-indigo-300 font-semibold'
                        : 'border-gray-700 bg-gray-900 text-gray-400 hover:text-gray-200'
                    }`}
                  >
                    <input
                      type="radio"
                      name="cryptoContinuity"
                      checked={phaseConfig.cryptoContinuity === cc}
                      onChange={() => setPhaseConfig((p) => ({ ...p, cryptoContinuity: cc }))}
                      className="sr-only"
                    />
                    {cc}
                  </label>
                ))}
              </div>
            </div>

            <div>
              <label className="block font-medium text-gray-300 mb-1">
                Transition Timeline Mode & Duration: <span className="font-mono text-indigo-300">{phaseConfig.timelineMonths} months</span>
              </label>
              <div className="flex items-center gap-3 mt-1">
                <input
                  type="range"
                  min={1}
                  max={120}
                  value={phaseConfig.timelineMonths}
                  onChange={(e) =>
                    setPhaseConfig((p) => ({ ...p, timelineMonths: parseInt(e.target.value, 10) }))
                  }
                  className="w-full accent-indigo-500"
                />
              </div>
              <div className="flex gap-2 mt-2">
                {(['IMMEDIATE', 'PHASED'] as const).map((tm) => (
                  <button
                    key={tm}
                    type="button"
                    onClick={() => setPhaseConfig((p) => ({ ...p, timelineMode: tm, timelineMonths: tm === 'IMMEDIATE' ? 1 : Math.max(12, p.timelineMonths) }))}
                    className={`px-2.5 py-1 rounded text-[11px] font-mono border ${
                      phaseConfig.timelineMode === tm
                        ? 'border-indigo-500 bg-indigo-950/60 text-indigo-300'
                        : 'border-gray-700 text-gray-400'
                    }`}
                  >
                    {tm}
                  </button>
                ))}
              </div>
            </div>

            <div className="md:col-span-2 lg:col-span-3 space-y-2">
              <label className="block font-medium text-gray-300">
                Framework Carryover ({phaseConfig.frameworks.length} selected)
              </label>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                {MAJOR_FRAMEWORKS.map((fw) => {
                  const checked = phaseConfig.frameworks.includes(fw);
                  return (
                    <label
                      key={fw}
                      onClick={() => toggleFramework(fw)}
                      className={`flex items-center gap-2 cursor-pointer p-2 rounded border text-xs ${
                        checked
                          ? 'border-indigo-500/80 bg-indigo-950/40 text-indigo-200'
                          : 'border-gray-700/80 bg-gray-900/60 text-gray-400 hover:text-gray-200'
                      }`}
                    >
                      <div
                        className={`w-4 h-4 rounded border flex items-center justify-center ${
                          checked ? 'border-indigo-500 bg-indigo-600 text-white' : 'border-gray-600'
                        }`}
                      >
                        {checked && <Check size={12} />}
                      </div>
                      <span className="truncate">{fw}</span>
                    </label>
                  );
                })}
              </div>
            </div>

            <div className="md:col-span-2 lg:col-span-3 space-y-2">
              <label className="block font-medium text-gray-300">
                Infinity Pillar Enfilade Activation ({phaseConfig.pillars.length} pillars)
              </label>
              <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-2">
                {INFINITY_PILLARS.map((p) => {
                  const active = phaseConfig.pillars.includes(p.id);
                  return (
                    <button
                      key={p.id}
                      type="button"
                      onClick={() => togglePillar(p.id)}
                      className={`p-2 rounded border text-left flex flex-col justify-between ${
                        active
                          ? 'border-indigo-500 bg-indigo-950/50 text-indigo-300'
                          : 'border-gray-700/80 bg-gray-900/60 text-gray-400 hover:text-gray-200'
                      }`}
                    >
                      <div className="flex items-center justify-between w-full">
                        <span className="font-mono text-xs font-bold">{p.id}</span>
                        <span className={`w-2 h-2 rounded-full ${active ? 'bg-indigo-400' : 'bg-gray-600'}`} />
                      </div>
                      <span className="text-[10px] text-gray-300 truncate mt-1">{p.name}</span>
                    </button>
                  );
                })}
              </div>
            </div>
          </div>
        )}

        {/* Ω-GAR Dissolution Arc Config */}
        {selectedScenarioId === 'omega_gar_dissolution' && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5 text-xs">
            <div>
              <label className="block font-medium text-gray-300 mb-1">Dissolution Trigger</label>
              <select
                value={omegaConfig.trigger}
                onChange={(e) =>
                  setOmegaConfig((p) => ({ ...p, trigger: e.target.value as OmegaGarDissolutionConfig['trigger'] }))
                }
                className="w-full rounded-md border border-gray-700 bg-gray-900 px-3 py-2 text-gray-100 focus:border-indigo-500 focus:outline-none"
              >
                <option value="SCHEDULED">SCHEDULED (Orderly 10-year arc)</option>
                <option value="EMERGENCY">EMERGENCY (Instantaneous containment)</option>
                <option value="TREATY-MANDATED">TREATY-MANDATED (Supranational clause)</option>
              </select>
            </div>

            <div>
              <label className="block font-medium text-gray-300 mb-1">Target Epoch Horizon</label>
              <select
                value={omegaConfig.targetEpoch}
                onChange={(e) =>
                  setOmegaConfig((p) => ({
                    ...p,
                    targetEpoch: e.target.value as OmegaGarDissolutionConfig['targetEpoch'],
                  }))
                }
                className="w-full rounded-md border border-gray-700 bg-gray-900 px-3 py-2 text-gray-100 focus:border-indigo-500 focus:outline-none"
              >
                <option value="2081">Epoch 2081 (Nominal Schedule)</option>
                <option value="2085">Epoch 2085</option>
                <option value="2090">Epoch 2090</option>
                <option value="2095">Epoch 2095</option>
                <option value="2100+">Epoch 2100+ (Deep Space)</option>
              </select>
            </div>

            <div>
              <label className="block font-medium text-gray-300 mb-1">Eternal Corpus Protocol</label>
              <div className="flex gap-2">
                {(['ACTIVE', 'STANDBY'] as const).map((st) => (
                  <button
                    key={st}
                    type="button"
                    onClick={() => setOmegaConfig((p) => ({ ...p, eternalCorpusProtocol: st }))}
                    className={`flex-1 py-2 rounded border text-center font-mono ${
                      omegaConfig.eternalCorpusProtocol === st
                        ? 'border-indigo-500 bg-indigo-950/60 text-indigo-300 font-semibold'
                        : 'border-gray-700 bg-gray-900 text-gray-400'
                    }`}
                  >
                    {st}
                  </button>
                ))}
              </div>
            </div>

            <div>
              <label className="block font-medium text-gray-300 mb-1">Beacon Signature Format</label>
              <select
                value={omegaConfig.beaconSignature}
                onChange={(e) =>
                  setOmegaConfig((p) => ({
                    ...p,
                    beaconSignature: e.target.value as OmegaGarDissolutionConfig['beaconSignature'],
                  }))
                }
                className="w-full rounded-md border border-gray-700 bg-gray-900 px-3 py-2 text-gray-100 focus:border-indigo-500 focus:outline-none"
              >
                <option value="STANDARD">STANDARD (Planetary broadcast)</option>
                <option value="ENHANCED">ENHANCED (Orbital relay mesh)</option>
                <option value="INTERSTELLAR">INTERSTELLAR (Triply redundant light-speed relay)</option>
              </select>
            </div>

            <div className="md:col-span-2">
              <label className="block font-medium text-gray-300 mb-1">Successor System Identifier</label>
              <input
                type="text"
                value={omegaConfig.successorSystem}
                onChange={(e) => setOmegaConfig((p) => ({ ...p, successorSystem: e.target.value }))}
                className="w-full rounded-md border border-gray-700 bg-gray-900 px-3 py-2 font-mono text-gray-100 focus:border-indigo-500 focus:outline-none"
                placeholder="e.g. Autonomous Post-Planetary Synthesis Mesh (APPS-01)"
              />
            </div>

            <div className="md:col-span-3 grid grid-cols-1 sm:grid-cols-3 gap-3 pt-2">
              <label className="flex items-center gap-2 cursor-pointer p-2.5 rounded border border-gray-700/80 bg-gray-900/60">
                <input
                  type="checkbox"
                  checked={omegaConfig.epitaphOmegaActive}
                  onChange={(e) => setOmegaConfig((p) => ({ ...p, epitaphOmegaActive: e.target.checked }))}
                  className="rounded border-gray-600 bg-gray-800 text-indigo-500 focus:ring-indigo-500"
                />
                <span className="font-mono text-indigo-300">GIEN-EPITAPH-OMEGA</span>
              </label>

              <label className="flex items-center gap-2 cursor-pointer p-2.5 rounded border border-gray-700/80 bg-gray-900/60">
                <input
                  type="checkbox"
                  checked={omegaConfig.invocationOmegaActive}
                  onChange={(e) => setOmegaConfig((p) => ({ ...p, invocationOmegaActive: e.target.checked }))}
                  className="rounded border-gray-600 bg-gray-800 text-indigo-500 focus:ring-indigo-500"
                />
                <span className="font-mono text-indigo-300">GIEN-INVOCATION-OMEGA</span>
              </label>

              <label className="flex items-center gap-2 cursor-pointer p-2.5 rounded border border-gray-700/80 bg-gray-900/60">
                <input
                  type="checkbox"
                  checked={omegaConfig.unifiedCodexSealed}
                  onChange={(e) => setOmegaConfig((p) => ({ ...p, unifiedCodexSealed: e.target.checked }))}
                  className="rounded border-gray-600 bg-gray-800 text-indigo-500 focus:ring-indigo-500"
                />
                <span className="font-mono text-indigo-300">GIEN-UNIFIED-CODEX-OMEGA Sealing</span>
              </label>
            </div>
          </div>
        )}

        {/* Successor Codex Config */}
        {selectedScenarioId === 'successor_codex' && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5 text-xs">
            <div>
              <label className="block font-medium text-gray-300 mb-1">Target Codex Version</label>
              <select
                value={successorConfig.targetCodexVersion}
                onChange={(e) =>
                  setSuccessorConfig((p) => ({
                    ...p,
                    targetCodexVersion: e.target.value as SuccessorCodexConfig['targetCodexVersion'],
                  }))
                }
                className="w-full rounded-md border border-gray-700 bg-gray-900 px-3 py-2 text-gray-100"
              >
                <option value="Codex v2.0">Codex v2.0 (Planetary Synthesis)</option>
                <option value="Codex v3.0">Codex v3.0 (Post-Planetary Mesh)</option>
                <option value="Codex v4.0">Codex v4.0 (Autonomous Recursive)</option>
                <option value="Codex v5.0">Codex v5.0 (Deep Space Transcendent)</option>
              </select>
            </div>

            <div>
              <label className="block font-medium text-gray-300 mb-1">
                Migration Window: <span className="font-mono text-indigo-300">{successorConfig.migrationWindowMonths} months</span>
              </label>
              <input
                type="range"
                min={1}
                max={60}
                value={successorConfig.migrationWindowMonths}
                onChange={(e) =>
                  setSuccessorConfig((p) => ({ ...p, migrationWindowMonths: parseInt(e.target.value, 10) }))
                }
                className="w-full accent-indigo-500 mt-2"
              />
            </div>

            <div>
              <label className="block font-medium text-gray-300 mb-1">Verification Mode</label>
              <select
                value={successorConfig.verificationMode}
                onChange={(e) =>
                  setSuccessorConfig((p) => ({
                    ...p,
                    verificationMode: e.target.value as SuccessorCodexConfig['verificationMode'],
                  }))
                }
                className="w-full rounded-md border border-gray-700 bg-gray-900 px-3 py-2 text-gray-100"
              >
                <option value="FORMAL">FORMAL (TLA+ Theorem Proved)</option>
                <option value="HYBRID">HYBRID (Statistical + Theorem)</option>
                <option value="EMPIRICAL">EMPIRICAL (Simulated Telemetry)</option>
              </select>
            </div>

            <div className="md:col-span-3 flex gap-4 pt-2">
              <label className="flex items-center gap-2 cursor-pointer text-gray-300">
                <input
                  type="checkbox"
                  checked={successorConfig.autoSealInvariants}
                  onChange={(e) => setSuccessorConfig((p) => ({ ...p, autoSealInvariants: e.target.checked }))}
                  className="rounded border-gray-600 bg-gray-800 text-indigo-500"
                />
                <span>Auto-Seal Active Invariant Gaps</span>
              </label>
              <label className="flex items-center gap-2 cursor-pointer text-gray-300">
                <input
                  type="checkbox"
                  checked={successorConfig.legacyQuarantine}
                  onChange={(e) => setSuccessorConfig((p) => ({ ...p, legacyQuarantine: e.target.checked }))}
                  className="rounded border-gray-600 bg-gray-800 text-indigo-500"
                />
                <span>Enable Legacy Data Quarantine</span>
              </label>
            </div>
          </div>
        )}

        {/* Invariant Stress Config */}
        {selectedScenarioId === 'invariant_stress_test' && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5 text-xs">
            <div>
              <label className="block font-medium text-gray-300 mb-1">Adversarial Attack Vector</label>
              <select
                value={stressConfig.attackVector}
                onChange={(e) =>
                  setStressConfig((p) => ({
                    ...p,
                    attackVector: e.target.value as InvariantStressConfig['attackVector'],
                  }))
                }
                className="w-full rounded-md border border-gray-700 bg-gray-900 px-3 py-2 text-gray-100"
              >
                <option value="QUANTUM_SPOOFING">QUANTUM_SPOOFING (PQC signature forgery attack)</option>
                <option value="CONCURRENCY_FLAW">CONCURRENCY_FLAW (State race condition loading)</option>
                <option value="BYZANTINE_SPLIT">BYZANTINE_SPLIT (Network partition split-brain)</option>
              </select>
            </div>

            <div>
              <label className="block font-medium text-gray-300 mb-1">
                Stress Load Multiplier: <span className="font-mono text-indigo-300">{stressConfig.stressLoadMultiplier}x</span>
              </label>
              <input
                type="range"
                min={15}
                max={50}
                step={1}
                value={stressConfig.stressLoadMultiplier * 10}
                onChange={(e) =>
                  setStressConfig((p) => ({ ...p, stressLoadMultiplier: parseInt(e.target.value, 10) / 10 }))
                }
                className="w-full accent-indigo-500 mt-2"
              />
            </div>

            <div>
              <label className="block font-medium text-gray-300 mb-1">
                Duration: <span className="font-mono text-indigo-300">{stressConfig.durationHours} hours</span>
              </label>
              <input
                type="range"
                min={1}
                max={72}
                value={stressConfig.durationHours}
                onChange={(e) =>
                  setStressConfig((p) => ({ ...p, durationHours: parseInt(e.target.value, 10) }))
                }
                className="w-full accent-indigo-500 mt-2"
              />
            </div>

            <div className="md:col-span-3 pt-2">
              <label className="flex items-center gap-2 cursor-pointer text-gray-300">
                <input
                  type="checkbox"
                  checked={stressConfig.autoSafeguard}
                  onChange={(e) => setStressConfig((p) => ({ ...p, autoSafeguard: e.target.checked }))}
                  className="rounded border-gray-600 bg-gray-800 text-indigo-500"
                />
                <span>Automatic Safeguard Engagement on Invariant Breach</span>
              </label>
            </div>
          </div>
        )}

        {/* Regulatory Shift Config */}
        {selectedScenarioId === 'regulatory_shift' && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5 text-xs">
            <div>
              <label className="block font-medium text-gray-300 mb-1">Target Regulatory Regime</label>
              <select
                value={regConfig.targetRegime}
                onChange={(e) =>
                  setRegConfig((p) => ({
                    ...p,
                    targetRegime: e.target.value as RegulatoryShiftConfig['targetRegime'],
                  }))
                }
                className="w-full rounded-md border border-gray-700 bg-gray-900 px-3 py-2 text-gray-100"
              >
                <option value="UN-GLOBAL-AI-TREATY">UN Global AI Governance Treaty</option>
                <option value="EU-AI-ACT-V2">EU AI Act v2.0 (Supranational Revision)</option>
                <option value="US-FEDERAL-AI-ACCORD">US Federal Executive Accord</option>
                <option value="SINGAPORE-FEAT-V3">Singapore FEAT v3.0 Framework</option>
              </select>
            </div>

            <div>
              <label className="block font-medium text-gray-300 mb-1">
                Grace Period: <span className="font-mono text-indigo-300">{regConfig.gracePeriodMonths} months</span>
              </label>
              <input
                type="range"
                min={3}
                max={36}
                value={regConfig.gracePeriodMonths}
                onChange={(e) =>
                  setRegConfig((p) => ({ ...p, gracePeriodMonths: parseInt(e.target.value, 10) }))
                }
                className="w-full accent-indigo-500 mt-2"
              />
            </div>

            <div>
              <label className="block font-medium text-gray-300 mb-1">Cross-Border Equivalence Mode</label>
              <select
                value={regConfig.crossBorderMode}
                onChange={(e) =>
                  setRegConfig((p) => ({
                    ...p,
                    crossBorderMode: e.target.value as RegulatoryShiftConfig['crossBorderMode'],
                  }))
                }
                className="w-full rounded-md border border-gray-700 bg-gray-900 px-3 py-2 text-gray-100"
              >
                <option value="HARMONIZED">HARMONIZED (Automatic reciprocity)</option>
                <option value="STRICT">STRICT (Unilateral verification)</option>
              </select>
            </div>
          </div>
        )}

        {/* Interstellar Handoff Config */}
        {selectedScenarioId === 'interstellar_handoff' && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5 text-xs">
            <div>
              <label className="block font-medium text-gray-300 mb-1">Target Deep Space Constellation</label>
              <select
                value={handoffConfig.targetConstellation}
                onChange={(e) =>
                  setHandoffConfig((p) => ({
                    ...p,
                    targetConstellation: e.target.value as InterstellarHandoffConfig['targetConstellation'],
                  }))
                }
                className="w-full rounded-md border border-gray-700 bg-gray-900 px-3 py-2 text-gray-100"
              >
                <option value="CENTAURI-ALPHA">Centauri-Alpha Relay Node</option>
                <option value="SOL-OUTER-COLONIES">Sol Outer Colonies (Kuiper Array)</option>
                <option value="DEEP-SPACE-RELAY">Deep Space Relay 09</option>
              </select>
            </div>

            <div>
              <label className="block font-medium text-gray-300 mb-1">Signal Round-Trip Latency</label>
              <select
                value={handoffConfig.signalLatencyHours}
                onChange={(e) =>
                  setHandoffConfig((p) => ({ ...p, signalLatencyHours: parseFloat(e.target.value) }))
                }
                className="w-full rounded-md border border-gray-700 bg-gray-900 px-3 py-2 text-gray-100"
              >
                <option value={1.2}>1.2 Hours (Lunar/Lagrange)</option>
                <option value={4.5}>4.5 Hours (Outer Sol)</option>
                <option value={24.0}>24.0 Hours (Kuiper Edge)</option>
                <option value={120.0}>120.0 Hours (Alpha Centauri Light-Speed Delay)</option>
              </select>
            </div>

            <div>
              <label className="block font-medium text-gray-300 mb-1">Interstellar Quorum Ratio</label>
              <select
                value={handoffConfig.quorumRatio}
                onChange={(e) =>
                  setHandoffConfig((p) => ({
                    ...p,
                    quorumRatio: e.target.value as InterstellarHandoffConfig['quorumRatio'],
                  }))
                }
                className="w-full rounded-md border border-gray-700 bg-gray-900 px-3 py-2 text-gray-100"
              >
                <option value="51%">51% Simple Majority</option>
                <option value="67%">67% Two-Thirds Treaty Supermajority</option>
                <option value="75%">75% Extended Supermajority</option>
                <option value="100%">100% Unanimous Consensus</option>
              </select>
            </div>
          </div>
        )}
      </section>

      {/* STEP 3: RESULTS PANEL */}
      {currentResult && (
        <div className="space-y-6">
          {/* Header & Outcome Score MetricCard */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="md:col-span-3 rounded-xl border border-gray-700 bg-gray-800/60 p-5 flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs text-indigo-400 font-semibold uppercase">
                    Simulation Outcome Report
                  </span>
                  <span className="font-mono text-xs text-gray-400">{currentResult.runTimestamp}</span>
                </div>
                <h2 className="text-lg font-bold text-gray-50 mt-1">{currentResult.scenarioTitle}</h2>
                <p className="text-xs text-gray-300 mt-1 leading-relaxed">{currentResult.summary}</p>
              </div>

              <div className="mt-4 flex flex-wrap items-center gap-3">
                <button
                  type="button"
                  onClick={() => setShowReport((prev) => !prev)}
                  className="inline-flex items-center gap-1.5 rounded-md bg-indigo-600/20 border border-indigo-500/40 px-3 py-1.5 text-xs font-semibold text-indigo-300 hover:bg-indigo-600/30"
                >
                  <FileText size={14} />
                  {showReport ? 'Hide Regulator Report' : 'Generate Regulator-Ready Report'}
                </button>
              </div>
            </div>

            <MetricCard
              label="Outcome Score"
              value={`${currentResult.outcomeScore}`}
              unit="/ 100"
              status={currentResult.overallStatus}
              footer={
                <span className="font-mono text-[11px] text-gray-400">
                  Status: {currentResult.overallStatus}
                </span>
              }
            />
          </div>

          {/* SVG Timeline of Events */}
          <div className="rounded-xl border border-gray-700 bg-gray-800/50 p-5 space-y-3">
            <h3 className="text-xs font-mono font-semibold uppercase text-gray-300 flex items-center gap-2">
              <Calendar size={14} className="text-indigo-400" />
              Event Timeline & Milestones
            </h3>
            <TimelineVisualization
              events={currentResult.events.map((e) => ({
                at: e.at,
                label: e.label,
                state: e.state,
              }))}
            />
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2 pt-2 border-t border-gray-700/60">
              {currentResult.events.map((ev) => (
                <div key={ev.step} className="rounded border border-gray-700/60 bg-gray-900/50 p-2 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="font-mono font-semibold text-indigo-300">{ev.at}</span>
                    <StatusBadge variant={ev.state === 'DONE' ? 'COMPLIANT' : ev.state === 'ACTIVE' ? 'ACTIVE' : ev.state === 'FAILED' ? 'CRITICAL' : 'PENDING'} label={ev.state} />
                  </div>
                  <p className="font-semibold text-gray-200 mt-1">{ev.label}</p>
                  <p className="text-[11px] text-gray-400 mt-0.5">{ev.description}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Multi-line SVG Chart for Risk Trajectories */}
          <div className="rounded-xl border border-gray-700 bg-gray-800/50 p-5 space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-mono font-semibold uppercase text-gray-300 flex items-center gap-2">
                <Activity size={14} className="text-indigo-400" />
                Systemic Risk Trajectories ({currentResult.riskTrajectories.length} Steps)
              </h3>
              <div className="flex items-center gap-4 text-xs font-mono">
                <span className="flex items-center gap-1.5 text-indigo-300">
                  <span className="w-3 h-0.5 bg-indigo-400 rounded-full" /> S_sys
                </span>
                <span className="flex items-center gap-1.5 text-amber-300">
                  <span className="w-3 h-0.5 bg-amber-400 rounded-full" /> G-SRI
                </span>
                <span className="flex items-center gap-1.5 text-red-300">
                  <span className="w-3 h-0.5 bg-red-400 rounded-full" /> C-SRI
                </span>
                <span className="flex items-center gap-1.5 text-violet-300">
                  <span className="w-3 h-0.5 bg-violet-400 rounded-full" /> p_doom
                </span>
              </div>
            </div>

            {/* Hand-rolled SVG Polyline Chart */}
            <div className="overflow-x-auto bg-gray-950 p-4 rounded-lg border border-gray-800">
              <svg viewBox="0 0 800 220" className="w-full h-auto min-w-[600px]" role="img" aria-label="Risk trajectory chart">
                {/* Horizontal Grid lines */}
                {[0, 0.25, 0.5, 0.75, 1.0].map((v) => {
                  const y = 180 - v * 150;
                  return (
                    <g key={v}>
                      <line x1={40} y1={y} x2={780} y2={y} stroke="#374151" strokeDasharray="3 3" strokeWidth={0.8} />
                      <text x={32} y={y + 3} fill="#6b7280" fontSize={9} textAnchor="end" fontFamily="monospace">
                        {v.toFixed(2)}
                      </text>
                    </g>
                  );
                })}

                {/* Plot trajectories */}
                {(() => {
                  const traj = currentResult.riskTrajectories;
                  if (traj.length < 2) return null;

                  const px = (i: number) => 50 + (i * (780 - 50)) / (traj.length - 1);
                  const py = (val: number) => 180 - Math.min(1, Math.max(0, val)) * 150;

                  const pathS = traj.map((t, i) => `${i === 0 ? 'M' : 'L'}${px(i)},${py(t.S_sys)}`).join(' ');
                  const pathG = traj.map((t, i) => `${i === 0 ? 'M' : 'L'}${px(i)},${py(t.G_SRI)}`).join(' ');
                  const pathC = traj.map((t, i) => `${i === 0 ? 'M' : 'L'}${px(i)},${py(t.C_SRI)}`).join(' ');
                  const pathP = traj.map((t, i) => `${i === 0 ? 'M' : 'L'}${px(i)},${py(t.p_doom)}`).join(' ');

                  return (
                    <>
                      {/* Polylines */}
                      <path d={pathS} fill="none" stroke="#818cf8" strokeWidth={2.5} />
                      <path d={pathG} fill="none" stroke="#f59e0b" strokeWidth={2} />
                      <path d={pathC} fill="none" stroke="#ef4444" strokeWidth={2} />
                      <path d={pathP} fill="none" stroke="#a78bfa" strokeWidth={2} strokeDasharray="4 2" />

                      {/* Step Points & X Labels */}
                      {traj.map((t, i) => {
                        const x = px(i);
                        return (
                          <g key={i}>
                            <line x1={x} y1={30} x2={x} y2={180} stroke="#1f2937" strokeWidth={0.5} />
                            <circle cx={x} cy={py(t.S_sys)} r={3} fill="#818cf8" />
                            <circle cx={x} cy={py(t.G_SRI)} r={2.5} fill="#f59e0b" />
                            <circle cx={x} cy={py(t.C_SRI)} r={2.5} fill="#ef4444" />
                            <circle cx={x} cy={py(t.p_doom)} r={2.5} fill="#a78bfa" />
                            <text x={x} y={198} fill="#9ca3af" fontSize={9} textAnchor="middle" fontFamily="monospace">
                              {t.label}
                            </text>
                          </g>
                        );
                      })}
                    </>
                  );
                })()}
              </svg>
            </div>
          </div>

          {/* Invariant Status Table Per Step */}
          <div className="rounded-xl border border-gray-700 bg-gray-800/50 p-5 space-y-3">
            <h3 className="text-xs font-mono font-semibold uppercase text-gray-300 flex items-center gap-2">
              <Layers size={14} className="text-indigo-400" />
              Constitutional Invariant Status Across Step Sequence
            </h3>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b border-gray-700 bg-gray-900/60 font-mono text-gray-400">
                    <th className="py-2.5 px-3">Step</th>
                    {currentResult.invariantStepStatuses[0]?.invariants.map((inv) => (
                      <th key={inv.id} className="py-2.5 px-2 text-center">
                        {inv.id}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-700/60 font-mono">
                  {currentResult.invariantStepStatuses.map((st) => (
                    <tr key={st.step} className="hover:bg-gray-800/40">
                      <td className="py-2 px-3 text-gray-300 font-semibold">{st.stepLabel}</td>
                      {st.invariants.map((inv) => (
                        <td key={inv.id} className="py-2 px-2 text-center">
                          <StatusBadge variant={inv.status} className="text-[10px]" />
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Compliance Impact & Recommendations */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            {/* Compliance Impacts */}
            <div className="rounded-xl border border-gray-700 bg-gray-800/50 p-5 space-y-3">
              <h3 className="text-xs font-mono font-semibold uppercase text-gray-300 flex items-center gap-2">
                <Globe size={14} className="text-emerald-400" />
                Compliance Framework Impact
              </h3>
              <div className="space-y-2.5">
                {currentResult.complianceImpacts.map((ci) => (
                  <div
                    key={ci.framework}
                    className="p-3 rounded-lg border border-gray-700/70 bg-gray-900/40 flex items-start justify-between gap-3 text-xs"
                  >
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-semibold text-gray-100">{ci.framework}</span>
                        <StatusBadge variant={ci.status} />
                      </div>
                      <p className="text-gray-400 mt-1">{ci.notes}</p>
                    </div>
                    <div className="text-right font-mono">
                      <span className="text-gray-400">{ci.prevScore}%</span>
                      <ChevronRight size={12} className="inline mx-1 text-gray-500" />
                      <span className={ci.newScore >= ci.prevScore ? 'text-emerald-400 font-bold' : 'text-amber-400 font-bold'}>
                        {ci.newScore}%
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Recommendations */}
            <div className="rounded-xl border border-gray-700 bg-gray-800/50 p-5 space-y-3">
              <h3 className="text-xs font-mono font-semibold uppercase text-gray-300 flex items-center gap-2">
                <Info size={14} className="text-indigo-400" />
                Simulation Guidance & Recommendations
              </h3>
              <ul className="space-y-2.5 text-xs">
                {currentResult.recommendations.map((rec, idx) => (
                  <li
                    key={idx}
                    className="p-3 rounded-lg border border-gray-700/60 bg-gray-900/40 flex items-start gap-2.5 text-gray-200"
                  >
                    {rec.startsWith('CRITICAL') || rec.startsWith('WARNING') ? (
                      <TriangleAlert size={16} className="text-amber-400 shrink-0 mt-0.5" />
                    ) : (
                      <Check size={16} className="text-emerald-400 shrink-0 mt-0.5" />
                    )}
                    <span>{rec}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          {/* Generated Regulator-Ready Report */}
          {showReport && (
            <div className="pt-2">
              <TaggedDocument title={currentResult.reportTitle} abstract={currentResult.reportAbstract}>
                <div className="whitespace-pre-line font-mono text-xs text-gray-300 leading-relaxed bg-gray-950 p-4 rounded-md border border-gray-800">
                  {currentResult.reportContent}
                </div>
              </TaggedDocument>
            </div>
          )}
        </div>
      )}

      {/* SCENARIO HISTORY SECTION */}
      <section className="rounded-xl border border-gray-700 bg-gray-800/40 p-5 space-y-3">
        <h2 className="text-xs font-mono font-semibold uppercase tracking-wider text-gray-300 flex items-center gap-2">
          <Clock size={14} className="text-indigo-400" />
          Simulation Run History ({history.length} runs recorded)
        </h2>

        <div className="space-y-2">
          {history.map((run) => (
            <div
              key={run.id}
              className="flex flex-wrap items-center justify-between gap-3 p-3 rounded-lg border border-gray-700/70 bg-gray-900/60 text-xs hover:bg-gray-900 transition-colors"
            >
              <div className="space-y-0.5">
                <div className="flex items-center gap-2">
                  <span className="font-semibold text-gray-100">{run.scenarioTitle}</span>
                  <StatusBadge variant={run.overallStatus} />
                  <span className="font-mono text-[10px] text-gray-500">{run.id}</span>
                </div>
                <p className="text-gray-400">{run.paramsSummary}</p>
                <span className="text-[10px] text-gray-500 font-mono">{run.timestamp}</span>
              </div>

              <div className="flex items-center gap-4">
                <div className="text-right">
                  <p className="text-[10px] uppercase text-gray-400">Score</p>
                  <p className="font-mono text-base font-bold text-gray-100">{run.outcomeScore}/100</p>
                </div>
                <button
                  type="button"
                  onClick={() => handleReloadHistoryRun(run)}
                  className="inline-flex items-center gap-1.5 rounded-md border border-gray-700 bg-gray-800 px-3 py-1.5 text-xs text-indigo-300 hover:bg-gray-700"
                >
                  <RotateCcw size={12} /> Reload Config
                </button>
              </div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
