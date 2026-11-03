import { Navigate, Route, Routes } from 'react-router-dom';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import ExecutiveSummary from './pages/ExecutiveSummary';
import RiskIndices from './pages/RiskIndices';
import Compliance from './pages/Compliance';
import GovernanceStacks from './pages/GovernanceStacks';
import ControlDomains from './pages/ControlDomains';
import CryptographicIntegrity from './pages/CryptographicIntegrity';
import DigitalTwin from './pages/DigitalTwin';
import ScenarioPlanner from './pages/ScenarioPlanner';
import PolicySimulator from './pages/PolicySimulator';
import Constitutional from './pages/Constitutional';
import SubmissionPackages from './pages/SubmissionPackages';
import LongHorizon from './pages/LongHorizon';
import Roadmap from './pages/Roadmap';
import RagHealth from './pages/RagHealth';
import RagAudit from './pages/RagAudit';
import PromptArchitect from './pages/PromptArchitect';
import Templates from './pages/Templates';
import AlertHistory from './pages/AlertHistory';
import VoiceCommander from './pages/VoiceCommander';

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/executive-summary" element={<ExecutiveSummary />} />
        <Route path="/risk-indices" element={<RiskIndices />} />
        <Route path="/compliance" element={<Compliance />} />
        <Route path="/governance-stacks" element={<GovernanceStacks />} />
        <Route path="/control-domains" element={<ControlDomains />} />
        <Route path="/cryptographic-integrity" element={<CryptographicIntegrity />} />
        <Route path="/digital-twin" element={<DigitalTwin />} />
        <Route path="/scenario-planner" element={<ScenarioPlanner />} />
        <Route path="/policy-simulator" element={<PolicySimulator />} />
        <Route path="/constitutional" element={<Constitutional />} />
        <Route path="/submission-packages" element={<SubmissionPackages />} />
        <Route path="/long-horizon" element={<LongHorizon />} />
        <Route path="/roadmap" element={<Roadmap />} />
        <Route path="/rag-health" element={<RagHealth />} />
        <Route path="/rag-audit" element={<RagAudit />} />
        <Route path="/prompt-architect" element={<PromptArchitect />} />
        <Route path="/templates" element={<Templates />} />
        <Route path="/alerts" element={<AlertHistory />} />
        <Route path="/voice" element={<VoiceCommander />} />
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Route>
    </Routes>
  );
}
