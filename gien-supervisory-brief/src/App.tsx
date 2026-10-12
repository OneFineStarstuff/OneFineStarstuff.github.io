import { Route, Routes } from 'react-router-dom';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import RiskIndices from './pages/RiskIndices';
import Compliance from './pages/Compliance';
import GovernanceStacks from './pages/GovernanceStacks';
import ControlDomains from './pages/ControlDomains';
import CryptographicIntegrity from './pages/CryptographicIntegrity';
import DigitalTwin from './pages/DigitalTwin';
import ScenarioPlanner from './pages/ScenarioPlanner';
import Constitutional from './pages/Constitutional';
import SubmissionPackages from './pages/SubmissionPackages';
import LongHorizon from './pages/LongHorizon';

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Dashboard />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/risk-indices" element={<RiskIndices />} />
        <Route path="/compliance" element={<Compliance />} />
        <Route path="/governance-stacks" element={<GovernanceStacks />} />
        <Route path="/control-domains" element={<ControlDomains />} />
        <Route path="/cryptographic-integrity" element={<CryptographicIntegrity />} />
        <Route path="/digital-twin" element={<DigitalTwin />} />
        <Route path="/scenario-planner" element={<ScenarioPlanner />} />
        <Route path="/constitutional" element={<Constitutional />} />
        <Route path="/submission-packages" element={<SubmissionPackages />} />
        <Route path="/long-horizon" element={<LongHorizon />} />
      </Route>
    </Routes>
  );
}
