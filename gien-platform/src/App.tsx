import { HashRouter, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider, ToastProvider, RoleProvider } from './contexts';
import Layout from './components/layout';
import ExecutiveSummary from './pages/ExecutiveSummary';
import GovernanceStacks from './pages/GovernanceStacks';
import GIENControlDomains from './pages/GIENControlDomains';
import SystemicRiskTelemetry from './pages/SystemicRiskTelemetry';
import ComplianceMatrix from './pages/ComplianceMatrix';
import OmniSentinelDashboard from './pages/OmniSentinelDashboard';
import SupervisoryDigitalTwin from './pages/SupervisoryDigitalTwin';
import ZeroTrustAttestation from './pages/ZeroTrustAttestation';
import VulnerabilityTracker from './pages/VulnerabilityTracker';
import RegulatoryRoadmap from './pages/RegulatoryRoadmap';
import GovernancePolicySimulator from './pages/GovernancePolicySimulator';
import PromptArchitect from './pages/PromptArchitect';
import RAGDataAudit from './pages/RAGDataAudit';
import RAGHealthMonitor from './pages/RAGHealthMonitor';
import HumanMeaningConstitution from './pages/HumanMeaningConstitution';
import ParityDashboard from './pages/ParityDashboard';
import RegulatorExport from './pages/RegulatorExport';
import GlobalGovernanceFrameworks from './pages/GlobalGovernanceFrameworks';
import LongHorizonGovernance from './pages/LongHorizonGovernance';
import AppWalkthrough from './pages/AppWalkthrough';
import AlertHistory from './pages/AlertHistory';

export default function App() {
  return (
    <ThemeProvider>
      <ToastProvider>
        <HashRouter>
          <RoleProvider>
            <Layout>
              <Routes>
                <Route path="/" element={<ExecutiveSummary />} />
                <Route path="/stacks" element={<GovernanceStacks />} />
                <Route path="/domains" element={<GIENControlDomains />} />
                <Route path="/telemetry" element={<SystemicRiskTelemetry />} />
                <Route path="/compliance" element={<ComplianceMatrix />} />
                <Route path="/omni-sentinel" element={<OmniSentinelDashboard />} />
                <Route path="/digital-twin" element={<SupervisoryDigitalTwin />} />
                <Route path="/zero-trust" element={<ZeroTrustAttestation />} />
                <Route path="/vulnerabilities" element={<VulnerabilityTracker />} />
                <Route path="/roadmap" element={<RegulatoryRoadmap />} />
                <Route path="/simulator" element={<GovernancePolicySimulator />} />
                <Route path="/prompt-architect" element={<PromptArchitect />} />
                <Route path="/rag-audit" element={<RAGDataAudit />} />
                <Route path="/rag-health" element={<RAGHealthMonitor />} />
                <Route path="/constitution" element={<HumanMeaningConstitution />} />
                <Route path="/parity" element={<ParityDashboard />} />
                <Route path="/export" element={<RegulatorExport />} />
                <Route path="/frameworks" element={<GlobalGovernanceFrameworks />} />
                <Route path="/long-horizon" element={<LongHorizonGovernance />} />
                <Route path="/walkthrough" element={<AppWalkthrough />} />
                <Route path="/alerts" element={<AlertHistory />} />
                <Route path="*" element={<Navigate to="/" replace />} />
              </Routes>
            </Layout>
          </RoleProvider>
        </HashRouter>
      </ToastProvider>
    </ThemeProvider>
  );
}
