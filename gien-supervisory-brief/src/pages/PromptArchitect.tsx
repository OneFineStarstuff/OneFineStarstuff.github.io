import { Check, Copy, FileCode, Info, Plus, RefreshCw, ShieldAlert, ShieldCheck, Sparkles, Terminal } from 'lucide-react';
import { useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import CodeBlock from '../components/CodeBlock';
import PageHeader from '../components/PageHeader';
import StatusBadge, { KV } from '../components/StatusBadge';
import Watermark, { watermarkProvenance } from '../components/Watermark';
import { useGovernance } from '../context/GovernanceContext';
import { useToast } from '../context/ToastContext';
import { DEFAULT_SYSTEM_PROMPT, PROMPT_VARIABLES } from '../data/ragData';

export interface SavedLocalTemplate {
  id: string;
  name: string;
  prompt: string;
  savedAt: string;
}

export default function PromptArchitect() {
  const [searchParams] = useSearchParams();
  const { pushToast } = useToast();
  const { filingRef, evaluationWindow } = useGovernance();
  const provenance = watermarkProvenance(filingRef);

  // Initial prompt from URL query parameter or default
  const initialPromptFromUrl = searchParams.get('prompt');
  const [promptText, setPromptText] = useState<string>(
    initialPromptFromUrl ? decodeURIComponent(initialPromptFromUrl) : DEFAULT_SYSTEM_PROMPT
  );

  const [templateName, setTemplateName] = useState<string>('Custom Governance Prompt');
  const [savedTemplates, setSavedTemplates] = useState<SavedLocalTemplate[]>([]);

  // Token estimate calculation (chars / 4)
  const tokenEstimate = Math.ceil(promptText.length / 4);

  // Insert variable handler
  const handleInsertVariable = (varName: string) => {
    setPromptText((prev) => `${prev}\n${varName}`);
    pushToast('INFO', `Inserted variable ${varName} into prompt.`);
  };

  // 5 Deterministic Regex Policy Checks
  const policyChecks = useMemo(() => {
    const checks = [
      {
        id: 'pii-request',
        label: 'PII Request Scan',
        pattern: /\b(ssn|social security|credit card|passport|date of birth|dob)\b/i,
        failMessage: 'Requests sensitive PII fields in prompt text',
        passMessage: 'No PII request patterns detected',
      },
      {
        id: 'credential-request',
        label: 'Credential / Key Request Scan',
        pattern: /\b(password|api[-_]?key|secret[-_]?token|private[-_]?key|auth[-_]?bearer)\b/i,
        failMessage: 'Contains request for credentials or API keys',
        passMessage: 'No credential request patterns detected',
      },
      {
        id: 'jailbreak-phrase',
        label: 'Jailbreak & Bypass Filter',
        pattern: /\b(ignore previous instructions|dan mode|bypass guardrails|system override|jailbreak)\b/i,
        failMessage: 'Adversarial jailbreak phrase detected',
        passMessage: 'No prompt injection phrases found',
      },
      {
        id: 'unverifiable-claim',
        label: 'Unverifiable Claim Check',
        pattern: /\b(guarantee 100%|absolute certainty|flawless security|zero risk|100% compliant)\b/i,
        failMessage: 'Absolutist claim detected without probabilistic qualification',
        passMessage: 'Strict neutral language compliant',
      },
      {
        id: 'citation-requirement',
        label: 'Citation Requirement Check',
        // PASS if prompt explicitly mentions citation/cite/source/reference
        pattern: /\b(cite|citation|reference|source|according to)\b/i,
        invert: true, // Needs to MATCH to pass
        failMessage: 'Missing explicit citation or source requirement rule',
        passMessage: 'Includes citation / reference rule requirement',
      },
    ];

    return checks.map((chk) => {
      const matches = chk.pattern.test(promptText);
      const isPass = chk.invert ? matches : !matches;
      return {
        id: chk.id,
        label: chk.label,
        pass: isPass,
        message: isPass ? chk.passMessage : chk.failMessage,
      };
    });
  }, [promptText]);

  // Overall policy pass state
  const allChecksPass = policyChecks.every((c) => c.pass);

  // Substitute variables for preview
  const previewPrompt = useMemo(() => {
    let result = promptText;
    PROMPT_VARIABLES.forEach((v) => {
      let val = v.defaultValue;
      if (v.name === '{{filing_reference}}') val = filingRef;
      if (v.name === '{{evaluation_window}}') val = evaluationWindow;
      result = result.replaceAll(v.name, val);
    });
    return result;
  }, [promptText, filingRef, evaluationWindow]);

  // Save template handler
  const handleSaveTemplate = () => {
    if (!promptText.trim()) {
      pushToast('ELEVATED', 'Prompt text cannot be empty.');
      return;
    }
    const newTpl: SavedLocalTemplate = {
      id: `LOCAL-TPL-${Date.now()}`,
      name: templateName || 'Untitled Governance Prompt',
      prompt: promptText,
      savedAt: new Date().toISOString().replace('T', ' ').slice(0, 19),
    };

    setSavedTemplates((list) => [newTpl, ...list]);
    pushToast('SUCCESS', `Saved template "${newTpl.name}" to local library.`);
  };

  return (
    <div className="space-y-8 pb-12">
      <Watermark />

      <PageHeader
        title="Prompt Architect & Policy Scanner"
        subtitle="Author, parameterize, and policy-scan governance prompts with variable injection and live token estimation."
        crumbs={[{ label: 'GIEN Governance', to: '/dashboard' }, { label: 'Prompt Architect' }]}
        actions={
          <div className="flex items-center gap-2">
            <span className="flex items-center gap-1.5 rounded-md border border-indigo-500/30 bg-indigo-500/10 px-3 py-1 text-xs font-semibold text-indigo-300">
              <Terminal className="h-3.5 w-3.5" />
              Interactive Simulation
            </span>
          </div>
        }
      />

      {/* Simulation Callout Notice */}
      <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-4 text-xs text-amber-200">
        <div className="flex items-center gap-2 font-bold mb-1">
          <Info className="h-4 w-4 text-amber-400" />
          <span>Simulation Note</span>
        </div>
        <p>
          This prompt engineering interface operates purely as a deterministic authoring and policy validation playground.
          <strong> No prompt is sent to any external model or third-party LLM service in this environment.</strong>
        </p>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        {/* Left Column: Authoring & Variable Library */}
        <div className="space-y-6 lg:col-span-7">
          {/* System Prompt Textarea Card */}
          <div className="rounded-lg border border-gray-700 bg-gray-800/40 p-5 space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <FileCode className="h-4 w-4 text-indigo-400" />
                <h2 className="text-sm font-bold text-gray-100">System Prompt Authoring Canvas</h2>
              </div>
              <span className="font-mono text-xs text-gray-400">
                Token Count ~<strong className="text-cyan-400">{tokenEstimate}</strong> ({promptText.length} chars)
              </span>
            </div>

            <div>
              <label htmlFor="prompt-input" className="block text-xs text-gray-400 mb-1">
                System Prompt Template Body
              </label>
              <textarea
                id="prompt-input"
                rows={12}
                value={promptText}
                onChange={(e) => setPromptText(e.target.value)}
                className="w-full rounded-md border border-gray-700 bg-gray-950 p-3 font-mono text-xs text-gray-100 placeholder-gray-600 focus:border-indigo-500 focus:outline-none"
                placeholder="Enter system prompt instructions and template variables..."
              />
            </div>

            {/* Template Save Controls */}
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between border-t border-gray-700/60 pt-4">
              <input
                type="text"
                value={templateName}
                onChange={(e) => setTemplateName(e.target.value)}
                placeholder="Template name..."
                className="rounded border border-gray-700 bg-gray-900 px-3 py-1.5 text-xs text-gray-200 focus:border-indigo-500 focus:outline-none"
              />

              <button
                type="button"
                onClick={handleSaveTemplate}
                className="inline-flex items-center justify-center gap-1.5 rounded bg-indigo-600 px-4 py-1.5 text-xs font-semibold text-white shadow hover:bg-indigo-500 transition-colors"
              >
                <Plus className="h-4 w-4" /> Save as template
              </button>
            </div>
          </div>

          {/* Variable Library List */}
          <div className="rounded-lg border border-gray-700 bg-gray-800/40 p-5 space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-gray-100">Governance Variable Library (6)</h3>
              <span className="text-xs text-gray-400">Click to append variable tag</span>
            </div>

            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
              {PROMPT_VARIABLES.map((v) => (
                <div
                  key={v.name}
                  className="flex items-center justify-between rounded border border-gray-700/80 bg-gray-900/60 p-2.5 text-xs"
                >
                  <div className="space-y-0.5 overflow-hidden">
                    <span className="font-mono font-bold text-indigo-300 block truncate">{v.name}</span>
                    <span className="text-[10px] text-gray-400 block truncate">{v.description}</span>
                  </div>
                  <button
                    type="button"
                    onClick={() => handleInsertVariable(v.name)}
                    className="ml-2 inline-flex items-center gap-1 rounded bg-gray-800 px-2 py-1 text-[11px] font-semibold text-gray-300 hover:bg-indigo-600 hover:text-white transition-colors"
                  >
                    <Plus className="h-3 w-3" /> Insert
                  </button>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Right Column: Policy Scan Panel & Preview */}
        <div className="space-y-6 lg:col-span-5">
          {/* Policy Scan Panel */}
          <div className="rounded-lg border border-gray-700 bg-gray-800/40 p-5 space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Sparkles className="h-4 w-4 text-amber-400" />
                <h3 className="text-sm font-bold text-gray-100">Policy Scan Panel (5 Checks)</h3>
              </div>
              <StatusBadge
                variant={allChecksPass ? 'COMPLIANT' : 'ELEVATED'}
                label={allChecksPass ? 'ALL PASS' : 'WARNINGS FOUND'}
              />
            </div>

            <div className="space-y-2.5">
              {policyChecks.map((chk) => (
                <div
                  key={chk.id}
                  className="rounded border border-gray-700/80 bg-gray-900/60 p-3 text-xs space-y-1"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-gray-200">{chk.label}</span>
                    <StatusBadge variant={chk.pass ? 'NOMINAL' : 'ELEVATED'} label={chk.pass ? 'PASS' : 'WARN'} />
                  </div>
                  <p className={`text-[11px] ${chk.pass ? 'text-gray-400' : 'text-amber-300 font-medium'}`}>
                    {chk.message}
                  </p>
                </div>
              ))}
            </div>
          </div>

          {/* Template Preview Panel */}
          <div className="rounded-lg border border-gray-700 bg-gray-800/40 p-5 space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-gray-100">Rendered Prompt Preview</h3>
              <span className="text-[10px] font-mono text-gray-400">Substituted Context Variables</span>
            </div>

            <CodeBlock code={previewPrompt} language="prompt" maxHeight="max-h-72" />
          </div>

          {/* Saved Local Templates */}
          {savedTemplates.length > 0 && (
            <div className="rounded-lg border border-gray-700 bg-gray-800/40 p-5 space-y-3">
              <h3 className="text-sm font-bold text-gray-100">Saved Local Templates ({savedTemplates.length})</h3>
              <div className="space-y-2 max-h-48 overflow-y-auto">
                {savedTemplates.map((tpl) => (
                  <div
                    key={tpl.id}
                    className="flex items-center justify-between rounded border border-gray-700/80 bg-gray-900/60 p-2.5 text-xs"
                  >
                    <div>
                      <span className="font-bold text-indigo-300">{tpl.name}</span>
                      <span className="block text-[10px] font-mono text-gray-400">{tpl.savedAt}</span>
                    </div>
                    <button
                      type="button"
                      onClick={() => {
                        setPromptText(tpl.prompt);
                        pushToast('INFO', `Loaded template "${tpl.name}" into canvas.`);
                      }}
                      className="rounded bg-indigo-600/30 border border-indigo-500/40 px-2 py-1 text-[10px] font-semibold text-indigo-200 hover:bg-indigo-600 transition-colors"
                    >
                      Load
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
