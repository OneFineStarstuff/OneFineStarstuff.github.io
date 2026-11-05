import { BookOpen, Copy, ExternalLink, FileText, Filter, Search, Sparkles, Tag } from 'lucide-react';
import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import CodeBlock from '../components/CodeBlock';
import DetailDrawer from '../components/DetailDrawer';
import PageHeader from '../components/PageHeader';
import StatusBadge, { KV } from '../components/StatusBadge';
import Watermark, { usePreservedParams, watermarkProvenance } from '../components/Watermark';
import { useGovernance } from '../context/GovernanceContext';
import { useToast } from '../context/ToastContext';
import { GOVERNANCE_TEMPLATES, PromptTemplate } from '../data/ragData';

export default function Templates() {
  const { filingRef } = useGovernance();
  const { pushToast } = useToast();
  const getPreservedPath = usePreservedParams();
  const provenance = watermarkProvenance(filingRef);

  // Filter states
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedTemplate, setSelectedTemplate] = useState<PromptTemplate | null>(null);

  // Categories list derived from templates
  const categories = useMemo(() => {
    const set = new Set<string>();
    GOVERNANCE_TEMPLATES.forEach((t) => set.add(t.category));
    return ['ALL', ...Array.from(set)];
  }, []);

  // Filtered templates grid
  const filteredTemplates = useMemo(() => {
    return GOVERNANCE_TEMPLATES.filter((tpl) => {
      if (selectedCategory !== 'ALL' && tpl.category !== selectedCategory) return false;
      if (searchQuery) {
        const query = searchQuery.toLowerCase();
        const matchName = tpl.name.toLowerCase().includes(query);
        const matchDesc = tpl.description.toLowerCase().includes(query);
        const matchVar = tpl.variables.some((v) => v.toLowerCase().includes(query));
        if (!matchName && !matchDesc && !matchVar) return false;
      }
      return true;
    });
  }, [selectedCategory, searchQuery]);

  const copyTemplateBody = async (body: string, name: string) => {
    try {
      await navigator.clipboard.writeText(body);
      pushToast('SUCCESS', `Copied template "${name}" to clipboard.`);
    } catch {
      pushToast('ELEVATED', 'Failed to copy template text.');
    }
  };

  return (
    <div className="space-y-8 pb-12">
      <Watermark />

      <PageHeader
        title="Governance Template Library"
        subtitle="Standardized supervisory brief templates, incident runbooks, and audit cover notes with variable bindings."
        crumbs={[{ label: 'GIEN Governance', to: '/dashboard' }, { label: 'Templates' }]}
        actions={
          <div className="flex items-center gap-2">
            <span className="flex items-center gap-1.5 rounded-md border border-cyan-500/30 bg-cyan-500/10 px-3 py-1 text-xs font-semibold text-cyan-300">
              <BookOpen className="h-3.5 w-3.5" />
              8 Pre-Approved Templates
            </span>
          </div>
        }
      />

      {/* Filter and Search Bar */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between rounded-lg border border-gray-700 bg-gray-800/40 p-4">
        {/* Search Input */}
        <div className="relative flex-1">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-gray-400" />
          <input
            type="text"
            placeholder="Search templates by name, description, or variable..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full rounded-md border border-gray-700 bg-gray-900 pl-9 pr-4 py-1.5 text-xs text-gray-200 placeholder-gray-500 focus:border-indigo-500 focus:outline-none"
          />
        </div>

        {/* Category Filters */}
        <div className="flex flex-wrap items-center gap-1.5">
          {categories.map((cat) => (
            <button
              key={cat}
              type="button"
              onClick={() => setSelectedCategory(cat)}
              className={`rounded-md px-3 py-1 text-xs font-semibold transition-colors ${
                selectedCategory === cat
                  ? 'bg-indigo-600 text-white'
                  : 'border border-gray-700 bg-gray-900 text-gray-300 hover:bg-gray-800'
              }`}
            >
              {cat === 'ALL' ? 'All Templates (8)' : cat}
            </button>
          ))}
        </div>
      </div>

      {/* Templates Grid (8 cards) */}
      <section aria-label="Governance Templates Grid">
        {filteredTemplates.length > 0 ? (
          <div className="grid grid-cols-1 gap-6 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
            {filteredTemplates.map((tpl) => (
              <div
                key={tpl.id}
                onClick={() => setSelectedTemplate(tpl)}
                role="button"
                tabIndex={0}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') setSelectedTemplate(tpl);
                }}
                className="group relative cursor-pointer rounded-lg border border-gray-700 bg-gray-800/50 p-5 transition-all hover:border-indigo-500/70 hover:bg-gray-800/90 flex flex-col justify-between"
              >
                <div className="space-y-3">
                  <div className="flex items-start justify-between gap-2">
                    <span className="rounded bg-indigo-500/20 border border-indigo-500/40 px-2 py-0.5 text-[10px] font-bold text-indigo-300 uppercase tracking-wider">
                      {tpl.category}
                    </span>
                    <span className="font-mono text-[10px] text-gray-400">{tpl.version}</span>
                  </div>

                  <div>
                    <h3 className="text-sm font-bold text-gray-100 group-hover:text-indigo-300 transition-colors">
                      {tpl.name}
                    </h3>
                    <p className="mt-1 text-xs text-gray-400 line-clamp-2 leading-relaxed">
                      {tpl.description}
                    </p>
                  </div>

                  {/* Variables Chips */}
                  <div className="space-y-1 pt-2">
                    <span className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider block">
                      Variables Used ({tpl.variables.length})
                    </span>
                    <div className="flex flex-wrap gap-1">
                      {tpl.variables.map((v) => (
                        <span
                          key={v}
                          className="rounded bg-gray-900 px-1.5 py-0.5 font-mono text-[10px] text-cyan-300 border border-gray-700/60"
                        >
                          {v}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>

                <div className="mt-4 flex items-center justify-between border-t border-gray-700/60 pt-3 text-[11px] text-gray-400">
                  <span>Updated: <strong className="font-mono text-gray-300">{tpl.lastUpdated}</strong></span>
                  <span className="text-indigo-400 font-semibold group-hover:translate-x-0.5 transition-transform">
                    Inspect Template →
                  </span>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="rounded-lg border border-gray-700 bg-gray-800/40 p-12 text-center text-gray-400">
            No governance templates match your filter query.
          </div>
        )}
      </section>

      {/* Template Detail Drawer */}
      <DetailDrawer
        open={selectedTemplate !== null}
        onClose={() => setSelectedTemplate(null)}
        title={selectedTemplate ? selectedTemplate.name : 'Template Detail'}
        subtitle={selectedTemplate ? `${selectedTemplate.category} Template (${selectedTemplate.version})` : undefined}
      >
        {selectedTemplate && (
          <div className="space-y-6 p-1">
            <div className="space-y-2">
              <span className="text-xs font-semibold uppercase tracking-wider text-gray-400">
                Description & Scope
              </span>
              <p className="text-xs text-gray-200 leading-relaxed">{selectedTemplate.description}</p>
            </div>

            <div className="space-y-2">
              <span className="text-xs font-semibold uppercase tracking-wider text-gray-400">
                Template Variables
              </span>
              <div className="flex flex-wrap gap-1.5">
                {selectedTemplate.variables.map((v) => (
                  <span
                    key={v}
                    className="rounded bg-gray-800 px-2 py-1 font-mono text-xs text-cyan-300 border border-gray-700"
                  >
                    {v}
                  </span>
                ))}
              </div>
            </div>

            <div className="space-y-2">
              <span className="text-xs font-semibold uppercase tracking-wider text-gray-400">
                Template Source Body
              </span>
              <CodeBlock code={selectedTemplate.body} language="markdown" maxHeight="max-h-80" />
            </div>

            {/* Action Buttons inside Drawer */}
            <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between border-t border-gray-700 pt-4">
              <button
                type="button"
                onClick={() => copyTemplateBody(selectedTemplate.body, selectedTemplate.name)}
                className="inline-flex items-center justify-center gap-1.5 rounded border border-gray-700 bg-gray-800 px-4 py-2 text-xs font-semibold text-gray-200 hover:bg-gray-700 transition-colors"
              >
                <Copy className="h-4 w-4 text-cyan-400" /> Copy Template Text
              </button>

              <Link
                to={getPreservedPath(`/prompt-architect?prompt=${encodeURIComponent(selectedTemplate.body)}`)}
                className="inline-flex items-center justify-center gap-1.5 rounded bg-indigo-600 px-4 py-2 text-xs font-semibold text-white shadow hover:bg-indigo-500 transition-colors"
              >
                <ExternalLink className="h-4 w-4" /> Use in Prompt Architect
              </Link>
            </div>
          </div>
        )}
      </DetailDrawer>
    </div>
  );
}
