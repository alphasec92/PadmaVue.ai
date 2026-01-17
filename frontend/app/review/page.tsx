'use client';

import { useState, useEffect, Suspense } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield, AlertTriangle, CheckCircle2, XCircle, ChevronDown, ChevronRight,
  FileSearch, Target, Zap, Users, Eye, RotateCcw, Edit3, Plus, Download,
  Layers, RefreshCw, Filter, Search, BarChart3, GitBranch, Network, Calendar, Clock
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { api, Threat, AnalysisResponse } from '@/lib/api';
import { ThreatEditor } from '@/components/threat-editor';
import { DiagramEditor } from '@/components/diagram-editor';
import { ExportModal } from '@/components/export-modal';
import { AnalysisHistory, AnalysisSelector } from '@/components/analysis-history';
import { OWASPBadge, OWASPInlineBadges, AIThreatSummary } from '@/components/owasp-badge';
import { MaestroCard, MaestroBadge } from '@/components/maestro-card';
import { useProjectStore } from '@/store/project-store';

// Add Bot icon for AI indicators
import { Bot } from 'lucide-react';

// MAESTRO category colors
const MAESTRO_COLORS: Record<string, string> = {
  'AGENT01': 'bg-watercolor-coral',
  'AGENT02': 'bg-watercolor-pink', 
  'AGENT03': 'bg-watercolor-slate',
  'AGENT04': 'bg-watercolor-blue',
  'AGENT05': 'bg-purple-500',
  'AGENT06': 'bg-amber-500',
};

const STRIDE_COLORS: Record<string, string> = {
  'S': 'bg-red-500', 'Spoofing': 'bg-red-500',
  'T': 'bg-orange-500', 'Tampering': 'bg-orange-500',
  'R': 'bg-yellow-500', 'Repudiation': 'bg-yellow-500',
  'I': 'bg-blue-500', 'Information Disclosure': 'bg-blue-500',
  'D': 'bg-purple-500', 'Denial of Service': 'bg-purple-500',
  'E': 'bg-pink-500', 'Elevation of Privilege': 'bg-pink-500',
};

const SEVERITY_CONFIG: Record<string, { color: string; bg: string; icon: any }> = {
  critical: { color: 'text-red-500', bg: 'bg-red-500/10', icon: XCircle },
  high: { color: 'text-orange-500', bg: 'bg-orange-500/10', icon: AlertTriangle },
  medium: { color: 'text-yellow-500', bg: 'bg-yellow-500/10', icon: AlertTriangle },
  low: { color: 'text-green-500', bg: 'bg-green-500/10', icon: CheckCircle2 },
};

// Main page wrapper with Suspense for useSearchParams
export default function ReviewPage() {
  return (
    <Suspense fallback={
      <div className="min-h-screen pt-24 px-4 flex items-center justify-center">
        <motion.div animate={{ rotate: 360 }} transition={{ duration: 1, repeat: Infinity, ease: 'linear' }}>
          <RefreshCw className="w-8 h-8 text-primary" />
        </motion.div>
      </div>
    }>
      <ReviewPageContent />
    </Suspense>
  );
}

function ReviewPageContent() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const { currentAnalysis, setCurrentAnalysis, setProjectId, projectId } = useProjectStore();
  const [analysis, setAnalysis] = useState<AnalysisResponse | null>(null);
  const [threats, setThreats] = useState<Threat[]>([]);
  const [loading, setLoading] = useState(true);
  const [expandedThreat, setExpandedThreat] = useState<string | null>(null);
  const [editingThreat, setEditingThreat] = useState<Threat | null>(null);
  const [showDiagramEditor, setShowDiagramEditor] = useState(false);
  const [showExportModal, setShowExportModal] = useState(false);
  const [filterSeverity, setFilterSeverity] = useState<string>('all');
  const [filterCategory, setFilterCategory] = useState<string>('all');
  const [filterMethodology, setFilterMethodology] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [zones, setZones] = useState<Array<{ id: string; name: string }>>([]);
  const [projectName, setProjectName] = useState<string>('');

  useEffect(() => {
    // Check URL params first, then store
    const analysisIdFromUrl = searchParams.get('analysis_id');
    const analysisIdToUse = analysisIdFromUrl || currentAnalysis;
    
    if (analysisIdToUse) {
      if (analysisIdFromUrl && analysisIdFromUrl !== currentAnalysis) {
        // Update store with URL param
        setCurrentAnalysis(analysisIdFromUrl);
      }
      loadAnalysis(analysisIdToUse);
    } else {
      // Try to load most recent analysis
      loadRecentAnalysis();
    }
  }, [searchParams, currentAnalysis]);

  const loadRecentAnalysis = async () => {
    try {
      setLoading(true);
      // Fetch list of analyses and load the most recent one
      const analyses = await api.request<{ analyses: any[] }>('/api/analyze/list');
      if (analyses.analyses && analyses.analyses.length > 0) {
        const mostRecent = analyses.analyses[0];
        setCurrentAnalysis(mostRecent.id);
        loadAnalysis(mostRecent.id);
      } else {
        setLoading(false);
      }
    } catch (e) {
      console.error('Failed to load recent analysis:', e);
      setLoading(false);
    }
  };

  const loadAnalysis = async (id: string) => {
    try {
      setLoading(true);
      const data = await api.getAnalysis(id);
      setAnalysis(data);
      setThreats(data.threats || []);
      setProjectId(data.project_id);
      
      // Load project name
      try {
        const projects = await api.listProjects();
        const project = projects.find((p: any) => p.id === data.project_id);
        if (project) {
          setProjectName(project.name);
        }
      } catch (e) {}
      
      // Load diagram metadata for zones
      try {
        const diagram = await api.getDiagram(id);
        if (diagram.metadata?.zones) {
          setZones(diagram.metadata.zones);
        }
      } catch (e) {}
    } catch (e) {
      console.error('Failed to load analysis:', e);
    } finally {
      setLoading(false);
    }
  };

  const handleSelectAnalysis = (analysisId: string, newProjectId: string) => {
    setCurrentAnalysis(analysisId);
    setProjectId(newProjectId);
    router.push(`/review?analysis_id=${analysisId}`);
    loadAnalysis(analysisId);
  };

  const handleSaveThreat = async (threat: Threat) => {
    try {
      await api.updateThreat(threat.id, threat);
      setThreats(threats.map(t => t.id === threat.id ? threat : t));
      setEditingThreat(null);
    } catch (e) {
      console.error('Failed to save threat:', e);
    }
  };

  const handleDeleteThreat = async (id: string) => {
    try {
      await api.deleteThreat(id);
      setThreats(threats.filter(t => t.id !== id));
      setEditingThreat(null);
    } catch (e) {
      console.error('Failed to delete threat:', e);
    }
  };

  const handleAddThreat = async () => {
    if (!analysis) return;
    try {
      const result = await api.createThreat({
        analysis_id: analysis.analysis_id,
        title: 'New Threat',
        description: 'Describe the threat...',
        category: 'Information Disclosure',
        severity: 'medium',
        stride_category: 'I',
        mitigations: [],
      });
      setThreats([...threats, result.threat]);
      setEditingThreat(result.threat);
    } catch (e) {
      console.error('Failed to create threat:', e);
    }
  };

  const handleSaveDiagram = async (code: string, meta: any) => {
    if (!analysis) return;
    try {
      await api.updateDiagram(analysis.analysis_id, { mermaid_code: code, ...meta });
      setShowDiagramEditor(false);
      if (meta.zones) setZones(meta.zones);
    } catch (e) {
      console.error('Failed to save diagram:', e);
    }
  };

  const handleExport = () => {
    setShowExportModal(true);
  };

  const filteredThreats = threats.filter(t => {
    if (filterSeverity !== 'all' && t.severity?.toLowerCase() !== filterSeverity) return false;
    if (filterCategory !== 'all' && t.category !== filterCategory) return false;
    if (filterMethodology !== 'all' && (t.methodology || 'stride') !== filterMethodology) return false;
    if (searchQuery && !t.title.toLowerCase().includes(searchQuery.toLowerCase()) && !t.description.toLowerCase().includes(searchQuery.toLowerCase())) return false;
    return true;
  });
  
  // Check if MAESTRO threats exist
  const hasMaestroThreats = threats.some(t => t.methodology === 'maestro');

  const categories = Array.from(new Set(threats.map(t => t.category)));
  const stats = {
    total: threats.length,
    critical: threats.filter(t => t.severity === 'critical').length,
    high: threats.filter(t => t.severity === 'high').length,
    medium: threats.filter(t => t.severity === 'medium').length,
    low: threats.filter(t => t.severity === 'low').length,
    mitigated: threats.filter(t => t.status === 'mitigated').length,
  };

  if (loading) {
    return (
      <div className="min-h-screen pt-24 px-4 flex items-center justify-center">
        <motion.div animate={{ rotate: 360 }} transition={{ duration: 1, repeat: Infinity, ease: 'linear' }}>
          <RefreshCw className="w-8 h-8 text-primary" />
        </motion.div>
      </div>
    );
  }

  if (!analysis) {
    return (
      <div className="min-h-screen pt-24 px-4">
        <div className="max-w-4xl mx-auto">
          {/* Header */}
          <div className="text-center mb-8">
            <div className="inline-flex items-center gap-3 mb-4">
              <div className="p-3 rounded-2xl bg-primary/10"><Shield className="w-8 h-8 text-primary" /></div>
              <h1 className="text-3xl font-bold">Threat Insights</h1>
            </div>
            <p className="text-muted-foreground">Select an analysis to review or start a new one</p>
          </div>
          
          {/* Analysis History */}
          <div className="rounded-2xl glass p-6 mb-6">
            <AnalysisHistory 
              onSelect={handleSelectAnalysis}
              showNavigation={false}
            />
          </div>
          
          {/* New Analysis CTA */}
          <div className="text-center">
            <a href="/upload" className="inline-flex items-center gap-2 px-6 py-3 rounded-xl bg-primary text-white hover:bg-primary/90 transition-colors">
              <Plus className="w-5 h-5" />
              Start New Analysis
            </a>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen pt-24 pb-12 px-4">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="flex flex-col gap-4 mb-8">
          {/* Top row: Project selector + actions */}
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
            <div className="flex items-center gap-3 flex-wrap">
              <AnalysisSelector 
                currentAnalysisId={analysis.analysis_id}
                onSelect={handleSelectAnalysis}
              />
              <span className={cn('px-2 py-1 rounded-lg text-xs font-medium uppercase', analysis.methodology?.toLowerCase() === 'stride' ? 'bg-blue-500/20 text-blue-500' : 'bg-purple-500/20 text-purple-500')}>
                {analysis.methodology}
              </span>
              {analysis.created_at && (
                <span className="flex items-center gap-1 text-xs text-muted-foreground">
                  <Calendar className="w-3 h-3" />
                  {new Date(analysis.created_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit' })}
                </span>
              )}
            </div>
            <div className="flex items-center gap-2 flex-wrap">
              <motion.button whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.98 }}
                onClick={() => window.location.href = `/dfd?analysis_id=${analysis?.analysis_id}`}
                className="flex items-center gap-2 px-3 py-2 rounded-xl border border-border hover:bg-muted text-sm">
                <Network className="w-4 h-4" />DFD
              </motion.button>
            <motion.button whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.98 }} onClick={() => setShowDiagramEditor(true)}
                className="flex items-center gap-2 px-3 py-2 rounded-xl border border-border hover:bg-muted text-sm">
                <GitBranch className="w-4 h-4" />Edit
            </motion.button>
            <motion.button whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.98 }} onClick={handleAddThreat}
                className="flex items-center gap-2 px-3 py-2 rounded-xl border border-border hover:bg-muted text-sm">
                <Plus className="w-4 h-4" />Threat
            </motion.button>
            <motion.button whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.98 }} onClick={handleExport}
                className="flex items-center gap-2 px-3 py-2 rounded-xl bg-primary text-white text-sm">
              <Download className="w-4 h-4" />Export
            </motion.button>
            </div>
          </div>
          
          {/* Project info row */}
          <div className="flex items-center gap-4">
            <div className="p-2 rounded-xl bg-primary/10"><Shield className="w-6 h-6 text-primary" /></div>
            <div>
              <h1 className="text-xl font-bold">{projectName || 'Threat Model Review'}</h1>
              <p className="text-sm text-muted-foreground">
                Analysis ID: <code className="text-xs bg-muted px-1 rounded">{analysis.analysis_id.slice(0, 8)}...</code>
                {analysis.completed_at && (
                  <> • Completed: {new Date(analysis.completed_at).toLocaleString()}</>
                )}
              </p>
            </div>
          </div>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-2 md:grid-cols-6 gap-4 mb-8">
          {[
            { label: 'Total', value: stats.total, icon: Shield, color: 'text-primary' },
            { label: 'Critical', value: stats.critical, icon: XCircle, color: 'text-red-500' },
            { label: 'High', value: stats.high, icon: AlertTriangle, color: 'text-orange-500' },
            { label: 'Medium', value: stats.medium, icon: AlertTriangle, color: 'text-yellow-500' },
            { label: 'Low', value: stats.low, icon: CheckCircle2, color: 'text-green-500' },
            { label: 'Mitigated', value: stats.mitigated, icon: CheckCircle2, color: 'text-emerald-500' },
          ].map(s => (
            <motion.div key={s.label} whileHover={{ scale: 1.02 }} className="p-4 rounded-2xl glass">
              <div className="flex items-center gap-2 mb-1">
                <s.icon className={cn('w-4 h-4', s.color)} />
                <span className="text-sm text-muted-foreground">{s.label}</span>
              </div>
              <p className={cn('text-2xl font-bold', s.color)}>{s.value}</p>
            </motion.div>
          ))}
        </div>

        {/* MAESTRO Applicability Card (if analysis includes MAESTRO) */}
        {analysis.maestro_applicability && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="mb-8"
          >
            <MaestroCard 
              applicability={analysis.maestro_applicability}
              threats={threats.filter(t => t.methodology === 'maestro')}
            />
          </motion.div>
        )}

        {/* Filters */}
        <div className="flex flex-wrap items-center gap-3 mb-6">
          <div className="relative flex-1 min-w-[200px]">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <input value={searchQuery} onChange={e => setSearchQuery(e.target.value)} placeholder="Search threats..."
              className="w-full pl-10 pr-4 py-2 rounded-xl bg-background dark:bg-muted border border-border focus:border-primary outline-none transition-colors" />
          </div>
          <select value={filterSeverity} onChange={e => setFilterSeverity(e.target.value)}
            className="px-4 py-2 rounded-xl bg-background dark:bg-muted border border-border focus:border-primary outline-none transition-colors cursor-pointer">
            <option value="all">All Severities</option>
            {['critical', 'high', 'medium', 'low'].map(s => <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>)}
          </select>
          <select value={filterCategory} onChange={e => setFilterCategory(e.target.value)}
            className="px-4 py-2 rounded-xl bg-background dark:bg-muted border border-border focus:border-primary outline-none transition-colors cursor-pointer">
            <option value="all">All Categories</option>
            {categories.map(c => <option key={c} value={c}>{c}</option>)}
          </select>
          {/* Methodology Filter */}
          <select value={filterMethodology} onChange={e => setFilterMethodology(e.target.value)}
            className="px-4 py-2 rounded-xl bg-background dark:bg-muted border border-border focus:border-primary outline-none transition-colors cursor-pointer">
            <option value="all">All Methodologies</option>
            <option value="stride">STRIDE</option>
            <option value="pasta">PASTA</option>
            {hasMaestroThreats && <option value="maestro">MAESTRO</option>}
          </select>
        </div>

        {/* Threats List */}
        <div className="space-y-4">
          {filteredThreats.length === 0 ? (
            <div className="text-center py-12 text-muted-foreground">
              <AlertTriangle className="w-12 h-12 mx-auto mb-3 opacity-50" />
              <p>No threats match your filters</p>
            </div>
          ) : (
            filteredThreats.map((threat, idx) => {
              const severity = SEVERITY_CONFIG[threat.severity?.toLowerCase() || 'medium'];
              const isExpanded = expandedThreat === threat.id;
              const isMaestro = threat.methodology === 'maestro';
              const categoryColor = isMaestro 
                ? (MAESTRO_COLORS[threat.category] || 'bg-watercolor-coral')
                : (STRIDE_COLORS[threat.stride_category || threat.category] || 'bg-gray-500');
              
              return (
                <motion.div key={threat.id} initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: idx * 0.05 }}
                  className={cn(
                    'rounded-2xl glass overflow-hidden',
                    isMaestro && 'border border-watercolor-coral/30'
                  )}>
                  {/* Header */}
                  <div className="p-4 flex items-center gap-4 cursor-pointer hover:bg-muted/50" onClick={() => setExpandedThreat(isExpanded ? null : threat.id)}>
                    <div className={cn('w-10 h-10 rounded-xl flex items-center justify-center', categoryColor)}>
                      {isMaestro ? (
                        <Bot className="w-5 h-5 text-white" />
                      ) : (
                        <span className="text-white font-bold">{threat.stride_category || threat.category?.charAt(0)}</span>
                      )}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <h3 className="font-semibold truncate">{threat.title}</h3>
                        {threat.status === 'mitigated' && <CheckCircle2 className="w-4 h-4 text-green-500" />}
                        {isMaestro && (
                          <span className="px-1.5 py-0.5 rounded text-xs bg-watercolor-coral/20 text-watercolor-coral font-medium">
                            MAESTRO
                          </span>
                        )}
                      </div>
                      <p className="text-sm text-muted-foreground truncate">{threat.affected_component}</p>
                    </div>
                    {/* OWASP badges */}
                    {threat.owasp_mappings && (
                      <OWASPInlineBadges mappings={threat.owasp_mappings} />
                    )}
                    <span className={cn('px-3 py-1 rounded-lg text-xs font-medium capitalize', severity.bg, severity.color)}>
                      {threat.severity}
                    </span>
                    <div className="text-sm text-muted-foreground">Risk: {threat.overall_risk?.toFixed(1)}</div>
                    <motion.button onClick={e => { e.stopPropagation(); setEditingThreat(threat); }}
                      className="p-2 rounded-lg hover:bg-muted"><Edit3 className="w-4 h-4" /></motion.button>
                    <ChevronDown className={cn('w-5 h-5 transition-transform', isExpanded && 'rotate-180')} />
                  </div>

                  {/* Expanded Content */}
                  <AnimatePresence>
                    {isExpanded && (
                      <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }}
                        className="border-t border-border/50">
                        <div className="p-4 grid md:grid-cols-2 gap-6">
                          <div>
                            <h4 className="font-medium mb-2">Description</h4>
                            <p className="text-sm text-muted-foreground">{threat.description}</p>
                            
                            <h4 className="font-medium mt-4 mb-2">Attack Vector</h4>
                            <p className="text-sm text-muted-foreground">{threat.attack_vector || 'Not specified'}</p>

                            {threat.zone && (
                              <div className="mt-4">
                                <h4 className="font-medium mb-2">Zone</h4>
                                <span className="px-2 py-1 rounded bg-amber-500/20 text-amber-500 text-sm">{zones.find(z => z.id === threat.zone)?.name || threat.zone}</span>
                              </div>
                            )}
                          </div>
                          <div>
                            <h4 className="font-medium mb-2">DREAD Score</h4>
                            <div className="grid grid-cols-5 gap-2 mb-4">
                              {[
                                { key: 'damage', label: 'D', icon: Target },
                                { key: 'reproducibility', label: 'R', icon: RotateCcw },
                                { key: 'exploitability', label: 'E', icon: Zap },
                                { key: 'affected_users', label: 'A', icon: Users },
                                { key: 'discoverability', label: 'D', icon: Eye },
                              ].map(d => (
                                <div key={d.key} className="text-center p-2 rounded-lg bg-muted">
                                  <d.icon className="w-4 h-4 mx-auto mb-1 text-muted-foreground" />
                                  <div className="text-lg font-bold">{threat.dread_score?.[d.key] || '-'}</div>
                                </div>
                              ))}
                            </div>

                            <h4 className="font-medium mb-2">Mitigations ({threat.mitigations?.length || 0})</h4>
                            <div className="space-y-2">
                              {threat.mitigations?.map((m, i) => (
                                <div key={i} className="flex items-start gap-2 text-sm">
                                  <CheckCircle2 className="w-4 h-4 text-green-500 mt-0.5 shrink-0" />
                                  <span>{m}</span>
                                </div>
                              ))}
                              {(!threat.mitigations || threat.mitigations.length === 0) && (
                                <p className="text-sm text-muted-foreground">No mitigations defined</p>
                              )}
                            </div>
                            
                            {/* OWASP Mappings Section */}
                            {threat.owasp_mappings && (
                              <OWASPBadge mappings={threat.owasp_mappings} />
                            )}
                          </div>
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </motion.div>
              );
            })
          )}
        </div>
      </div>

      {/* Threat Editor Modal */}
      <AnimatePresence>
        {editingThreat && (
          <ThreatEditor
            threat={editingThreat as any}
            zones={zones}
            onSave={handleSaveThreat as any}
            onDelete={handleDeleteThreat}
            onClose={() => setEditingThreat(null)}
          />
        )}
      </AnimatePresence>

      {/* Diagram Editor Modal */}
      <AnimatePresence>
        {showDiagramEditor && (
          <DiagramEditor
            initialCode={analysis.dfd_mermaid || ''}
            initialMeta={analysis.metadata?.diagram}
            onSave={handleSaveDiagram}
            onClose={() => setShowDiagramEditor(false)}
          />
        )}
      </AnimatePresence>

      {/* Export Modal */}
      <ExportModal
        isOpen={showExportModal}
        onClose={() => setShowExportModal(false)}
        analysisId={analysis?.analysis_id || ''}
        projectName={analysis?.project_id}
        methodology={analysis?.methodology}
        threatCount={threats.length}
      />
    </div>
  );
}
