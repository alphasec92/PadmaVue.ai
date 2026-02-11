'use client';

import { useState, useEffect, Suspense } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield, AlertTriangle, CheckCircle2, XCircle, ChevronDown, ChevronRight,
  FileSearch, Target, Zap, Users, Eye, RotateCcw, Edit3, Plus, Download,
  Layers, RefreshCw, Filter, Search, BarChart3, GitBranch, Network, Calendar, Clock,
  MapPin, ArrowRight, Link2, ShieldCheck, ShieldAlert, Activity, Info, HelpCircle,
  Play, Pause, CheckSquare, User, ExternalLink
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

const MITIGATION_TYPE_CONFIG = {
  prevent: { color: 'bg-blue-500', textColor: 'text-blue-500', bgLight: 'bg-blue-500/10', icon: ShieldCheck, label: 'Prevent' },
  detect: { color: 'bg-amber-500', textColor: 'text-amber-500', bgLight: 'bg-amber-500/10', icon: Activity, label: 'Detect' },
  respond: { color: 'bg-purple-500', textColor: 'text-purple-500', bgLight: 'bg-purple-500/10', icon: Play, label: 'Respond' },
};

const MITIGATION_STATUS_CONFIG = {
  planned: { color: 'bg-slate-500', label: 'Planned', icon: Pause },
  in_progress: { color: 'bg-amber-500', label: 'In Progress', icon: Play },
  implemented: { color: 'bg-green-500', label: 'Implemented', icon: CheckSquare },
};

// Component chip for navigating to flow map
function ComponentChip({ componentId, name, onClick }: { componentId: string; name?: string; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-blue-500/10 text-blue-500 text-xs font-medium hover:bg-blue-500/20 transition-colors"
    >
      <MapPin className="w-3 h-3" />
      {name || componentId}
      <ExternalLink className="w-3 h-3 opacity-60" />
    </button>
  );
}

// Flow chip for navigating to flow map with focus
function FlowChip({ flowId, name, onClick }: { flowId: string; name?: string; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-purple-500/10 text-purple-500 text-xs font-medium hover:bg-purple-500/20 transition-colors"
    >
      <ArrowRight className="w-3 h-3" />
      {name || flowId}
      <ExternalLink className="w-3 h-3 opacity-60" />
    </button>
  );
}

// Structured mitigation display
function StructuredMitigationCard({ mitigation }: { mitigation: any }) {
  const typeConfig = MITIGATION_TYPE_CONFIG[mitigation.mitigation_type as keyof typeof MITIGATION_TYPE_CONFIG] || MITIGATION_TYPE_CONFIG.prevent;
  const statusConfig = MITIGATION_STATUS_CONFIG[mitigation.status as keyof typeof MITIGATION_STATUS_CONFIG] || MITIGATION_STATUS_CONFIG.planned;
  
  return (
    <div className="p-3 rounded-lg bg-muted/50 space-y-2">
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-start gap-2 flex-1">
          <typeConfig.icon className={cn("w-4 h-4 mt-0.5 shrink-0", typeConfig.textColor)} />
          <span className="text-sm">{mitigation.text}</span>
        </div>
        <span className={cn("px-2 py-0.5 rounded text-xs font-medium text-white shrink-0", statusConfig.color)}>
          {statusConfig.label}
        </span>
      </div>
      {(mitigation.owner || (mitigation.verification && mitigation.verification.length > 0)) && (
        <div className="flex flex-wrap items-center gap-3 text-xs text-muted-foreground pl-6">
          {mitigation.owner && (
            <span className="flex items-center gap-1">
              <User className="w-3 h-3" />
              {mitigation.owner}
            </span>
          )}
          {mitigation.verification && mitigation.verification.length > 0 && (
            <span className="flex items-center gap-1">
              <CheckSquare className="w-3 h-3" />
              {mitigation.verification.length} verification{mitigation.verification.length !== 1 ? 's' : ''}
            </span>
          )}
        </div>
      )}
    </div>
  );
}

// Mitigations grouped by type
function GroupedMitigations({ mitigations }: { mitigations: any[] }) {
  const grouped = {
    prevent: mitigations.filter(m => m.mitigation_type === 'prevent'),
    detect: mitigations.filter(m => m.mitigation_type === 'detect'),
    respond: mitigations.filter(m => m.mitigation_type === 'respond'),
  };
  
  return (
    <div className="space-y-4">
      {Object.entries(grouped).map(([type, mits]) => {
        if (mits.length === 0) return null;
        const config = MITIGATION_TYPE_CONFIG[type as keyof typeof MITIGATION_TYPE_CONFIG];
        return (
          <div key={type}>
            <h5 className={cn("text-sm font-medium mb-2 flex items-center gap-2", config.textColor)}>
              <config.icon className="w-4 h-4" />
              {config.label} ({mits.length})
            </h5>
            <div className="space-y-2">
              {mits.map((m, i) => (
                <StructuredMitigationCard key={m.id || i} mitigation={m} />
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}

// Scoring explanation tooltip/accordion
function ScoringExplanation({ threat }: { threat: Threat }) {
  const [isOpen, setIsOpen] = useState(false);
  
  if (!threat.scoring_explanation) return null;
  
  return (
    <div className="mt-2">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
      >
        <HelpCircle className="w-3 h-3" />
        How score is calculated
        <ChevronDown className={cn("w-3 h-3 transition-transform", isOpen && "rotate-180")} />
      </button>
      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="overflow-hidden"
          >
            <div className="mt-2 p-3 rounded-lg bg-muted/50 text-xs">
              <div className="flex items-center gap-2 mb-1 text-muted-foreground">
                <Info className="w-3 h-3" />
                <span className="font-medium">{threat.scoring_model || 'DREAD_AVG_V1'}</span>
              </div>
              <p className="text-muted-foreground leading-relaxed">{threat.scoring_explanation}</p>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

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
                        <div className="p-4 space-y-6">
                          
                          {/* NEW: Where This Happens Section */}
                          <div className="p-4 rounded-xl bg-gradient-to-r from-blue-500/5 to-purple-500/5 border border-blue-500/10">
                            <h4 className="font-medium mb-3 flex items-center gap-2">
                              <MapPin className="w-4 h-4 text-blue-500" />
                              Where This Happens
                            </h4>
                            <div className="flex flex-wrap gap-2">
                              {/* Components */}
                              {threat.affected_component_ids && threat.affected_component_ids.length > 0 ? (
                                threat.affected_component_ids.map(compId => (
                                  <ComponentChip
                                    key={compId}
                                    componentId={compId}
                                    onClick={() => router.push(`/dfd?analysis_id=${analysis?.analysis_id}&focusComponent=${compId}`)}
                                  />
                                ))
                              ) : threat.affected_component ? (
                                <ComponentChip
                                  componentId={threat.affected_component}
                                  name={threat.affected_component}
                                  onClick={() => router.push(`/dfd?analysis_id=${analysis?.analysis_id}`)}
                                />
                              ) : null}
                              
                              {/* Flows */}
                              {threat.impacted_flow_ids && threat.impacted_flow_ids.length > 0 && (
                                threat.impacted_flow_ids.map(flowId => (
                                  <FlowChip
                                    key={flowId}
                                    flowId={flowId}
                                    onClick={() => router.push(`/dfd?analysis_id=${analysis?.analysis_id}&focus=${flowId}`)}
                                  />
                                ))
                              )}
                              
                              {/* Trust Boundaries */}
                              {threat.trust_boundaries && threat.trust_boundaries.length > 0 && (
                                threat.trust_boundaries.map(tb => (
                                  <span key={tb} className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-amber-500/10 text-amber-500 text-xs font-medium">
                                    <Shield className="w-3 h-3" />
                                    {tb}
                                  </span>
                                ))
                              )}
                              
                              {/* None linked message */}
                              {(!threat.affected_component_ids || threat.affected_component_ids.length === 0) &&
                               (!threat.impacted_flow_ids || threat.impacted_flow_ids.length === 0) &&
                               !threat.affected_component && (
                                <span className="text-sm text-muted-foreground flex items-center gap-2">
                                  <Link2 className="w-4 h-4" />
                                  No components/flows linked yet
                                  <button 
                                    onClick={(e) => { e.stopPropagation(); setEditingThreat(threat); }}
                                    className="text-primary hover:underline"
                                  >
                                    Link now
                                  </button>
                                </span>
                              )}
                            </div>
                            
                            {/* Assets Impacted */}
                            {threat.assets_impacted && threat.assets_impacted.length > 0 && (
                              <div className="mt-3 pt-3 border-t border-border/50">
                                <span className="text-xs text-muted-foreground mr-2">Assets at risk:</span>
                                {threat.assets_impacted.map(asset => (
                                  <span key={asset} className="inline-flex items-center px-2 py-0.5 rounded bg-red-500/10 text-red-500 text-xs font-medium mr-1">
                                    {asset}
                                  </span>
                                ))}
                              </div>
                            )}
                          </div>

                          {/* NEW: Attack Scenario Section */}
                          {(threat.preconditions?.length > 0 || threat.attack_scenario_steps?.length > 0 || threat.impact_narrative || threat.scenario) && (
                            <div className="p-4 rounded-xl bg-gradient-to-r from-red-500/5 to-orange-500/5 border border-red-500/10">
                              <h4 className="font-medium mb-3 flex items-center gap-2">
                                <Target className="w-4 h-4 text-red-500" />
                                Attack Scenario
                              </h4>
                              
                              {/* Preconditions */}
                              {threat.preconditions && threat.preconditions.length > 0 && (
                                <div className="mb-3">
                                  <h5 className="text-xs font-medium text-muted-foreground uppercase mb-2">Preconditions</h5>
                                  <ul className="space-y-1">
                                    {threat.preconditions.map((pre, i) => (
                                      <li key={i} className="flex items-start gap-2 text-sm">
                                        <span className="w-1.5 h-1.5 rounded-full bg-amber-500 mt-2 shrink-0" />
                                        {pre}
                                      </li>
                                    ))}
                                  </ul>
                                </div>
                              )}
                              
                              {/* Attack Steps */}
                              {threat.attack_scenario_steps && threat.attack_scenario_steps.length > 0 && (
                                <div className="mb-3">
                                  <h5 className="text-xs font-medium text-muted-foreground uppercase mb-2">Attack Steps</h5>
                                  <ol className="space-y-2">
                                    {threat.attack_scenario_steps.map((step, i) => (
                                      <li key={i} className="flex items-start gap-3 text-sm">
                                        <span className="flex items-center justify-center w-5 h-5 rounded-full bg-red-500/20 text-red-500 text-xs font-bold shrink-0">
                                          {i + 1}
                                        </span>
                                        {step}
                                      </li>
                                    ))}
                                  </ol>
                                </div>
                              )}
                              
                              {/* Legacy scenario field */}
                              {threat.scenario && !threat.attack_scenario_steps?.length && (
                                <p className="text-sm text-muted-foreground leading-relaxed mb-3">{threat.scenario}</p>
                              )}
                              
                              {/* Impact Narrative */}
                              {threat.impact_narrative && (
                                <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20">
                                  <h5 className="text-xs font-medium text-red-500 uppercase mb-1">Impact</h5>
                                  <p className="text-sm font-medium">{threat.impact_narrative}</p>
                                </div>
                              )}
                            </div>
                          )}

                          <div className="grid md:grid-cols-2 gap-6">
                            {/* Left Column: Description & Details */}
                            <div className="space-y-4">
                              <div>
                                <h4 className="font-medium mb-2">Description</h4>
                                <p className="text-sm text-muted-foreground">{threat.description}</p>
                              </div>
                              
                              <div>
                                <h4 className="font-medium mb-2">Attack Vector</h4>
                                <p className="text-sm text-muted-foreground">{threat.attack_vector || 'Not specified'}</p>
                              </div>

                              {threat.zone && (
                                <div>
                                  <h4 className="font-medium mb-2">Zone</h4>
                                  <span className="px-2 py-1 rounded bg-amber-500/20 text-amber-500 text-sm">
                                    {zones.find(z => z.id === threat.zone)?.name || threat.zone}
                                  </span>
                                </div>
                              )}
                              
                              {/* References Section */}
                              {threat.references && threat.references.length > 0 && (
                                <div>
                                  <h4 className="font-medium mb-2 flex items-center gap-2">
                                    <FileSearch className="w-4 h-4 text-blue-500" />
                                    Security References
                                  </h4>
                                  <div className="space-y-1">
                                    {threat.references.map((ref, i) => {
                                      const match = ref.match(/\[(.+?)\]\((.+?)\)/);
                                      return match ? (
                                        <a
                                          key={i}
                                          href={match[2]}
                                          target="_blank"
                                          rel="noopener noreferrer"
                                          className="flex items-center gap-2 text-sm text-blue-500 hover:text-blue-400 hover:underline transition-colors"
                                        >
                                          <span className="w-1.5 h-1.5 rounded-full bg-blue-500" />
                                          {match[1]}
                                        </a>
                                      ) : (
                                        <span key={i} className="text-sm text-muted-foreground">{ref}</span>
                                      );
                                    })}
                                  </div>
                                </div>
                              )}
                              
                              {/* OWASP Mappings */}
                              {threat.owasp_mappings && (
                                <OWASPBadge mappings={threat.owasp_mappings} />
                              )}
                            </div>
                            
                            {/* Right Column: Risk & Mitigations */}
                            <div className="space-y-4">
                              {/* DREAD Score with Explanation */}
                              <div>
                                <h4 className="font-medium mb-2 flex items-center gap-2">
                                  DREAD Score
                                  {threat.confidence && (
                                    <span className={cn(
                                      "px-2 py-0.5 rounded text-xs font-medium",
                                      threat.confidence === 'high' ? 'bg-green-500/20 text-green-500' :
                                      threat.confidence === 'low' ? 'bg-red-500/20 text-red-500' :
                                      'bg-amber-500/20 text-amber-500'
                                    )}>
                                      {threat.confidence} confidence
                                    </span>
                                  )}
                                </h4>
                                <div className="grid grid-cols-5 gap-2">
                                  {[
                                    { key: 'damage', label: 'D', icon: Target, title: 'Damage' },
                                    { key: 'reproducibility', label: 'R', icon: RotateCcw, title: 'Reproducibility' },
                                    { key: 'exploitability', label: 'E', icon: Zap, title: 'Exploitability' },
                                    { key: 'affected_users', label: 'A', icon: Users, title: 'Affected Users' },
                                    { key: 'discoverability', label: 'D', icon: Eye, title: 'Discoverability' },
                                  ].map(d => (
                                    <div key={d.key} className="text-center p-2 rounded-lg bg-muted" title={d.title}>
                                      <d.icon className="w-4 h-4 mx-auto mb-1 text-muted-foreground" />
                                      <div className="text-lg font-bold">{threat.dread_score?.[d.key] || '-'}</div>
                                    </div>
                                  ))}
                                </div>
                                <ScoringExplanation threat={threat} />
                              </div>

                              {/* Mitigations Section - Structured or Legacy */}
                              <div>
                                <h4 className="font-medium mb-3 flex items-center gap-2">
                                  <ShieldCheck className="w-4 h-4 text-green-500" />
                                  Mitigations
                                </h4>
                                
                                {/* Use structured mitigations if available */}
                                {threat.structured_mitigations && threat.structured_mitigations.length > 0 ? (
                                  <GroupedMitigations mitigations={threat.structured_mitigations} />
                                ) : (
                                  /* Fall back to legacy mitigations */
                                  <div className="space-y-2">
                                    {(threat.specific_mitigations || threat.mitigations)?.map((m, i) => (
                                      <div key={i} className="flex items-start gap-2 text-sm p-2 rounded-lg bg-muted/50">
                                        <CheckCircle2 className="w-4 h-4 text-green-500 mt-0.5 shrink-0" />
                                        <span className={threat.specific_mitigations ? 'font-mono text-xs' : ''}>{m}</span>
                                      </div>
                                    ))}
                                    {(!(threat.specific_mitigations || threat.mitigations) || (threat.specific_mitigations || threat.mitigations).length === 0) && (
                                      <p className="text-sm text-muted-foreground">No mitigations defined</p>
                                    )}
                                  </div>
                                )}
                              </div>
                            </div>
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
