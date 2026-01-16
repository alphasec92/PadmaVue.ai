'use client';

import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useRouter } from 'next/navigation';
import {
  Clock,
  Shield,
  FileText,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  ChevronRight,
  Loader2,
  Calendar,
  Search,
  Filter,
  Network,
  RefreshCw,
  Trash2,
  MoreVertical,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { api } from '@/lib/api';
import { useProjectStore } from '@/store/project-store';

interface AnalysisItem {
  id: string;
  project_id: string;
  project_name?: string;
  project_description?: string;
  methodology: string;
  status: string;
  created_at: string;
  completed_at?: string;
  threats_count: number;
}

interface AnalysisHistoryProps {
  onSelect?: (analysisId: string, projectId: string) => void;
  showNavigation?: boolean;
  compact?: boolean;
  limit?: number;
  filterProjectId?: string;
}

const STATUS_CONFIG = {
  completed: { icon: CheckCircle2, color: 'text-green-500', bg: 'bg-green-500/10' },
  in_progress: { icon: Loader2, color: 'text-blue-500', bg: 'bg-blue-500/10' },
  pending: { icon: Clock, color: 'text-yellow-500', bg: 'bg-yellow-500/10' },
  failed: { icon: XCircle, color: 'text-red-500', bg: 'bg-red-500/10' },
};

const METHODOLOGY_COLORS = {
  stride: 'bg-blue-500/20 text-blue-500',
  pasta: 'bg-purple-500/20 text-purple-500',
};

function formatDate(dateStr: string) {
  const date = new Date(dateStr);
  const now = new Date();
  const diff = now.getTime() - date.getTime();
  const hours = diff / (1000 * 60 * 60);
  const days = hours / 24;
  
  if (hours < 1) return 'Just now';
  if (hours < 24) return `${Math.floor(hours)}h ago`;
  if (days < 7) return `${Math.floor(days)}d ago`;
  
  return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
}

function formatFullDate(dateStr: string) {
  return new Date(dateStr).toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  });
}

export function AnalysisHistory({ 
  onSelect, 
  showNavigation = true, 
  compact = false,
  limit = 20,
  filterProjectId 
}: AnalysisHistoryProps) {
  const router = useRouter();
  const { setCurrentAnalysis, setProjectId } = useProjectStore();
  const [analyses, setAnalyses] = useState<AnalysisItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [methodologyFilter, setMethodologyFilter] = useState<string>('all');
  const [refreshing, setRefreshing] = useState(false);

  const loadAnalyses = async () => {
    try {
      setLoading(true);
      const response = await api.request<{ analyses: AnalysisItem[]; total: number }>(
        `/api/analyze/list?limit=${limit}&include_project_info=true`
      );
      let analysesData = response.analyses || [];
      
      // Apply project filter if provided
      if (filterProjectId) {
        analysesData = analysesData.filter(a => a.project_id === filterProjectId);
      }
      
      setAnalyses(analysesData);
    } catch (e) {
      console.error('Failed to load analyses:', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAnalyses();
  }, [filterProjectId, limit]);

  const handleRefresh = async () => {
    setRefreshing(true);
    await loadAnalyses();
    setRefreshing(false);
  };

  const handleSelect = (analysis: AnalysisItem) => {
    setCurrentAnalysis(analysis.id);
    setProjectId(analysis.project_id);
    
    if (onSelect) {
      onSelect(analysis.id, analysis.project_id);
    } else if (showNavigation) {
      router.push(`/review?analysis_id=${analysis.id}`);
    }
  };

  const handleViewDFD = (e: React.MouseEvent, analysis: AnalysisItem) => {
    e.stopPropagation();
    setCurrentAnalysis(analysis.id);
    router.push(`/dfd?analysis_id=${analysis.id}`);
  };

  const filteredAnalyses = analyses.filter(a => {
    const matchesSearch = !searchQuery || 
      a.project_name?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      a.project_id.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesMethodology = methodologyFilter === 'all' || a.methodology?.toLowerCase() === methodologyFilter;
    return matchesSearch && matchesMethodology;
  });

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="w-6 h-6 animate-spin text-primary" />
      </div>
    );
  }

  if (analyses.length === 0) {
    return (
      <div className="text-center py-12">
        <FileText className="w-12 h-12 mx-auto text-muted-foreground mb-3" />
        <h3 className="font-medium mb-1">No analyses yet</h3>
        <p className="text-sm text-muted-foreground mb-4">Run your first security analysis to see results here.</p>
        <button
          onClick={() => router.push('/upload')}
          className="px-4 py-2 rounded-xl bg-primary text-white text-sm"
        >
          Start Analysis
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Header & Filters */}
      {!compact && (
        <div className="flex flex-col sm:flex-row gap-3 items-start sm:items-center justify-between">
          <div className="flex items-center gap-2">
            <Clock className="w-5 h-5 text-primary" />
            <span className="font-medium">Analysis History</span>
            <span className="text-xs text-muted-foreground">({filteredAnalyses.length})</span>
          </div>
          
          <div className="flex items-center gap-2 w-full sm:w-auto">
            <div className="relative flex-1 sm:w-48">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <input
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                placeholder="Search..."
                className="w-full pl-9 pr-3 py-1.5 text-sm rounded-lg bg-muted/50 border border-border focus:border-primary outline-none"
              />
            </div>
            
            <select
              value={methodologyFilter}
              onChange={e => setMethodologyFilter(e.target.value)}
              className="px-3 py-1.5 text-sm rounded-lg bg-muted/50 border border-border outline-none"
            >
              <option value="all">All Methods</option>
              <option value="stride">STRIDE</option>
              <option value="pasta">PASTA</option>
            </select>
            
            <button
              onClick={handleRefresh}
              disabled={refreshing}
              className="p-1.5 rounded-lg hover:bg-muted transition-colors"
            >
              <RefreshCw className={cn('w-4 h-4', refreshing && 'animate-spin')} />
            </button>
          </div>
        </div>
      )}

      {/* Analysis List */}
      <div className={cn('space-y-2', compact && 'max-h-96 overflow-y-auto pr-2')}>
        <AnimatePresence mode="popLayout">
          {filteredAnalyses.map((analysis, idx) => {
            const status = STATUS_CONFIG[analysis.status as keyof typeof STATUS_CONFIG] || STATUS_CONFIG.pending;
            const StatusIcon = status.icon;
            const methodologyClass = METHODOLOGY_COLORS[analysis.methodology?.toLowerCase() as keyof typeof METHODOLOGY_COLORS] || 'bg-gray-500/20 text-gray-500';
            
            return (
              <motion.div
                key={analysis.id}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, scale: 0.95 }}
                transition={{ delay: idx * 0.03 }}
                onClick={() => handleSelect(analysis)}
                className={cn(
                  'group rounded-xl border border-border/50 p-3 hover:border-primary/50 hover:bg-muted/30 cursor-pointer transition-all',
                  compact ? 'p-2' : 'p-4'
                )}
              >
                <div className="flex items-center gap-3">
                  {/* Status Icon */}
                  <div className={cn('p-2 rounded-lg', status.bg)}>
                    <StatusIcon className={cn('w-4 h-4', status.color, analysis.status === 'in_progress' && 'animate-spin')} />
                  </div>
                  
                  {/* Info */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <h4 className="font-medium truncate text-sm">
                        {analysis.project_name || analysis.project_id.slice(0, 8) + '...'}
                      </h4>
                      <span className={cn('px-2 py-0.5 rounded text-xs font-medium uppercase', methodologyClass)}>
                        {analysis.methodology}
                      </span>
                    </div>
                    
                    <div className="flex items-center gap-3 text-xs text-muted-foreground">
                      <span className="flex items-center gap-1" title={formatFullDate(analysis.created_at)}>
                        <Calendar className="w-3 h-3" />
                        {formatDate(analysis.created_at)}
                      </span>
                      {analysis.threats_count > 0 && (
                        <span className="flex items-center gap-1">
                          <AlertTriangle className="w-3 h-3" />
                          {analysis.threats_count} threats
                        </span>
                      )}
                    </div>
                  </div>
                  
                  {/* Actions */}
                  <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                    {showNavigation && analysis.status === 'completed' && (
                      <button
                        onClick={(e) => handleViewDFD(e, analysis)}
                        className="p-1.5 rounded-lg hover:bg-muted"
                        title="View DFD"
                      >
                        <Network className="w-4 h-4" />
                      </button>
                    )}
                    <ChevronRight className="w-4 h-4 text-muted-foreground" />
                  </div>
                </div>
              </motion.div>
            );
          })}
        </AnimatePresence>
      </div>

      {filteredAnalyses.length === 0 && searchQuery && (
        <div className="text-center py-8 text-muted-foreground">
          <Search className="w-8 h-8 mx-auto mb-2 opacity-50" />
          <p className="text-sm">No analyses match your search</p>
        </div>
      )}
    </div>
  );
}

// Compact inline version for headers
export function AnalysisSelector({ 
  currentAnalysisId, 
  onSelect 
}: { 
  currentAnalysisId?: string; 
  onSelect: (analysisId: string, projectId: string) => void 
}) {
  const [analyses, setAnalyses] = useState<AnalysisItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [isOpen, setIsOpen] = useState(false);

  useEffect(() => {
    const load = async () => {
      try {
        const response = await api.request<{ analyses: AnalysisItem[] }>('/api/analyze/list?limit=20&include_project_info=true');
        setAnalyses(response.analyses || []);
      } catch (e) {
        console.error('Failed to load analyses:', e);
      } finally {
        setLoading(false);
      }
    };
    load();
  }, []);

  const currentAnalysis = analyses.find(a => a.id === currentAnalysisId);

  return (
    <div className="relative">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-2 px-3 py-2 rounded-xl border border-border hover:border-primary transition-colors"
      >
        <FileText className="w-4 h-4 text-primary" />
        <span className="text-sm font-medium max-w-[200px] truncate">
          {currentAnalysis?.project_name || currentAnalysis?.project_id?.slice(0, 8) || 'Select Analysis'}
        </span>
        <ChevronRight className={cn('w-4 h-4 transition-transform', isOpen && 'rotate-90')} />
      </button>

      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            className="absolute top-full left-0 mt-2 w-80 rounded-xl glass-solid border border-border shadow-xl z-50 overflow-hidden"
          >
            <div className="max-h-80 overflow-y-auto p-2">
              {loading ? (
                <div className="flex items-center justify-center py-6">
                  <Loader2 className="w-5 h-5 animate-spin" />
                </div>
              ) : analyses.length === 0 ? (
                <div className="text-center py-6 text-muted-foreground text-sm">No analyses found</div>
              ) : (
                analyses.map(analysis => (
                  <button
                    key={analysis.id}
                    onClick={() => {
                      onSelect(analysis.id, analysis.project_id);
                      setIsOpen(false);
                    }}
                    className={cn(
                      'w-full text-left p-3 rounded-lg hover:bg-muted transition-colors',
                      analysis.id === currentAnalysisId && 'bg-primary/10 border border-primary/30'
                    )}
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-medium text-sm truncate">
                        {analysis.project_name || analysis.project_id.slice(0, 12)}
                      </span>
                      <span className={cn(
                        'px-1.5 py-0.5 rounded text-[10px] font-medium uppercase',
                        METHODOLOGY_COLORS[analysis.methodology?.toLowerCase() as keyof typeof METHODOLOGY_COLORS]
                      )}>
                        {analysis.methodology}
                      </span>
                    </div>
                    <div className="flex items-center gap-2 text-xs text-muted-foreground">
                      <span>{formatDate(analysis.created_at)}</span>
                      <span>•</span>
                      <span>{analysis.threats_count} threats</span>
                    </div>
                  </button>
                ))
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
      
      {/* Backdrop */}
      {isOpen && (
        <div 
          className="fixed inset-0 z-40" 
          onClick={() => setIsOpen(false)}
        />
      )}
    </div>
  );
}
