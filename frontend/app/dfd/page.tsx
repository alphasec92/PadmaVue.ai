'use client';

import { useState, useEffect, useRef, Suspense, useCallback } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import { motion } from 'framer-motion';
import mermaid from 'mermaid';
import {
  GitBranch,
  Download,
  Copy,
  Check,
  RefreshCw,
  ZoomIn,
  ZoomOut,
  Maximize2,
  Loader2,
  Code2,
  Image,
  Sparkles,
  Shield,
  ArrowLeft,
  FileText,
  AlertTriangle
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { useProjectStore } from '@/store/project-store';
import { useTheme } from '@/components/theme-provider';
import { api } from '@/lib/api';

// Sample Mermaid DFD
const sampleDFD = `flowchart TB
    subgraph External["External Zone"]
        User["👤 User\\n(Browser)"]
        Admin["👤 Admin\\n(Browser)"]
        ThirdParty["🔗 Third-Party API"]
    end
    
    subgraph DMZ["DMZ"]
        CDN["📦 CDN"]
        WAF["🛡️ WAF"]
        LB["⚖️ Load Balancer"]
    end
    
    subgraph AppTier["Application Tier"]
        WebApp["🌐 Web Frontend\\n(Next.js)"]
        API["⚙️ API Gateway\\n(FastAPI)"]
        Auth["🔐 Auth Service"]
        Core["💼 Core Service"]
    end
    
    subgraph DataTier["Data Tier"]
        DB[("🗄️ PostgreSQL\\nDatabase")]
        Cache[("⚡ Redis\\nCache")]
        Queue["📨 Message Queue"]
    end
    
    User -->|HTTPS| CDN
    Admin -->|HTTPS| CDN
    CDN --> WAF
    WAF --> LB
    LB --> WebApp
    WebApp -->|REST| API
    API --> Auth
    API --> Core
    Auth --> DB
    Auth --> Cache
    Core --> DB
    Core --> Queue
    Core <-->|Webhook| ThirdParty
    
    classDef external fill:#4a5568,stroke:#718096,color:#fff
    classDef dmz fill:#553c9a,stroke:#805ad5,color:#fff
    classDef app fill:#2b6cb0,stroke:#4299e1,color:#fff
    classDef data fill:#276749,stroke:#48bb78,color:#fff
    classDef threat fill:#c53030,stroke:#fc8181,color:#fff
    
    class User,Admin,ThirdParty external
    class CDN,WAF,LB dmz
    class WebApp,API,Auth,Core app
    class DB,Cache,Queue data`;

interface AnalysisInfo {
  id: string;
  project_id: string;
  methodology: string;
  status: string;
  created_at?: string;
  threat_count?: number;
}

function DFDContent() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const containerRef = useRef<HTMLDivElement>(null);
  const { projectId, currentAnalysis, setCurrentAnalysis } = useProjectStore();
  const { theme } = useTheme();
  
  const [loading, setLoading] = useState(true);
  const [mermaidCode, setMermaidCode] = useState(sampleDFD);
  const [showCode, setShowCode] = useState(false);
  const [copied, setCopied] = useState(false);
  const [zoom, setZoom] = useState(1);
  const [renderKey, setRenderKey] = useState(0);
  const [fetchError, setFetchError] = useState<string | null>(null);
  const [analysisInfo, setAnalysisInfo] = useState<AnalysisInfo | null>(null);
  const [mermaidReady, setMermaidReady] = useState(false);

  // Generate unique render ID to prevent mermaid conflicts
  const renderIdRef = useRef(0);

  // Determine if we should use dark theme
  const isDark = theme === 'dark' || (theme === 'system' && typeof window !== 'undefined' && window.matchMedia('(prefers-color-scheme: dark)').matches);

  // Load DFD from analysis
  useEffect(() => {
    const analysisIdFromUrl = searchParams.get('analysis_id');
    const analysisId = analysisIdFromUrl || currentAnalysis;
    
    if (analysisIdFromUrl && analysisIdFromUrl !== currentAnalysis) {
      setCurrentAnalysis(analysisIdFromUrl);
    }
    
    if (analysisId) {
      loadDFDFromAnalysis(analysisId);
    } else {
      // Try loading the most recent analysis
      loadRecentAnalysis();
    }
  }, [searchParams, currentAnalysis]);

  const loadRecentAnalysis = async () => {
    try {
      const response = await api.request<{ analyses: AnalysisInfo[] }>('/api/analyze/list');
      if (response.analyses && response.analyses.length > 0) {
        const mostRecent = response.analyses[0];
        setCurrentAnalysis(mostRecent.id);
        loadDFDFromAnalysis(mostRecent.id);
      } else {
        setLoading(false);
      }
    } catch (e) {
      console.error('Failed to load recent analysis:', e);
      setLoading(false);
    }
  };

  const loadDFDFromAnalysis = async (analysisId: string) => {
    try {
      setLoading(true);
      const data = await api.getAnalysis(analysisId);
      
      // Store analysis info for context
      setAnalysisInfo({
        id: data.analysis_id,
        project_id: data.project_id,
        methodology: data.methodology,
        status: data.status,
        created_at: data.created_at,
        threat_count: data.threats?.length || 0
      });
      
      if (data.dfd_mermaid) {
        setMermaidCode(data.dfd_mermaid);
        setFetchError(null);
      } else {
        setFetchError('No DFD available for this analysis');
      }
    } catch (e) {
      console.error('Failed to load DFD:', e);
      setFetchError('Using sample diagram - analysis not found');
    } finally {
      setLoading(false);
    }
  };

  const navigateToReview = () => {
    if (analysisInfo?.id) {
      router.push(`/review?analysis_id=${analysisInfo.id}`);
    } else {
      router.push('/review');
    }
  };

  // Initialize mermaid once
  useEffect(() => {
    const initMermaid = async () => {
      try {
        mermaid.initialize({
          startOnLoad: false,
          theme: isDark ? 'dark' : 'default',
          flowchart: {
            curve: 'basis',
            padding: 20,
            nodeSpacing: 50,
            rankSpacing: 50,
            useMaxWidth: true,
          },
          securityLevel: 'loose',
          themeVariables: isDark ? {
            primaryColor: '#3b82f6',
            primaryTextColor: '#fff',
            primaryBorderColor: '#60a5fa',
            lineColor: '#64748b',
            secondaryColor: '#8b5cf6',
            tertiaryColor: '#1e293b',
            background: '#0f172a',
            mainBkg: '#1e293b',
            nodeBorder: '#475569',
            clusterBkg: '#1e293b20',
            clusterBorder: '#475569',
            titleColor: '#f1f5f9',
            edgeLabelBackground: '#1e293b',
          } : {
            primaryColor: '#3b82f6',
            primaryTextColor: '#1e293b',
            primaryBorderColor: '#3b82f6',
            lineColor: '#94a3b8',
            secondaryColor: '#8b5cf6',
            tertiaryColor: '#f1f5f9',
            background: '#ffffff',
            mainBkg: '#f8fafc',
            nodeBorder: '#cbd5e1',
            clusterBkg: '#f1f5f920',
            clusterBorder: '#cbd5e1',
            titleColor: '#1e293b',
            edgeLabelBackground: '#ffffff',
          },
        });
        setMermaidReady(true);
      } catch (e) {
        console.error('Failed to initialize mermaid:', e);
      }
    };
    initMermaid();
  }, [isDark]);

  // Render diagram when mermaid is ready and code changes
  useEffect(() => {
    if (mermaidReady && mermaidCode) {
      renderDiagram();
    }
  }, [mermaidCode, renderKey, mermaidReady]);

  const renderDiagram = useCallback(async () => {
    if (!containerRef.current || !mermaidReady) return;
    
    setLoading(true);
    try {
      // Clear previous content
      containerRef.current.innerHTML = '';
      
      // Generate unique ID for this render to prevent conflicts
      renderIdRef.current += 1;
      const uniqueId = `dfd-diagram-${Date.now()}-${renderIdRef.current}`;
      
      const { svg } = await mermaid.render(uniqueId, mermaidCode);
      containerRef.current.innerHTML = svg;
      
      // Style the SVG
      const svgElement = containerRef.current.querySelector('svg');
      if (svgElement) {
        svgElement.style.maxWidth = '100%';
        svgElement.style.height = 'auto';
        svgElement.style.transform = `scale(${zoom})`;
        svgElement.style.transformOrigin = 'center';
      }
    } catch (error) {
      console.error('Mermaid render error:', error);
      containerRef.current.innerHTML = `
        <div class="text-center p-8">
          <p class="text-red-500">Error rendering diagram</p>
          <p class="text-sm text-muted-foreground mt-2">Check the Mermaid syntax</p>
        </div>
      `;
    }
    setLoading(false);
  }, [mermaidCode, zoom, mermaidReady]);

  const handleCopyCode = async () => {
    await navigator.clipboard.writeText(mermaidCode);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadSVG = () => {
    const svgElement = containerRef.current?.querySelector('svg');
    if (!svgElement) return;
    
    const svgData = new XMLSerializer().serializeToString(svgElement);
    const blob = new Blob([svgData], { type: 'image/svg+xml' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'dfd-diagram.svg';
    link.click();
    URL.revokeObjectURL(url);
  };

  const handleZoom = (direction: 'in' | 'out' | 'reset') => {
    if (direction === 'in') setZoom(z => Math.min(z + 0.25, 3));
    else if (direction === 'out') setZoom(z => Math.max(z - 0.25, 0.5));
    else setZoom(1);
    setRenderKey(k => k + 1);
  };

  return (
    <div className="min-h-screen pt-20 px-4 sm:px-6 lg:px-8 py-8">
      <div className="mx-auto max-w-7xl">
        {/* Header with Analysis Context */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="mb-8"
        >
          <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
            <div>
              {/* Analysis Context Badge */}
              {analysisInfo ? (
                <div className="flex items-center gap-3 mb-4">
                  <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full glass">
                    <Sparkles className="w-4 h-4 text-primary" />
                    <span className="text-sm font-medium">System Flow Map</span>
                  </div>
                  <span className={cn(
                    'px-2 py-1 rounded-lg text-xs font-medium',
                    analysisInfo.methodology === 'STRIDE' ? 'bg-blue-500/20 text-blue-500' : 'bg-purple-500/20 text-purple-500'
                  )}>
                    {analysisInfo.methodology}
                  </span>
                  {analysisInfo.threat_count !== undefined && analysisInfo.threat_count > 0 && (
                    <span className="px-2 py-1 rounded-lg text-xs font-medium bg-orange-500/20 text-orange-500 flex items-center gap-1">
                      <AlertTriangle className="w-3 h-3" />
                      {analysisInfo.threat_count} threats
                    </span>
                  )}
                </div>
              ) : (
                <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full glass mb-4">
                  <Sparkles className="w-4 h-4 text-primary" />
                  <span className="text-sm font-medium">System Flow Map</span>
                </div>
              )}
              
              <h1 className="heading-lg">
                {analysisInfo?.project_id ? analysisInfo.project_id : 'System Architecture'}
              </h1>
              <p className="text-muted-foreground mt-2">
                {analysisInfo 
                  ? `Analysis ID: ${analysisInfo.id.slice(0, 8)}... • ${analysisInfo.status}`
                  : 'AI-generated data flow diagram with threat annotations'}
              </p>
              
              {fetchError && (
                <p className="text-amber-500 text-sm mt-2 flex items-center gap-1">
                  <AlertTriangle className="w-4 h-4" />
                  {fetchError}
                </p>
              )}
            </div>
            
            <div className="flex items-center gap-2">
              {/* Navigate to Review */}
              <motion.button
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                onClick={navigateToReview}
                className="flex items-center gap-2 px-4 py-2 rounded-xl glass hover:bg-muted"
              >
                <Shield className="w-4 h-4" />
                <span className="hidden sm:inline">View Threats</span>
              </motion.button>
              
              <motion.button
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                onClick={() => setShowCode(!showCode)}
                className={cn(
                  'flex items-center gap-2 px-4 py-2 rounded-xl transition-colors',
                  showCode ? 'bg-primary text-white' : 'glass hover:bg-muted'
                )}
              >
                <Code2 className="w-4 h-4" />
                <span className="hidden sm:inline">Code</span>
              </motion.button>
              
              <motion.button
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                onClick={handleDownloadSVG}
                className="flex items-center gap-2 px-4 py-2 rounded-xl glass hover:bg-muted"
              >
                <Download className="w-4 h-4" />
                <span className="hidden sm:inline">Export</span>
              </motion.button>
            </div>
          </div>
        </motion.div>

        <div className="grid lg:grid-cols-3 gap-6">
          {/* Diagram Panel */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className={cn(
              'rounded-2xl glass overflow-hidden',
              showCode ? 'lg:col-span-2' : 'lg:col-span-3'
            )}
          >
            {/* Toolbar */}
            <div className="p-4 border-b border-border flex items-center justify-between">
              <div className="flex items-center gap-2">
                <GitBranch className="w-5 h-5 text-primary" />
                <span className="font-medium">System Flow Map</span>
              </div>
              
              <div className="flex items-center gap-1">
                <motion.button
                  whileHover={{ scale: 1.1 }}
                  whileTap={{ scale: 0.9 }}
                  onClick={() => handleZoom('out')}
                  className="p-2 rounded-lg hover:bg-muted transition-colors"
                  title="Zoom out"
                >
                  <ZoomOut className="w-4 h-4" />
                </motion.button>
                <span className="text-sm text-muted-foreground px-2">
                  {Math.round(zoom * 100)}%
                </span>
                <motion.button
                  whileHover={{ scale: 1.1 }}
                  whileTap={{ scale: 0.9 }}
                  onClick={() => handleZoom('in')}
                  className="p-2 rounded-lg hover:bg-muted transition-colors"
                  title="Zoom in"
                >
                  <ZoomIn className="w-4 h-4" />
                </motion.button>
                <motion.button
                  whileHover={{ scale: 1.1 }}
                  whileTap={{ scale: 0.9 }}
                  onClick={() => handleZoom('reset')}
                  className="p-2 rounded-lg hover:bg-muted transition-colors"
                  title="Reset zoom"
                >
                  <Maximize2 className="w-4 h-4" />
                </motion.button>
                <motion.button
                  whileHover={{ scale: 1.1 }}
                  whileTap={{ scale: 0.9 }}
                  onClick={() => setRenderKey(k => k + 1)}
                  className="p-2 rounded-lg hover:bg-muted transition-colors"
                  title="Refresh"
                >
                  <RefreshCw className="w-4 h-4" />
                </motion.button>
              </div>
            </div>
            
            {/* Diagram */}
            <div className={cn(
              "relative min-h-[500px] p-8 overflow-auto",
              isDark ? "bg-slate-900/50" : "bg-slate-50"
            )}>
              {loading && (
                <div className="absolute inset-0 flex items-center justify-center bg-background/50 backdrop-blur-sm z-10">
                  <Loader2 className="w-8 h-8 animate-spin text-primary" />
                </div>
              )}
              <div 
                ref={containerRef}
                className="flex items-center justify-center transition-transform duration-300"
              />
            </div>
            
            {/* Legend */}
            <div className="p-4 border-t border-border">
              <p className="text-xs text-muted-foreground mb-2">Legend:</p>
              <div className="flex flex-wrap gap-4 text-xs">
                <div className="flex items-center gap-2">
                  <div className="w-3 h-3 rounded bg-slate-500" />
                  <span>External</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-3 h-3 rounded bg-purple-500" />
                  <span>DMZ</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-3 h-3 rounded bg-blue-500" />
                  <span>Application</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-3 h-3 rounded bg-green-500" />
                  <span>Data</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-3 h-3 rounded bg-red-500" />
                  <span>Threat</span>
                </div>
              </div>
            </div>
          </motion.div>

          {/* Code Panel */}
          {showCode && (
            <motion.div
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 20 }}
              className="lg:col-span-1 rounded-2xl glass overflow-hidden"
            >
              <div className="p-4 border-b border-border flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Code2 className="w-5 h-5 text-primary" />
                  <span className="font-medium">Mermaid Code</span>
                </div>
                
                <motion.button
                  whileHover={{ scale: 1.1 }}
                  whileTap={{ scale: 0.9 }}
                  onClick={handleCopyCode}
                  className="p-2 rounded-lg hover:bg-muted transition-colors"
                >
                  {copied ? (
                    <Check className="w-4 h-4 text-green-500" />
                  ) : (
                    <Copy className="w-4 h-4" />
                  )}
                </motion.button>
              </div>
              
              <div className="p-4 h-[500px] overflow-auto">
                <textarea
                  value={mermaidCode}
                  onChange={(e) => setMermaidCode(e.target.value)}
                  className="w-full h-full bg-transparent font-mono text-sm resize-none focus:outline-none"
                  spellCheck={false}
                />
              </div>
            </motion.div>
          )}
        </div>

        {/* Component Details */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="mt-6 grid sm:grid-cols-2 lg:grid-cols-4 gap-4"
        >
          {[
            { name: 'External Zone', count: 3, color: 'bg-slate-500' },
            { name: 'DMZ Layer', count: 3, color: 'bg-purple-500' },
            { name: 'Application Tier', count: 4, color: 'bg-blue-500' },
            { name: 'Data Tier', count: 3, color: 'bg-green-500' },
          ].map((zone, index) => (
            <motion.div
              key={zone.name}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.3 + index * 0.1 }}
              className="p-4 rounded-xl glass"
            >
              <div className="flex items-center gap-3 mb-2">
                <div className={cn('w-3 h-3 rounded', zone.color)} />
                <span className="font-medium">{zone.name}</span>
              </div>
              <p className="text-2xl font-bold">{zone.count}</p>
              <p className="text-xs text-muted-foreground">components</p>
            </motion.div>
          ))}
        </motion.div>
      </div>
    </div>
  );
}

export default function DFDPage() {
  return (
    <Suspense fallback={
      <div className="flex items-center justify-center min-h-[60vh]">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
      </div>
    }>
      <DFDContent />
    </Suspense>
  );
}
