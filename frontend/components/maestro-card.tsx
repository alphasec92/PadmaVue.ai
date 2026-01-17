'use client';

import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Bot,
  CheckCircle2,
  AlertTriangle,
  Info,
  ChevronDown,
  FileText,
  MessageSquare,
  Code,
  Settings,
  Sparkles
} from 'lucide-react';
import { cn } from '@/lib/utils';

// ===========================================
// Types
// ===========================================

interface Evidence {
  source: string;
  snippet: string;
  signal_type: string;
  file?: string;
  confidence: number;
}

interface MaestroApplicability {
  applicable: boolean;
  confidence: number;
  status: 'detected' | 'not_detected' | 'forced';
  reasons: string[];
  evidence: Evidence[];
  signals?: Record<string, string[]>;
  checked_at?: string;
}

interface Threat {
  id: string;
  category: string;
  title: string;
  description: string;
  severity: string;
  methodology?: string;
  evidence?: Array<{ source: string; snippet: string }>;
  trust_level?: string;
}

interface MaestroCardProps {
  applicability: MaestroApplicability | null;
  threats?: Threat[];
  className?: string;
}

// ===========================================
// Helper Functions
// ===========================================

const getSourceIcon = (source: string) => {
  switch (source) {
    case 'document':
      return FileText;
    case 'chat':
      return MessageSquare;
    case 'code':
      return Code;
    case 'config':
      return Settings;
    default:
      return Info;
  }
};

const getStatusConfig = (status: MaestroApplicability['status']) => {
  switch (status) {
    case 'detected':
      return {
        label: 'AI Components Detected',
        icon: CheckCircle2,
        color: 'text-emerald-500',
        bg: 'bg-emerald-500/10',
        border: 'border-emerald-500/30'
      };
    case 'forced':
      return {
        label: 'Manually Enabled',
        icon: AlertTriangle,
        color: 'text-amber-500',
        bg: 'bg-amber-500/10',
        border: 'border-amber-500/30'
      };
    case 'not_detected':
    default:
      return {
        label: 'Not Detected',
        icon: Info,
        color: 'text-muted-foreground',
        bg: 'bg-muted',
        border: 'border-border'
      };
  }
};

// ===========================================
// Component
// ===========================================

export function MaestroCard({ applicability, threats = [], className }: MaestroCardProps) {
  const [showEvidence, setShowEvidence] = useState(false);
  const [showThreats, setShowThreats] = useState(false);

  if (!applicability) {
    return (
      <div className={cn('p-4 rounded-xl border border-dashed border-border', className)}>
        <div className="flex items-center gap-3 text-muted-foreground">
          <Bot className="w-5 h-5" />
          <span className="text-sm">MAESTRO analysis not included in this review</span>
        </div>
      </div>
    );
  }

  const statusConfig = getStatusConfig(applicability.status);
  const StatusIcon = statusConfig.icon;
  const confidencePercent = Math.round(applicability.confidence * 100);
  const maestroThreats = threats.filter(t => t.methodology === 'maestro');

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className={cn(
        'rounded-2xl border-2 overflow-hidden',
        statusConfig.border,
        className
      )}
    >
      {/* Header */}
      <div className={cn('p-4', statusConfig.bg)}>
        <div className="flex items-start justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-gradient-to-br from-watercolor-coral to-watercolor-pink">
              <Bot className="w-5 h-5 text-white" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="font-bold">MAESTRO Analysis</h3>
                <span className="px-2 py-0.5 rounded-full text-xs bg-watercolor-coral/20 text-watercolor-coral font-medium">
                  Agentic AI
                </span>
              </div>
              <p className="text-sm text-muted-foreground">
                Multi-Agent Environment Security Threat Assessment
              </p>
            </div>
          </div>
          
          {/* Status Badge */}
          <div className={cn(
            'flex items-center gap-1.5 px-3 py-1.5 rounded-full text-sm font-medium',
            statusConfig.bg,
            statusConfig.color
          )}>
            <StatusIcon className="w-4 h-4" />
            <span>{statusConfig.label}</span>
          </div>
        </div>

        {/* Confidence Bar */}
        <div className="mt-4">
          <div className="flex items-center justify-between text-sm mb-1">
            <span className="text-muted-foreground">Detection Confidence</span>
            <span className={cn('font-medium', statusConfig.color)}>{confidencePercent}%</span>
          </div>
          <div className="h-2 rounded-full bg-muted overflow-hidden">
            <motion.div
              initial={{ width: 0 }}
              animate={{ width: `${confidencePercent}%` }}
              transition={{ duration: 0.5, delay: 0.2 }}
              className={cn(
                'h-full rounded-full',
                applicability.status === 'detected' 
                  ? 'bg-gradient-to-r from-emerald-500 to-emerald-400'
                  : applicability.status === 'forced'
                  ? 'bg-gradient-to-r from-amber-500 to-amber-400'
                  : 'bg-muted-foreground'
              )}
            />
          </div>
        </div>
      </div>

      {/* Content */}
      <div className="p-4 space-y-4">
        {/* Reasons */}
        {applicability.reasons.length > 0 && (
          <div>
            <h4 className="text-sm font-medium mb-2 flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-watercolor-coral" />
              Detection Reasons
            </h4>
            <ul className="space-y-1">
              {applicability.reasons.map((reason, idx) => (
                <li key={idx} className="flex items-start gap-2 text-sm">
                  <CheckCircle2 className="w-4 h-4 text-emerald-500 mt-0.5 flex-shrink-0" />
                  <span className="text-muted-foreground">{reason}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Evidence Accordion */}
        {applicability.evidence.length > 0 && (
          <div className="rounded-xl border border-border overflow-hidden">
            <button
              onClick={() => setShowEvidence(!showEvidence)}
              className="w-full flex items-center justify-between p-3 hover:bg-muted/50 transition-colors"
            >
              <span className="flex items-center gap-2 text-sm font-medium">
                <FileText className="w-4 h-4 text-muted-foreground" />
                Evidence ({applicability.evidence.length} items)
              </span>
              <ChevronDown className={cn(
                'w-4 h-4 text-muted-foreground transition-transform',
                showEvidence && 'rotate-180'
              )} />
            </button>
            
            <AnimatePresence>
              {showEvidence && (
                <motion.div
                  initial={{ height: 0 }}
                  animate={{ height: 'auto' }}
                  exit={{ height: 0 }}
                  className="overflow-hidden"
                >
                  <div className="p-3 pt-0 space-y-2">
                    {applicability.evidence.slice(0, 10).map((ev, idx) => {
                      const SourceIcon = getSourceIcon(ev.source);
                      return (
                        <div
                          key={idx}
                          className="p-2 rounded-lg bg-muted/50 text-sm"
                        >
                          <div className="flex items-center gap-2 mb-1">
                            <SourceIcon className="w-3 h-3 text-muted-foreground" />
                            <span className="text-xs font-medium text-muted-foreground capitalize">
                              {ev.source}
                            </span>
                            <span className="text-xs text-muted-foreground">
                              • {Math.round(ev.confidence * 100)}% confidence
                            </span>
                          </div>
                          <p className="text-xs text-muted-foreground font-mono break-all">
                            {ev.snippet.length > 150 
                              ? ev.snippet.substring(0, 150) + '...' 
                              : ev.snippet}
                          </p>
                        </div>
                      );
                    })}
                    {applicability.evidence.length > 10 && (
                      <p className="text-xs text-muted-foreground text-center py-1">
                        +{applicability.evidence.length - 10} more items
                      </p>
                    )}
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        )}

        {/* MAESTRO Threats */}
        {maestroThreats.length > 0 && (
          <div className="rounded-xl border border-watercolor-coral/30 overflow-hidden">
            <button
              onClick={() => setShowThreats(!showThreats)}
              className="w-full flex items-center justify-between p-3 bg-watercolor-coral/5 hover:bg-watercolor-coral/10 transition-colors"
            >
              <span className="flex items-center gap-2 text-sm font-medium">
                <AlertTriangle className="w-4 h-4 text-watercolor-coral" />
                MAESTRO Threats ({maestroThreats.length})
              </span>
              <ChevronDown className={cn(
                'w-4 h-4 text-muted-foreground transition-transform',
                showThreats && 'rotate-180'
              )} />
            </button>
            
            <AnimatePresence>
              {showThreats && (
                <motion.div
                  initial={{ height: 0 }}
                  animate={{ height: 'auto' }}
                  exit={{ height: 0 }}
                  className="overflow-hidden"
                >
                  <div className="p-3 space-y-2">
                    {maestroThreats.map((threat) => (
                      <div
                        key={threat.id}
                        className="p-3 rounded-lg border border-border hover:border-watercolor-coral/30 transition-colors"
                      >
                        <div className="flex items-start justify-between gap-2 mb-1">
                          <h5 className="font-medium text-sm">{threat.title}</h5>
                          <span className={cn(
                            'px-2 py-0.5 rounded text-xs font-medium',
                            threat.severity === 'high' 
                              ? 'bg-red-500/10 text-red-500'
                              : threat.severity === 'medium'
                              ? 'bg-amber-500/10 text-amber-500'
                              : 'bg-blue-500/10 text-blue-500'
                          )}>
                            {threat.severity}
                          </span>
                        </div>
                        <p className="text-xs text-muted-foreground line-clamp-2">
                          {threat.description}
                        </p>
                        <div className="flex items-center gap-2 mt-2">
                          <span className="px-2 py-0.5 rounded-full text-xs bg-watercolor-coral/20 text-watercolor-coral">
                            {threat.category}
                          </span>
                          {threat.trust_level && (
                            <span className="text-xs text-muted-foreground">
                              Trust: {threat.trust_level}
                            </span>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        )}

        {/* No MAESTRO threats but applicable */}
        {applicability.applicable && maestroThreats.length === 0 && (
          <div className="p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/20">
            <p className="text-sm text-emerald-600 dark:text-emerald-400 flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4" />
              AI components detected but no specific MAESTRO threats were identified.
            </p>
          </div>
        )}

        {/* Not applicable */}
        {!applicability.applicable && applicability.status !== 'forced' && (
          <div className="p-3 rounded-xl bg-muted border border-border">
            <p className="text-sm text-muted-foreground flex items-center gap-2">
              <Info className="w-4 h-4" />
              No AI/agent components were detected. MAESTRO analysis was skipped.
            </p>
          </div>
        )}
      </div>
    </motion.div>
  );
}

// ===========================================
// Compact Badge Version
// ===========================================

interface MaestroBadgeProps {
  applicability: MaestroApplicability | null;
  className?: string;
}

export function MaestroBadge({ applicability, className }: MaestroBadgeProps) {
  if (!applicability) return null;

  const statusConfig = getStatusConfig(applicability.status);
  const StatusIcon = statusConfig.icon;

  return (
    <div className={cn(
      'inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border',
      statusConfig.bg,
      statusConfig.border,
      statusConfig.color,
      className
    )}>
      <Bot className="w-3 h-3" />
      <span>MAESTRO</span>
      <StatusIcon className="w-3 h-3" />
      <span>{Math.round(applicability.confidence * 100)}%</span>
    </div>
  );
}
