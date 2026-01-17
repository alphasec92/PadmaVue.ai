'use client';

import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Shield, Target, CheckCircle2, ArrowRight, Zap, BarChart3,
  Bot, AlertTriangle, ChevronDown, Info, Lock
} from 'lucide-react';
import { cn } from '@/lib/utils';

// ===========================================
// Types
// ===========================================

export interface MethodologySettings {
  primary: 'stride' | 'pasta' | 'maestro';
  includeMaestro: boolean;
  forceMaestro: boolean;
  maestroConfidenceThreshold: number;
}

interface MethodologySelectorProps {
  settings: MethodologySettings;
  onSettingsChange: (settings: MethodologySettings) => void;
  disabled?: boolean;
}

interface MethodologyItem {
  name: string;
  desc: string;
}

interface MethodologyConfig {
  id: 'stride' | 'pasta' | 'maestro';
  name: string;
  fullName: string;
  description: string;
  icon: typeof Shield | typeof Target | typeof Bot;
  color: string;
  bgColor: string;
  borderColor: string;
  items: MethodologyItem[];
  itemLabel: string;
  bestFor: string;
  complexity: string;
  timeEstimate: string;
  badge?: string;
  reference?: string;
}

// ===========================================
// Configuration
// ===========================================

const methodologies: Record<'stride' | 'pasta' | 'maestro', MethodologyConfig> = {
  stride: {
    id: 'stride',
    name: 'STRIDE',
    fullName: 'Spoofing, Tampering, Repudiation, Information Disclosure, DoS, Elevation',
    description: 'Microsoft\'s threat categorization framework for systematic identification of security threats',
    icon: Shield,
    color: 'from-blue-500 to-cyan-500',
    bgColor: 'bg-blue-500/10',
    borderColor: 'border-blue-500/30',
    items: [
      { name: 'Spoofing', desc: 'Identity threats' },
      { name: 'Tampering', desc: 'Data integrity' },
      { name: 'Repudiation', desc: 'Audit trails' },
      { name: 'Info Disclosure', desc: 'Confidentiality' },
      { name: 'Denial of Service', desc: 'Availability' },
      { name: 'Elevation', desc: 'Authorization' }
    ],
    itemLabel: 'Categories',
    bestFor: 'Technical threat identification, developer-focused analysis, quick assessments',
    complexity: 'Medium',
    timeEstimate: '~5 minutes'
  },
  pasta: {
    id: 'pasta',
    name: 'PASTA',
    fullName: 'Process for Attack Simulation and Threat Analysis',
    description: '7-stage risk-centric methodology focusing on business objectives and threat agents',
    icon: Target,
    color: 'from-purple-500 to-pink-500',
    bgColor: 'bg-purple-500/10',
    borderColor: 'border-purple-500/30',
    items: [
      { name: 'Define Objectives', desc: 'Business goals' },
      { name: 'Technical Scope', desc: 'Architecture' },
      { name: 'Decomposition', desc: 'Data flows' },
      { name: 'Threat Analysis', desc: 'Threat agents' },
      { name: 'Vulnerability', desc: 'Weak points' },
      { name: 'Attack Modeling', desc: 'Scenarios' },
      { name: 'Risk Analysis', desc: 'Prioritization' }
    ],
    itemLabel: 'Stages',
    bestFor: 'Enterprise applications, stakeholder communication, compliance-focused reviews',
    complexity: 'High',
    timeEstimate: '~10 minutes'
  },
  maestro: {
    id: 'maestro',
    name: 'MAESTRO',
    fullName: 'Multi-Agent Environment Security Threat Risk & Outcome',
    description: 'CSA\'s Agentic AI framework designed specifically for AI agents, LLMs, and multi-agent systems',
    icon: Bot,
    color: 'from-orange-500 to-red-500',
    bgColor: 'bg-orange-500/10',
    borderColor: 'border-orange-500/30',
    items: [
      { name: 'Autonomous Actions', desc: 'Uncontrolled AI behavior' },
      { name: 'Multi-Agent', desc: 'Coordination attacks' },
      { name: 'Tool Exploitation', desc: 'MCP/API abuse' },
      { name: 'Memory Attacks', desc: 'Context manipulation' },
      { name: 'Goal Hijacking', desc: 'Objective redirect' },
      { name: 'LLM Trust', desc: 'Decision exploitation' }
    ],
    itemLabel: 'Threat Layers',
    bestFor: 'AI agents, LLM applications, autonomous systems, multi-agent workflows',
    complexity: 'High',
    timeEstimate: '~8 minutes',
    badge: 'Agentic AI',
    reference: 'https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro'
  }
};

const MAESTRO_CATEGORIES = [
  { id: 'AGENT01', name: 'Autonomous Action Abuse' },
  { id: 'AGENT02', name: 'Multi-Agent Coordination' },
  { id: 'AGENT03', name: 'Tool/MCP Exploitation' },
  { id: 'AGENT04', name: 'Memory/Context Manipulation' },
  { id: 'AGENT05', name: 'Goal Hijacking' },
  { id: 'AGENT06', name: 'LLM Decision Trust' }
];

// ===========================================
// Main Component
// ===========================================

export function MethodologySelector({ 
  settings, 
  onSettingsChange, 
  disabled = false 
}: MethodologySelectorProps) {
  const [showAdvanced, setShowAdvanced] = useState(false);

  const handlePrimaryChange = (primary: 'stride' | 'pasta' | 'maestro') => {
    // When MAESTRO is selected as primary, automatically enable it
    if (primary === 'maestro') {
      onSettingsChange({ ...settings, primary, includeMaestro: true });
    } else {
      onSettingsChange({ ...settings, primary });
    }
  };

  const handleMaestroToggle = () => {
    onSettingsChange({ 
      ...settings, 
      includeMaestro: !settings.includeMaestro,
      forceMaestro: false // Reset force when toggling
    });
  };

  const handleForceMaestro = () => {
    onSettingsChange({ 
      ...settings, 
      forceMaestro: !settings.forceMaestro 
    });
  };

  return (
    <div className="w-full space-y-6">
      {/* Primary Methodology Selection */}
      <div>
        <div className="mb-4">
          <h3 className="text-lg font-semibold mb-1">Primary Methodology</h3>
          <p className="text-sm text-muted-foreground">
            Choose the main threat modeling approach
          </p>
        </div>
        
        <div className="grid md:grid-cols-3 gap-4">
          {Object.values(methodologies).map((methodology) => {
            const isSelected = settings.primary === methodology.id;
            const Icon = methodology.icon;
            
            return (
              <motion.button
                key={methodology.id}
                onClick={() => !disabled && handlePrimaryChange(methodology.id)}
                disabled={disabled}
                className={cn(
                  'relative p-5 rounded-2xl text-left transition-all duration-300',
                  'border-2 backdrop-blur-sm',
                  isSelected
                    ? `${methodology.borderColor} ${methodology.bgColor}`
                    : 'border-border/50 hover:border-border bg-card/50 hover:bg-card',
                  disabled && 'opacity-50 cursor-not-allowed'
                )}
                whileHover={!disabled ? { scale: 1.02, y: -2 } : {}}
                whileTap={!disabled ? { scale: 0.98 } : {}}
              >
                {/* Selection indicator */}
                <AnimatePresence>
                  {isSelected && (
                    <motion.div
                      initial={{ scale: 0 }}
                      animate={{ scale: 1 }}
                      exit={{ scale: 0 }}
                      className="absolute top-3 right-3"
                    >
                      <div className={cn(
                        'w-6 h-6 rounded-full flex items-center justify-center',
                        `bg-gradient-to-r ${methodology.color}`
                      )}>
                        <CheckCircle2 className="w-4 h-4 text-white" />
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
                
                {/* Badge for MAESTRO */}
                {methodology.badge && (
                  <div className="absolute top-3 left-3">
                    <span className={cn(
                      'px-2 py-0.5 rounded-full text-[10px] font-bold uppercase',
                      'bg-gradient-to-r from-orange-500 to-red-500 text-white'
                    )}>
                      {methodology.badge}
                    </span>
                  </div>
                )}
                
                {/* Header */}
                <div className={cn("flex items-start gap-3 mb-3", methodology.badge && "mt-4")}>
                  <div className={cn(
                    'p-2.5 rounded-xl bg-gradient-to-br',
                    methodology.color
                  )}>
                    <Icon className="w-5 h-5 text-white" />
                  </div>
                  <div className="flex-1">
                    <h4 className="font-bold">{methodology.name}</h4>
                    <p className="text-xs text-muted-foreground line-clamp-1">{methodology.fullName}</p>
                  </div>
                </div>
                
                {/* Description */}
                <p className="text-sm text-muted-foreground mb-3 line-clamp-2">
                  {methodology.description}
                </p>
                
                {/* Categories/Stages */}
                <div className="flex flex-wrap gap-1.5 mb-3">
                  {methodology.items.slice(0, 4).map((item) => (
                    <span
                      key={item.name}
                      className={cn(
                        'px-2 py-0.5 rounded-full text-xs',
                        isSelected ? methodology.bgColor : 'bg-muted'
                      )}
                    >
                      {item.name}
                    </span>
                  ))}
                  {methodology.items.length > 4 && (
                    <span className="px-2 py-0.5 rounded-full text-xs bg-muted">
                      +{methodology.items.length - 4}
                    </span>
                  )}
                </div>
                
                {/* Footer */}
                <div className="flex items-center justify-between text-xs text-muted-foreground pt-2 border-t border-border/50">
                  <span className="flex items-center gap-1">
                    <Zap className="w-3 h-3" />
                    {methodology.complexity}
                  </span>
                  <span className="flex items-center gap-1">
                    <BarChart3 className="w-3 h-3" />
                    {methodology.timeEstimate}
                  </span>
                </div>
              </motion.button>
            );
          })}
        </div>
      </div>

      {/* MAESTRO Overlay Section - Only show when MAESTRO is not the primary methodology */}
      {settings.primary !== 'maestro' && (
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        className="rounded-2xl border-2 border-dashed border-watercolor-coral/30 bg-watercolor-coral/5 p-5"
      >
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-start gap-3">
            <div className="p-2.5 rounded-xl bg-gradient-to-br from-watercolor-coral to-watercolor-pink">
              <Bot className="w-5 h-5 text-white" />
            </div>
            <div className="flex-1">
              <div className="flex items-center gap-2 mb-1">
                <h4 className="font-bold">MAESTRO</h4>
                <span className="px-2 py-0.5 rounded-full text-xs bg-watercolor-coral/20 text-watercolor-coral font-medium">
                  Agentic AI
                </span>
              </div>
              <p className="text-sm text-muted-foreground">
                Multi-Agent Environment Security Threat Risk & Opportunity analysis
              </p>
            </div>
          </div>
          
          {/* Toggle */}
          <button
            onClick={handleMaestroToggle}
            disabled={disabled}
            className={cn(
              'relative w-12 h-6 rounded-full transition-colors',
              settings.includeMaestro 
                ? 'bg-watercolor-coral' 
                : 'bg-muted',
              disabled && 'opacity-50 cursor-not-allowed'
            )}
          >
            <motion.div
              className="absolute top-1 w-4 h-4 rounded-full bg-white shadow-sm"
              animate={{ left: settings.includeMaestro ? '1.5rem' : '0.25rem' }}
              transition={{ type: 'spring', stiffness: 500, damping: 30 }}
            />
          </button>
        </div>
        
        {/* MAESTRO Details */}
        <AnimatePresence>
          {settings.includeMaestro && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              className="overflow-hidden"
            >
              <div className="mt-4 pt-4 border-t border-watercolor-coral/20 space-y-4">
                {/* Info banner */}
                <div className="flex items-start gap-2 p-3 rounded-xl bg-blue-500/10 border border-blue-500/20">
                  <Info className="w-4 h-4 text-blue-500 mt-0.5 flex-shrink-0" />
                  <p className="text-sm text-muted-foreground">
                    MAESTRO is automatically applied when AI/agent components are detected in your project. 
                    The AI analyzes your documents, code, and configuration for evidence of agentic systems.
                  </p>
                </div>
                
                {/* Categories preview */}
                <div>
                  <p className="text-xs font-medium text-muted-foreground mb-2">Threat Categories:</p>
                  <div className="flex flex-wrap gap-1.5">
                    {MAESTRO_CATEGORIES.map((cat) => (
                      <span
                        key={cat.id}
                        className="px-2 py-0.5 rounded-full text-xs bg-watercolor-coral/10 text-watercolor-coral"
                        title={cat.name}
                      >
                        {cat.id}
                      </span>
                    ))}
                  </div>
                </div>
                
                {/* Advanced Options Toggle */}
                <button
                  onClick={() => setShowAdvanced(!showAdvanced)}
                  className="flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground transition-colors"
                >
                  <ChevronDown 
                    className={cn(
                      "w-4 h-4 transition-transform",
                      showAdvanced && "rotate-180"
                    )} 
                  />
                  Advanced Options
                </button>
                
                {/* Advanced Options */}
                <AnimatePresence>
                  {showAdvanced && (
                    <motion.div
                      initial={{ opacity: 0, height: 0 }}
                      animate={{ opacity: 1, height: 'auto' }}
                      exit={{ opacity: 0, height: 0 }}
                      className="space-y-3 overflow-hidden"
                    >
                      {/* Force MAESTRO */}
                      <div className="flex items-start justify-between gap-3 p-3 rounded-xl bg-amber-500/10 border border-amber-500/20">
                        <div className="flex items-start gap-2">
                          <AlertTriangle className="w-4 h-4 text-amber-500 mt-0.5 flex-shrink-0" />
                          <div>
                            <p className="text-sm font-medium">Force MAESTRO</p>
                            <p className="text-xs text-muted-foreground">
                              Generate MAESTRO threats even if no AI components are detected.
                              Results will be marked as "forced" with lower confidence.
                            </p>
                          </div>
                        </div>
                        <button
                          onClick={handleForceMaestro}
                          disabled={disabled}
                          className={cn(
                            'relative w-10 h-5 rounded-full transition-colors flex-shrink-0',
                            settings.forceMaestro 
                              ? 'bg-amber-500' 
                              : 'bg-muted',
                            disabled && 'opacity-50 cursor-not-allowed'
                          )}
                        >
                          <motion.div
                            className="absolute top-0.5 w-4 h-4 rounded-full bg-white shadow-sm"
                            animate={{ left: settings.forceMaestro ? '1.25rem' : '0.125rem' }}
                            transition={{ type: 'spring', stiffness: 500, damping: 30 }}
                          />
                        </button>
                      </div>
                      
                      {/* Confidence Threshold (optional) */}
                      <div className="p-3 rounded-xl bg-muted/50">
                        <div className="flex items-center justify-between mb-2">
                          <p className="text-sm font-medium">Confidence Threshold</p>
                          <span className="text-sm text-muted-foreground">
                            {Math.round(settings.maestroConfidenceThreshold * 100)}%
                          </span>
                        </div>
                        <input
                          type="range"
                          min="0"
                          max="100"
                          value={settings.maestroConfidenceThreshold * 100}
                          onChange={(e) => onSettingsChange({
                            ...settings,
                            maestroConfidenceThreshold: parseInt(e.target.value) / 100
                          })}
                          disabled={disabled || settings.forceMaestro}
                          className="w-full accent-watercolor-coral"
                        />
                        <p className="text-xs text-muted-foreground mt-1">
                          Minimum confidence required to apply MAESTRO analysis
                        </p>
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </motion.div>
      )}

      {/* Best For Section */}
      <motion.div
        key={settings.primary}
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        className="p-4 rounded-xl glass"
      >
        <div className="flex items-start gap-3">
          <ArrowRight className="w-4 h-4 mt-0.5 text-primary" />
          <div>
            <p className="text-sm font-medium">Best suited for:</p>
            <p className="text-sm text-muted-foreground">
              {methodologies[settings.primary].bestFor}
              {settings.includeMaestro && (
                <span className="text-watercolor-coral">
                  {' '}+ AI/Agent system threat analysis
                </span>
              )}
            </p>
          </div>
        </div>
      </motion.div>
    </div>
  );
}

// ===========================================
// Compact Toggle Version
// ===========================================

interface MethodologyToggleProps {
  selected: 'stride' | 'pasta' | 'maestro';
  onSelect: (methodology: 'stride' | 'pasta' | 'maestro') => void;
  disabled?: boolean;
}

export function MethodologyToggle({ selected, onSelect, disabled = false }: MethodologyToggleProps) {
  return (
    <div className="flex items-center p-1 rounded-full glass">
      {(['stride', 'pasta', 'maestro'] as const).map((id) => {
        const methodology = methodologies[id];
        const isSelected = selected === id;
        const Icon = methodology.icon;
        
        return (
          <motion.button
            key={id}
            onClick={() => !disabled && onSelect(id)}
            disabled={disabled}
            className={cn(
              'relative flex items-center gap-2 px-4 py-2 rounded-full transition-colors',
              isSelected ? 'text-white' : 'text-muted-foreground hover:text-foreground',
              disabled && 'opacity-50 cursor-not-allowed'
            )}
            whileHover={!disabled ? { scale: 1.02 } : {}}
            whileTap={!disabled ? { scale: 0.98 } : {}}
          >
            {isSelected && (
              <motion.div
                layoutId="methodology-bg"
                className={cn(
                  'absolute inset-0 rounded-full bg-gradient-to-r',
                  methodology.color
                )}
                transition={{ type: 'spring', bounce: 0.3, duration: 0.4 }}
              />
            )}
            <Icon className="w-4 h-4 relative z-10" />
            <span className="font-medium text-sm relative z-10">{methodology.name}</span>
          </motion.button>
        );
      })}
    </div>
  );
}

// ===========================================
// MAESTRO Status Badge
// ===========================================

interface MaestroStatusBadgeProps {
  status: 'detected' | 'not_detected' | 'forced' | null;
  confidence?: number;
  className?: string;
}

export function MaestroStatusBadge({ status, confidence, className }: MaestroStatusBadgeProps) {
  if (!status) return null;
  
  const config = {
    detected: {
      label: 'Detected',
      icon: CheckCircle2,
      color: 'bg-green-500/10 text-green-600 border-green-500/30'
    },
    not_detected: {
      label: 'Not Detected',
      icon: Info,
      color: 'bg-muted text-muted-foreground border-border'
    },
    forced: {
      label: 'Forced',
      icon: AlertTriangle,
      color: 'bg-amber-500/10 text-amber-600 border-amber-500/30'
    }
  };
  
  const { label, icon: Icon, color } = config[status];
  
  return (
    <div className={cn(
      'inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border',
      color,
      className
    )}>
      <Icon className="w-3 h-3" />
      <span>MAESTRO: {label}</span>
      {confidence !== undefined && (
        <span className="opacity-70">({Math.round(confidence * 100)}%)</span>
      )}
    </div>
  );
}
