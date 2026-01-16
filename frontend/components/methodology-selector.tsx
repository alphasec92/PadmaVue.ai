'use client';

import { motion, AnimatePresence } from 'framer-motion';
import { Shield, Target, CheckCircle2, ArrowRight, Zap, BarChart3 } from 'lucide-react';
import { cn } from '@/lib/utils';

interface MethodologySelectorProps {
  selected: 'stride' | 'pasta';
  onSelect: (methodology: 'stride' | 'pasta') => void;
  disabled?: boolean;
}

interface MethodologyItem {
  name: string;
  desc: string;
}

interface MethodologyConfig {
  id: 'stride' | 'pasta';
  name: string;
  fullName: string;
  description: string;
  icon: typeof Shield | typeof Target;
  color: string;
  bgColor: string;
  borderColor: string;
  items: MethodologyItem[];
  itemLabel: string;
  bestFor: string;
  complexity: string;
  timeEstimate: string;
}

const methodologies: Record<'stride' | 'pasta', MethodologyConfig> = {
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
  }
};

export function MethodologySelector({ selected, onSelect, disabled = false }: MethodologySelectorProps) {
  return (
    <div className="w-full">
      <div className="mb-6">
        <h3 className="text-lg font-semibold mb-2">Select Threat Modeling Methodology</h3>
        <p className="text-sm text-muted-foreground">
          Choose the approach that best fits your security review needs
        </p>
      </div>
      
      <div className="grid md:grid-cols-2 gap-4">
        {Object.values(methodologies).map((methodology) => {
          const isSelected = selected === methodology.id;
          const Icon = methodology.icon;
          
          return (
            <motion.button
              key={methodology.id}
              onClick={() => !disabled && onSelect(methodology.id as 'stride' | 'pasta')}
              disabled={disabled}
              className={cn(
                'relative p-6 rounded-2xl text-left transition-all duration-300',
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
                    className="absolute top-4 right-4"
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
              
              {/* Header */}
              <div className="flex items-start gap-4 mb-4">
                <div className={cn(
                  'p-3 rounded-xl bg-gradient-to-br',
                  methodology.color
                )}>
                  <Icon className="w-6 h-6 text-white" />
                </div>
                <div className="flex-1">
                  <h4 className="font-bold text-lg">{methodology.name}</h4>
                  <p className="text-xs text-muted-foreground">{methodology.fullName}</p>
                </div>
              </div>
              
              {/* Description */}
              <p className="text-sm text-muted-foreground mb-4">
                {methodology.description}
              </p>
              
              {/* Categories/Stages */}
              <div className="mb-4">
                <p className="text-xs font-medium text-muted-foreground mb-2">
                  {methodology.itemLabel}:
                </p>
                <div className="flex flex-wrap gap-1.5">
                  {methodology.items.slice(0, 6).map((item, index) => (
                    <motion.span
                      key={item.name}
                      initial={{ opacity: 0, scale: 0.8 }}
                      animate={{ opacity: 1, scale: 1 }}
                      transition={{ delay: index * 0.05 }}
                      className={cn(
                        'px-2 py-0.5 rounded-full text-xs',
                        isSelected ? methodology.bgColor : 'bg-muted'
                      )}
                      title={item.desc}
                    >
                      {item.name}
                    </motion.span>
                  ))}
                  {methodology.items.length > 6 && (
                    <span className="px-2 py-0.5 rounded-full text-xs bg-muted">
                      +{methodology.items.length - 6} more
                    </span>
                  )}
                </div>
              </div>
              
              {/* Footer info */}
              <div className="flex items-center justify-between text-xs text-muted-foreground pt-3 border-t border-border/50">
                <div className="flex items-center gap-1">
                  <Zap className="w-3 h-3" />
                  <span>{methodology.complexity} complexity</span>
                </div>
                <div className="flex items-center gap-1">
                  <BarChart3 className="w-3 h-3" />
                  <span>{methodology.timeEstimate}</span>
                </div>
              </div>
              
              {/* Hover gradient border */}
              {isSelected && (
                <motion.div
                  className={cn(
                    'absolute inset-0 rounded-2xl opacity-20 pointer-events-none',
                    `bg-gradient-to-r ${methodology.color}`
                  )}
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 0.1 }}
                />
              )}
            </motion.button>
          );
        })}
      </div>
      
      {/* Best for section */}
      <motion.div
        key={selected}
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        className="mt-4 p-4 rounded-xl glass"
      >
        <div className="flex items-start gap-3">
          <ArrowRight className="w-4 h-4 mt-0.5 text-primary" />
          <div>
            <p className="text-sm font-medium">Best suited for:</p>
            <p className="text-sm text-muted-foreground">
              {methodologies[selected].bestFor}
            </p>
          </div>
        </div>
      </motion.div>
    </div>
  );
}

// Compact version for smaller spaces
export function MethodologyToggle({ selected, onSelect, disabled = false }: MethodologySelectorProps) {
  return (
    <div className="flex items-center p-1 rounded-full glass">
      {(['stride', 'pasta'] as const).map((id) => {
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


