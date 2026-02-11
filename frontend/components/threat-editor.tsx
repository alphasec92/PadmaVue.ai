'use client';

import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  X, Save, Trash2, Plus, AlertTriangle, Shield, ChevronDown, 
  Target, Zap, Users, Eye, RotateCcw, Check, Network, GitBranch,
  Layers, ShieldAlert, ShieldCheck, Bell, User, CheckCircle2,
  Clock, HelpCircle, FileText
} from 'lucide-react';
import { cn } from '@/lib/utils';

const STRIDE_CATEGORIES = [
  { id: 'S', name: 'Spoofing', color: 'bg-red-500', desc: 'Impersonating something or someone' },
  { id: 'T', name: 'Tampering', color: 'bg-orange-500', desc: 'Modifying data or code' },
  { id: 'R', name: 'Repudiation', color: 'bg-yellow-500', desc: 'Claiming to not have performed an action' },
  { id: 'I', name: 'Information Disclosure', color: 'bg-blue-500', desc: 'Exposing data to unauthorized parties' },
  { id: 'D', name: 'Denial of Service', color: 'bg-purple-500', desc: 'Denying or degrading service' },
  { id: 'E', name: 'Elevation of Privilege', color: 'bg-pink-500', desc: 'Gaining unauthorized capabilities' },
];

const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const STATUSES = ['identified', 'mitigated', 'accepted', 'transferred'];

// Mitigation types and statuses - must match backend enum values (lowercase)
const MITIGATION_TYPES = ['prevent', 'detect', 'respond'] as const;
const MITIGATION_STATUSES = ['planned', 'in_progress', 'implemented'] as const;

type MitigationType = typeof MITIGATION_TYPES[number];
type MitigationStatus = typeof MITIGATION_STATUSES[number];

// Display labels for UI
const MITIGATION_TYPE_LABELS: Record<MitigationType, string> = {
  'prevent': 'Prevent',
  'detect': 'Detect',
  'respond': 'Respond',
};

const MITIGATION_STATUS_LABELS: Record<MitigationStatus, string> = {
  'planned': 'Planned',
  'in_progress': 'In Progress',
  'implemented': 'Implemented',
};

interface StructuredMitigation {
  id: string;
  text: string;  // matches backend field name
  description?: string;
  mitigation_type: MitigationType;
  status: MitigationStatus;
  owner?: string;
  verification?: string[];
  created_at?: string;
  updated_at?: string;
}

interface Threat {
  id: string;
  title: string;
  description: string;
  category: string;
  stride_category: string;
  severity: string;
  status: string;
  affected_component: string;
  attack_vector: string;
  mitigations: string[];
  structured_mitigations?: StructuredMitigation[];
  dread_score: Record<string, number>;
  zone?: string;
  trust_boundary?: string;
  overall_risk: number;
  // New fields for enhanced experience
  affected_component_ids?: string[];
  impacted_flow_ids?: string[];
  trust_boundaries?: string[];
  assets_impacted?: string[];
  preconditions?: string[];
  attack_scenario_steps?: string[];
  impact_narrative?: string;
  scoring_model?: string;
  scoring_explanation?: string;
}

interface Props {
  threat: Threat;
  zones: Array<{ id: string; name: string }>;
  components?: Array<{ id: string; name: string }>;
  flows?: Array<{ id: string; name: string; source: string; target: string }>;
  onSave: (threat: Threat) => void;
  onDelete: (id: string) => void;
  onClose: () => void;
}

// Helper functions for mitigation UI
const getMitigationTypeIcon = (type: MitigationType) => {
  switch (type) {
    case 'prevent': return ShieldAlert;
    case 'detect': return Bell;
    case 'respond': return ShieldCheck;
    default: return Shield;
  }
};

const getMitigationTypeColor = (type: MitigationType) => {
  switch (type) {
    case 'prevent': return 'text-blue-500 bg-blue-500/10';
    case 'detect': return 'text-amber-500 bg-amber-500/10';
    case 'respond': return 'text-green-500 bg-green-500/10';
    default: return 'text-gray-500 bg-gray-500/10';
  }
};

const getMitigationStatusIcon = (status: MitigationStatus) => {
  switch (status) {
    case 'planned': return HelpCircle;
    case 'in_progress': return Clock;
    case 'implemented': return CheckCircle2;
    default: return HelpCircle;
  }
};

const getMitigationStatusColor = (status: MitigationStatus) => {
  switch (status) {
    case 'planned': return 'text-gray-500';
    case 'in_progress': return 'text-blue-500';
    case 'implemented': return 'text-green-500';
    default: return 'text-gray-500';
  }
};

export function ThreatEditor({ threat: initial, zones, components = [], flows = [], onSave, onDelete, onClose }: Props) {
  const [threat, setThreat] = useState<Threat>({ ...initial });
  const [newMitigation, setNewMitigation] = useState('');
  const [showDread, setShowDread] = useState(false);
  const [showStructuredMitigations, setShowStructuredMitigations] = useState(true);
  const [showAttackScenario, setShowAttackScenario] = useState(false);
  const [showLocationMapping, setShowLocationMapping] = useState(false);
  const [newStructuredMitigation, setNewStructuredMitigation] = useState<Partial<StructuredMitigation>>({
    mitigation_type: 'prevent',
    status: 'planned',
    text: '',
    description: '',
    owner: '',
    verification: []
  });

  // Initialize structured_mitigations if not present
  useEffect(() => {
    if (!threat.structured_mitigations) {
      setThreat(t => ({ ...t, structured_mitigations: [] }));
    }
    if (!threat.affected_component_ids) {
      setThreat(t => ({ ...t, affected_component_ids: [] }));
    }
    if (!threat.impacted_flow_ids) {
      setThreat(t => ({ ...t, impacted_flow_ids: [] }));
    }
    if (!threat.preconditions) {
      setThreat(t => ({ ...t, preconditions: [] }));
    }
    if (!threat.attack_scenario_steps) {
      setThreat(t => ({ ...t, attack_scenario_steps: [] }));
    }
  }, []);

  const update = <K extends keyof Threat>(key: K, value: Threat[K]) => {
    setThreat(t => {
      const updated = { ...t, [key]: value };
      if (key === 'dread_score') {
        updated.overall_risk = Object.values(value as Record<string, number>).reduce((a, b) => a + b, 0) / 5;
      }
      return updated;
    });
  };

  // Legacy mitigations (string-based)
  const addMitigation = () => {
    if (newMitigation.trim()) {
      update('mitigations', [...threat.mitigations, newMitigation.trim()]);
      setNewMitigation('');
    }
  };

  const removeMitigation = (idx: number) => {
    update('mitigations', threat.mitigations.filter((_, i) => i !== idx));
  };

  // Structured mitigations
  const addStructuredMitigation = () => {
    if (!newStructuredMitigation.text?.trim()) return;
    
    const newMit: StructuredMitigation = {
      id: `mit-${Date.now()}`,
      text: newStructuredMitigation.text.trim(),
      description: newStructuredMitigation.description?.trim() || '',
      mitigation_type: newStructuredMitigation.mitigation_type || 'prevent',
      status: newStructuredMitigation.status || 'planned',
      owner: newStructuredMitigation.owner?.trim() || '',
      verification: newStructuredMitigation.verification || [],
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };

    const current = threat.structured_mitigations || [];
    update('structured_mitigations', [...current, newMit]);
    setNewStructuredMitigation({
      mitigation_type: 'prevent',
      status: 'planned',
      text: '',
      description: '',
      owner: '',
      verification: []
    });
  };

  const removeStructuredMitigation = (id: string) => {
    const current = threat.structured_mitigations || [];
    update('structured_mitigations', current.filter(m => m.id !== id));
  };

  const updateStructuredMitigation = (id: string, updates: Partial<StructuredMitigation>) => {
    const current = threat.structured_mitigations || [];
    update('structured_mitigations', current.map(m => 
      m.id === id ? { ...m, ...updates, updated_at: new Date().toISOString() } : m
    ));
  };

  // Component/Flow mapping
  const toggleComponent = (compId: string) => {
    const current = threat.affected_component_ids || [];
    if (current.includes(compId)) {
      update('affected_component_ids', current.filter(id => id !== compId));
    } else {
      update('affected_component_ids', [...current, compId]);
    }
  };

  const toggleFlow = (flowId: string) => {
    const current = threat.impacted_flow_ids || [];
    if (current.includes(flowId)) {
      update('impacted_flow_ids', current.filter(id => id !== flowId));
    } else {
      update('impacted_flow_ids', [...current, flowId]);
    }
  };

  // Attack scenario helpers
  const addPrecondition = (value: string) => {
    if (value.trim()) {
      const current = threat.preconditions || [];
      update('preconditions', [...current, value.trim()]);
    }
  };

  const removePrecondition = (idx: number) => {
    const current = threat.preconditions || [];
    update('preconditions', current.filter((_, i) => i !== idx));
  };

  const addAttackStep = (value: string) => {
    if (value.trim()) {
      const current = threat.attack_scenario_steps || [];
      update('attack_scenario_steps', [...current, value.trim()]);
    }
  };

  const removeAttackStep = (idx: number) => {
    const current = threat.attack_scenario_steps || [];
    update('attack_scenario_steps', current.filter((_, i) => i !== idx));
  };

  const severityColor = (s: string) => ({ critical: 'text-red-500 bg-red-500/10', high: 'text-orange-500 bg-orange-500/10', medium: 'text-yellow-500 bg-yellow-500/10', low: 'text-green-500 bg-green-500/10' }[s] || '');

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm" onClick={onClose}>
      <motion.div initial={{ scale: 0.95, y: 20 }} animate={{ scale: 1, y: 0 }} exit={{ scale: 0.95, y: 20 }}
        className="relative w-full max-w-3xl max-h-[90vh] overflow-hidden rounded-3xl glass-solid shadow-2xl" onClick={e => e.stopPropagation()}>
        
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-border/50">
          <div className="flex items-center gap-3">
            <div className={cn('p-2 rounded-xl', STRIDE_CATEGORIES.find(c => c.id === threat.stride_category)?.color || 'bg-gray-500')}>
              <AlertTriangle className="w-5 h-5 text-white" />
            </div>
            <div>
              <h2 className="text-xl font-bold">Edit Threat</h2>
              <p className="text-sm text-muted-foreground">Modify threat details and mitigations</p>
            </div>
          </div>
          <button onClick={onClose} className="p-2 rounded-xl hover:bg-muted transition-colors"><X className="w-5 h-5" /></button>
        </div>

        <div className="p-6 space-y-6 max-h-[calc(90vh-200px)] overflow-y-auto">
          {/* Title & Category */}
          <div className="grid grid-cols-2 gap-4">
            <div className="col-span-2">
              <label className="block text-sm font-medium mb-2">Title</label>
              <input value={threat.title} onChange={e => update('title', e.target.value)}
                className="w-full px-4 py-3 rounded-xl bg-muted border border-border focus:border-primary outline-none" />
            </div>
            
            <div>
              <label className="block text-sm font-medium mb-2">STRIDE Category</label>
              <div className="grid grid-cols-3 gap-2">
                {STRIDE_CATEGORIES.map(c => (
                  <button key={c.id} onClick={() => { update('stride_category', c.id); update('category', c.name); }}
                    className={cn('p-2 rounded-lg text-xs font-medium transition-all', c.color, threat.stride_category === c.id ? 'ring-2 ring-white text-white' : 'opacity-50 hover:opacity-100')}>
                    {c.id} - {c.name}
                  </button>
                ))}
              </div>
            </div>
            
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-2">Severity</label>
                <div className="flex gap-2">
                  {SEVERITIES.map(s => (
                    <button key={s} onClick={() => update('severity', s)}
                      className={cn('px-3 py-2 rounded-lg text-sm font-medium capitalize transition-all', threat.severity === s ? severityColor(s) : 'bg-muted hover:bg-muted/80')}>
                      {s}
                    </button>
                  ))}
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium mb-2">Status</label>
                <select value={threat.status} onChange={e => update('status', e.target.value)}
                  className="w-full px-4 py-2 rounded-xl bg-muted border border-border">
                  {STATUSES.map(s => <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>)}
                </select>
              </div>
            </div>
          </div>

          {/* Description */}
          <div>
            <label className="block text-sm font-medium mb-2">Description</label>
            <textarea value={threat.description} onChange={e => update('description', e.target.value)} rows={3}
              className="w-full px-4 py-3 rounded-xl bg-muted border border-border focus:border-primary outline-none resize-none" />
          </div>

          {/* Component & Attack Vector */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium mb-2">Affected Component</label>
              <input value={threat.affected_component} onChange={e => update('affected_component', e.target.value)}
                className="w-full px-4 py-3 rounded-xl bg-muted border border-border focus:border-primary outline-none" />
            </div>
            <div>
              <label className="block text-sm font-medium mb-2">Attack Vector</label>
              <input value={threat.attack_vector} onChange={e => update('attack_vector', e.target.value)}
                className="w-full px-4 py-3 rounded-xl bg-muted border border-border focus:border-primary outline-none" />
            </div>
          </div>

          {/* Zone */}
          {zones.length > 0 && (
            <div>
              <label className="block text-sm font-medium mb-2">Zone</label>
              <select value={threat.zone || ''} onChange={e => update('zone', e.target.value)}
                className="w-full px-4 py-3 rounded-xl bg-muted border border-border">
                <option value="">No zone assigned</option>
                {zones.map(z => <option key={z.id} value={z.id}>{z.name}</option>)}
              </select>
            </div>
          )}

          {/* Location Mapping - NEW SECTION */}
          <div className="border border-border/50 rounded-xl overflow-hidden">
            <button onClick={() => setShowLocationMapping(!showLocationMapping)}
              className="flex items-center justify-between w-full p-4 hover:bg-muted/50 transition-colors">
              <div className="flex items-center gap-2">
                <Network className="w-5 h-5 text-blue-500" />
                <span className="font-medium">Where this happens</span>
                <span className="text-xs text-muted-foreground">
                  ({(threat.affected_component_ids?.length || 0)} components, {(threat.impacted_flow_ids?.length || 0)} flows)
                </span>
              </div>
              <ChevronDown className={cn('w-4 h-4 transition-transform', showLocationMapping && 'rotate-180')} />
            </button>
            <AnimatePresence>
              {showLocationMapping && (
                <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }}
                  className="border-t border-border/50 p-4 space-y-4">
                  {/* Components */}
                  <div>
                    <label className="text-sm font-medium mb-2 flex items-center gap-2">
                      <Layers className="w-4 h-4 text-blue-500" />
                      Affected Components
                    </label>
                    {components.length > 0 ? (
                      <div className="flex flex-wrap gap-2 mt-2">
                        {components.map(comp => (
                          <button key={comp.id} onClick={() => toggleComponent(comp.id)}
                            className={cn(
                              'px-3 py-1.5 rounded-lg text-sm transition-all border',
                              threat.affected_component_ids?.includes(comp.id)
                                ? 'bg-blue-500/20 border-blue-500 text-blue-500'
                                : 'bg-muted border-border hover:border-blue-500/50'
                            )}>
                            {threat.affected_component_ids?.includes(comp.id) && <Check className="w-3 h-3 inline mr-1" />}
                            {comp.name || comp.id}
                          </button>
                        ))}
                      </div>
                    ) : (
                      <p className="text-sm text-muted-foreground mt-2">No components available. Generate a DFD first.</p>
                    )}
                  </div>
                  
                  {/* Flows */}
                  <div>
                    <label className="text-sm font-medium mb-2 flex items-center gap-2">
                      <GitBranch className="w-4 h-4 text-purple-500" />
                      Impacted Flows
                    </label>
                    {flows.length > 0 ? (
                      <div className="flex flex-wrap gap-2 mt-2">
                        {flows.map(flow => (
                          <button key={flow.id} onClick={() => toggleFlow(flow.id)}
                            className={cn(
                              'px-3 py-1.5 rounded-lg text-sm transition-all border',
                              threat.impacted_flow_ids?.includes(flow.id)
                                ? 'bg-purple-500/20 border-purple-500 text-purple-500'
                                : 'bg-muted border-border hover:border-purple-500/50'
                            )}>
                            {threat.impacted_flow_ids?.includes(flow.id) && <Check className="w-3 h-3 inline mr-1" />}
                            {flow.name || `${flow.source} → ${flow.target}`}
                          </button>
                        ))}
                      </div>
                    ) : (
                      <p className="text-sm text-muted-foreground mt-2">No flows available. Generate a DFD first.</p>
                    )}
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          {/* Attack Scenario - NEW SECTION */}
          <div className="border border-border/50 rounded-xl overflow-hidden">
            <button onClick={() => setShowAttackScenario(!showAttackScenario)}
              className="flex items-center justify-between w-full p-4 hover:bg-muted/50 transition-colors">
              <div className="flex items-center gap-2">
                <Target className="w-5 h-5 text-red-500" />
                <span className="font-medium">Attack Scenario</span>
                <span className="text-xs text-muted-foreground">
                  ({(threat.preconditions?.length || 0)} preconditions, {(threat.attack_scenario_steps?.length || 0)} steps)
                </span>
              </div>
              <ChevronDown className={cn('w-4 h-4 transition-transform', showAttackScenario && 'rotate-180')} />
            </button>
            <AnimatePresence>
              {showAttackScenario && (
                <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }}
                  className="border-t border-border/50 p-4 space-y-4">
                  {/* Preconditions */}
                  <div>
                    <label className="text-sm font-medium mb-2 block">Preconditions</label>
                    <div className="space-y-2 mb-2">
                      {(threat.preconditions || []).map((pre, i) => (
                        <div key={i} className="flex items-center gap-2 p-2 rounded-lg bg-muted/50">
                          <span className="text-xs text-muted-foreground w-6">{i + 1}.</span>
                          <span className="flex-1 text-sm">{pre}</span>
                          <button onClick={() => removePrecondition(i)} className="p-1 rounded hover:bg-red-500/20 text-red-500">
                            <X className="w-3 h-3" />
                          </button>
                        </div>
                      ))}
                    </div>
                    <input placeholder="Add precondition..." 
                      onKeyDown={e => { if (e.key === 'Enter' && e.currentTarget.value) { addPrecondition(e.currentTarget.value); e.currentTarget.value = ''; }}}
                      className="w-full px-3 py-2 rounded-lg bg-muted border border-border text-sm" />
                  </div>

                  {/* Attack Steps */}
                  <div>
                    <label className="text-sm font-medium mb-2 block">Attack Steps</label>
                    <div className="space-y-2 mb-2">
                      {(threat.attack_scenario_steps || []).map((step, i) => (
                        <div key={i} className="flex items-start gap-2 p-2 rounded-lg bg-muted/50">
                          <div className="w-6 h-6 rounded-full bg-red-500/20 text-red-500 flex items-center justify-center text-xs shrink-0">
                            {i + 1}
                          </div>
                          <span className="flex-1 text-sm">{step}</span>
                          <button onClick={() => removeAttackStep(i)} className="p-1 rounded hover:bg-red-500/20 text-red-500">
                            <X className="w-3 h-3" />
                          </button>
                        </div>
                      ))}
                    </div>
                    <input placeholder="Add attack step..." 
                      onKeyDown={e => { if (e.key === 'Enter' && e.currentTarget.value) { addAttackStep(e.currentTarget.value); e.currentTarget.value = ''; }}}
                      className="w-full px-3 py-2 rounded-lg bg-muted border border-border text-sm" />
                  </div>

                  {/* Impact Narrative */}
                  <div>
                    <label className="text-sm font-medium mb-2 block">Impact Narrative</label>
                    <textarea value={threat.impact_narrative || ''} onChange={e => update('impact_narrative', e.target.value)}
                      rows={2} placeholder="Describe the impact if this attack succeeds..."
                      className="w-full px-3 py-2 rounded-lg bg-muted border border-border text-sm resize-none" />
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          {/* DREAD Score */}
          <div className="border border-border/50 rounded-xl overflow-hidden">
            <button onClick={() => setShowDread(!showDread)}
              className="flex items-center justify-between w-full p-4 hover:bg-muted/50 transition-colors">
              <div className="flex items-center gap-2">
                <AlertTriangle className="w-5 h-5 text-amber-500" />
                <span className="font-medium">DREAD Score</span>
                <span className={cn(
                  'px-2 py-0.5 rounded-full text-xs font-medium',
                  threat.overall_risk >= 8 ? 'bg-red-500/20 text-red-500' :
                  threat.overall_risk >= 6 ? 'bg-orange-500/20 text-orange-500' :
                  threat.overall_risk >= 4 ? 'bg-yellow-500/20 text-yellow-500' :
                  'bg-green-500/20 text-green-500'
                )}>
                  {threat.overall_risk.toFixed(1)}
                </span>
              </div>
              <ChevronDown className={cn('w-4 h-4 transition-transform', showDread && 'rotate-180')} />
            </button>
            <AnimatePresence>
              {showDread && (
                <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }}
                  className="border-t border-border/50 p-4">
                  <div className="grid grid-cols-5 gap-3">
                    {[
                      { key: 'damage', icon: Target, label: 'Damage' },
                      { key: 'reproducibility', icon: RotateCcw, label: 'Reproducibility' },
                      { key: 'exploitability', icon: Zap, label: 'Exploitability' },
                      { key: 'affected_users', icon: Users, label: 'Affected Users' },
                      { key: 'discoverability', icon: Eye, label: 'Discoverability' },
                    ].map(({ key, icon: Icon, label }) => (
                      <div key={key} className="text-center">
                        <Icon className="w-4 h-4 mx-auto mb-1 text-muted-foreground" />
                        <p className="text-xs text-muted-foreground mb-1">{label}</p>
                        <input type="number" min="1" max="10" value={threat.dread_score[key] || 5}
                          onChange={e => update('dread_score', { ...threat.dread_score, [key]: Math.min(10, Math.max(1, parseInt(e.target.value) || 1)) })}
                          className="w-full px-2 py-1 rounded-lg bg-muted border border-border text-center text-sm" />
                      </div>
                    ))}
                  </div>
                  {threat.scoring_explanation && (
                    <div className="mt-4 p-3 rounded-lg bg-muted/50 text-xs text-muted-foreground">
                      <span className="font-medium text-foreground">Model: </span>{threat.scoring_model || 'DREAD_AVG_V1'}
                      <br />
                      <span className="font-medium text-foreground">Explanation: </span>{threat.scoring_explanation}
                    </div>
                  )}
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          {/* Structured Mitigations - NEW SECTION */}
          <div className="border border-border/50 rounded-xl overflow-hidden">
            <button onClick={() => setShowStructuredMitigations(!showStructuredMitigations)}
              className="flex items-center justify-between w-full p-4 hover:bg-muted/50 transition-colors">
              <div className="flex items-center gap-2">
                <Shield className="w-5 h-5 text-green-500" />
                <span className="font-medium">Structured Mitigations</span>
                <span className="text-xs text-muted-foreground">
                  ({(threat.structured_mitigations?.length || 0)} controls)
                </span>
              </div>
              <ChevronDown className={cn('w-4 h-4 transition-transform', showStructuredMitigations && 'rotate-180')} />
            </button>
            <AnimatePresence>
              {showStructuredMitigations && (
                <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }}
                  className="border-t border-border/50 p-4 space-y-4">
                  {/* Grouped by type */}
                  {MITIGATION_TYPES.map(type => {
                    const TypeIcon = getMitigationTypeIcon(type);
                    const typeColor = getMitigationTypeColor(type);
                    const mitsOfType = (threat.structured_mitigations || []).filter(m => m.mitigation_type === type);
                    
                    return (
                      <div key={type} className="space-y-2">
                        <div className={cn('flex items-center gap-2 text-sm font-medium', typeColor.split(' ')[0])}>
                          <TypeIcon className="w-4 h-4" />
                          {MITIGATION_TYPE_LABELS[type]} ({mitsOfType.length})
                        </div>
                        {mitsOfType.map(mit => {
                          const StatusIcon = getMitigationStatusIcon(mit.status);
                          const statusColor = getMitigationStatusColor(mit.status);
                          
                          return (
                            <div key={mit.id} className="p-3 rounded-lg bg-muted/50 space-y-2">
                              <div className="flex items-start justify-between gap-2">
                                <div className="flex-1">
                                  <div className="flex items-center gap-2">
                                    <span className="font-medium text-sm">{mit.text}</span>
                                    <span className={cn('flex items-center gap-1 text-xs', statusColor)}>
                                      <StatusIcon className="w-3 h-3" />
                                      {MITIGATION_STATUS_LABELS[mit.status]}
                                    </span>
                                  </div>
                                  {mit.description && (
                                    <p className="text-xs text-muted-foreground mt-1">{mit.description}</p>
                                  )}
                                </div>
                                <button onClick={() => removeStructuredMitigation(mit.id)}
                                  className="p-1 rounded hover:bg-red-500/20 text-red-500">
                                  <X className="w-3 h-3" />
                                </button>
                              </div>
                              <div className="flex flex-wrap gap-2 text-xs">
                                {mit.owner && (
                                  <span className="flex items-center gap-1 px-2 py-0.5 rounded-full bg-muted">
                                    <User className="w-3 h-3" /> {mit.owner}
                                  </span>
                                )}
                                {mit.verification && mit.verification.length > 0 && (
                                  <span className="flex items-center gap-1 px-2 py-0.5 rounded-full bg-muted">
                                    <FileText className="w-3 h-3" /> {mit.verification.join(', ')}
                                  </span>
                                )}
                                <select value={mit.status}
                                  onChange={e => updateStructuredMitigation(mit.id, { status: e.target.value as MitigationStatus })}
                                  className="px-2 py-0.5 rounded-full bg-muted border-none text-xs cursor-pointer">
                                  {MITIGATION_STATUSES.map(s => (
                                    <option key={s} value={s}>{MITIGATION_STATUS_LABELS[s]}</option>
                                  ))}
                                </select>
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    );
                  })}

                  {/* Add new structured mitigation */}
                  <div className="border-t border-border/50 pt-4 space-y-3">
                    <div className="text-sm font-medium flex items-center gap-2">
                      <Plus className="w-4 h-4" /> Add New Mitigation
                    </div>
                    <div className="grid grid-cols-2 gap-3">
                      <input value={newStructuredMitigation.text || ''} onChange={e => setNewStructuredMitigation(s => ({ ...s, text: e.target.value }))}
                        placeholder="Mitigation description..." className="col-span-2 px-3 py-2 rounded-lg bg-muted border border-border text-sm" />
                      <select value={newStructuredMitigation.mitigation_type}
                        onChange={e => setNewStructuredMitigation(s => ({ ...s, mitigation_type: e.target.value as MitigationType }))}
                        className="px-3 py-2 rounded-lg bg-muted border border-border text-sm">
                        {MITIGATION_TYPES.map(t => <option key={t} value={t}>{MITIGATION_TYPE_LABELS[t]}</option>)}
                      </select>
                      <select value={newStructuredMitigation.status}
                        onChange={e => setNewStructuredMitigation(s => ({ ...s, status: e.target.value as MitigationStatus }))}
                        className="px-3 py-2 rounded-lg bg-muted border border-border text-sm">
                        {MITIGATION_STATUSES.map(s => <option key={s} value={s}>{MITIGATION_STATUS_LABELS[s]}</option>)}
                      </select>
                      <input value={newStructuredMitigation.owner || ''} onChange={e => setNewStructuredMitigation(s => ({ ...s, owner: e.target.value }))}
                        placeholder="Owner (optional)" className="px-3 py-2 rounded-lg bg-muted border border-border text-sm" />
                      <input value={(newStructuredMitigation.verification || []).join(', ')} 
                        onChange={e => setNewStructuredMitigation(s => ({ ...s, verification: e.target.value.split(',').map(v => v.trim()).filter(Boolean) }))}
                        placeholder="Verification methods (comma-separated)" className="px-3 py-2 rounded-lg bg-muted border border-border text-sm" />
                      <textarea value={newStructuredMitigation.description || ''} onChange={e => setNewStructuredMitigation(s => ({ ...s, description: e.target.value }))}
                        placeholder="Description (optional)" rows={2} className="col-span-2 px-3 py-2 rounded-lg bg-muted border border-border text-sm resize-none" />
                    </div>
                    <button onClick={addStructuredMitigation} disabled={!newStructuredMitigation.text?.trim()}
                      className="w-full px-4 py-2 rounded-lg bg-green-500 text-white text-sm font-medium disabled:opacity-50 disabled:cursor-not-allowed">
                      <Plus className="w-4 h-4 inline mr-2" /> Add Mitigation
                    </button>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          {/* Legacy Mitigations (keep for backward compat) */}
          {threat.mitigations.length > 0 && (
            <div className="border border-border/50 rounded-xl p-4">
              <label className="text-sm font-medium mb-2 block text-muted-foreground">
                Legacy Mitigations ({threat.mitigations.length})
              </label>
              <div className="space-y-2 mb-3">
                {threat.mitigations.map((m, i) => (
                  <div key={i} className="flex items-center gap-2 p-3 rounded-xl bg-muted/50">
                    <Shield className="w-4 h-4 text-green-500 shrink-0" />
                    <span className="flex-1 text-sm">{m}</span>
                    <button onClick={() => removeMitigation(i)} className="p-1 rounded hover:bg-red-500/20 text-red-500"><X className="w-4 h-4" /></button>
                  </div>
                ))}
              </div>
              <div className="flex gap-2">
                <input value={newMitigation} onChange={e => setNewMitigation(e.target.value)} placeholder="Add a legacy mitigation..."
                  onKeyDown={e => e.key === 'Enter' && addMitigation()}
                  className="flex-1 px-4 py-2 rounded-xl bg-muted border border-border focus:border-primary outline-none" />
                <button onClick={addMitigation} className="px-4 py-2 rounded-xl bg-green-500 text-white"><Plus className="w-5 h-5" /></button>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between p-6 border-t border-border/50">
          <button onClick={() => onDelete(threat.id)} className="flex items-center gap-2 px-4 py-2 rounded-xl text-red-500 hover:bg-red-500/10">
            <Trash2 className="w-4 h-4" />Delete
          </button>
          <div className="flex gap-3">
            <button onClick={onClose} className="px-4 py-2 rounded-xl border border-border hover:bg-muted">Cancel</button>
            <motion.button whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.98 }} onClick={() => onSave(threat)}
              className="flex items-center gap-2 px-6 py-2 rounded-xl bg-gradient-to-r from-primary to-purple-600 text-white font-medium">
              <Save className="w-4 h-4" />Save Changes
            </motion.button>
          </div>
        </div>
      </motion.div>
    </motion.div>
  );
}


