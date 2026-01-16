'use client';

import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  X, Save, Trash2, Plus, AlertTriangle, Shield, ChevronDown, 
  Target, Zap, Users, Eye, RotateCcw, Check
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
  dread_score: Record<string, number>;
  zone?: string;
  trust_boundary?: string;
  overall_risk: number;
}

interface Props {
  threat: Threat;
  zones: Array<{ id: string; name: string }>;
  onSave: (threat: Threat) => void;
  onDelete: (id: string) => void;
  onClose: () => void;
}

export function ThreatEditor({ threat: initial, zones, onSave, onDelete, onClose }: Props) {
  const [threat, setThreat] = useState<Threat>({ ...initial });
  const [newMitigation, setNewMitigation] = useState('');
  const [showDread, setShowDread] = useState(false);

  const update = <K extends keyof Threat>(key: K, value: Threat[K]) => {
    setThreat(t => {
      const updated = { ...t, [key]: value };
      if (key === 'dread_score') {
        updated.overall_risk = Object.values(value as Record<string, number>).reduce((a, b) => a + b, 0) / 5;
      }
      return updated;
    });
  };

  const addMitigation = () => {
    if (newMitigation.trim()) {
      update('mitigations', [...threat.mitigations, newMitigation.trim()]);
      setNewMitigation('');
    }
  };

  const removeMitigation = (idx: number) => {
    update('mitigations', threat.mitigations.filter((_, i) => i !== idx));
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

          {/* DREAD Score */}
          <div>
            <button onClick={() => setShowDread(!showDread)} className="flex items-center gap-2 text-sm font-medium mb-2">
              <ChevronDown className={cn('w-4 h-4 transition-transform', showDread && 'rotate-180')} />
              DREAD Score (Risk: {threat.overall_risk.toFixed(1)})
            </button>
            <AnimatePresence>
              {showDread && (
                <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }}
                  className="grid grid-cols-5 gap-3 overflow-hidden">
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
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          {/* Mitigations */}
          <div>
            <label className="block text-sm font-medium mb-2">Mitigations ({threat.mitigations.length})</label>
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
              <input value={newMitigation} onChange={e => setNewMitigation(e.target.value)} placeholder="Add a mitigation..."
                onKeyDown={e => e.key === 'Enter' && addMitigation()}
                className="flex-1 px-4 py-2 rounded-xl bg-muted border border-border focus:border-primary outline-none" />
              <button onClick={addMitigation} className="px-4 py-2 rounded-xl bg-green-500 text-white"><Plus className="w-5 h-5" /></button>
            </div>
          </div>
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


