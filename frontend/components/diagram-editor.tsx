'use client';

import { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  X, Save, Plus, Trash2, Code, Eye, Palette, Box, ArrowRight, Shield, 
  ZoomIn, ZoomOut, Download, RefreshCw, Layers, AlertTriangle
} from 'lucide-react';
import { cn } from '@/lib/utils';
import mermaid from 'mermaid';

interface Zone { id: string; name: string; description?: string; color?: string; components: string[]; }
interface TrustBoundary { id: string; name: string; zones: string[]; style?: string; color?: string; }
interface Component { id: string; name: string; type: string; zone?: string; }
interface DataFlow { id: string; from: string; to: string; label?: string; stride?: string; }

interface Props {
  initialCode: string;
  initialMeta?: { zones?: Zone[]; trust_boundaries?: TrustBoundary[]; components?: Component[]; data_flows?: DataFlow[]; };
  onSave: (code: string, meta: any) => void;
  onClose: () => void;
}

const STRIDE_BADGES = [
  { id: 'S', name: 'Spoofing', color: '#ef4444' },
  { id: 'T', name: 'Tampering', color: '#f97316' },
  { id: 'R', name: 'Repudiation', color: '#eab308' },
  { id: 'I', name: 'Information Disclosure', color: '#3b82f6' },
  { id: 'D', name: 'Denial of Service', color: '#8b5cf6' },
  { id: 'E', name: 'Elevation of Privilege', color: '#ec4899' },
];

const ZONE_COLORS = ['#fef3c7', '#dcfce7', '#dbeafe', '#fce7f3', '#e0e7ff', '#fef9c3'];
const COMPONENT_TYPES = ['process', 'datastore', 'external', 'actor', 'service'];

export function DiagramEditor({ initialCode, initialMeta, onSave, onClose }: Props) {
  const [code, setCode] = useState(initialCode || 'flowchart TB\n  User[User] --> App[Application]\n  App --> DB[(Database)]');
  const [view, setView] = useState<'split' | 'code' | 'preview'>('split');
  const [zones, setZones] = useState<Zone[]>(initialMeta?.zones || []);
  const [boundaries, setBoundaries] = useState<TrustBoundary[]>(initialMeta?.trust_boundaries || []);
  const [components, setComponents] = useState<Component[]>(initialMeta?.components || []);
  const [dataFlows, setDataFlows] = useState<DataFlow[]>(initialMeta?.data_flows || []);
  const [activeTab, setActiveTab] = useState<'code' | 'zones' | 'boundaries' | 'components' | 'flows'>('code');
  const [preview, setPreview] = useState('');
  const [error, setError] = useState('');
  const previewRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    mermaid.initialize({ startOnLoad: false, theme: 'neutral', securityLevel: 'loose' });
  }, []);

  useEffect(() => {
    renderDiagram();
  }, [code]);

  const renderDiagram = async () => {
    try {
      setError('');
      const { svg } = await mermaid.render('mermaid-preview', code);
      setPreview(svg);
    } catch (e: any) {
      const errorMsg = typeof e === 'string' ? e : (e.message || e.toString() || 'Invalid Mermaid syntax');
      setError(errorMsg);
      setPreview('');
    }
  };

  const addZone = () => setZones([...zones, { id: `Z${zones.length}`, name: `Zone ${zones.length}`, description: '', color: ZONE_COLORS[zones.length % ZONE_COLORS.length], components: [] }]);
  const addBoundary = () => setBoundaries([...boundaries, { id: `TB${boundaries.length}`, name: `Trust Boundary ${boundaries.length}`, zones: [], style: 'dashed', color: '#ef4444' }]);
  const addComponent = () => setComponents([...components, { id: `C${components.length}`, name: `Component ${components.length}`, type: 'process' }]);
  const addFlow = () => setDataFlows([...dataFlows, { id: `F${dataFlows.length}`, from: '', to: '', label: '' }]);

  const generateMermaid = () => {
    let m = 'flowchart TB\n';
    
    // Add subgraphs for trust boundaries
    boundaries.forEach(b => {
      m += `  subgraph ${b.id}["${b.name}"]\n`;
      zones.filter(z => b.zones.includes(z.id)).forEach(z => {
        m += `    subgraph ${z.id}["${z.name}"]\n`;
        z.components.forEach(c => {
          const comp = components.find(x => x.id === c);
          if (comp) m += `      ${comp.id}[${comp.name}]\n`;
        });
        m += '    end\n';
      });
      m += '  end\n';
    });
    
    // Add components not in boundaries
    const inBoundary = new Set(boundaries.flatMap(b => zones.filter(z => b.zones.includes(z.id)).flatMap(z => z.components)));
    components.filter(c => !inBoundary.has(c.id)).forEach(c => {
      m += `  ${c.id}[${c.name}]\n`;
    });
    
    // Add flows with STRIDE annotations
    dataFlows.forEach(f => {
      if (f.from && f.to) {
        const label = f.stride ? `${f.label}|${f.stride}|` : f.label;
        m += `  ${f.from} -->|${label}| ${f.to}\n`;
      }
    });
    
    setCode(m);
  };

  const downloadSvg = () => {
    const blob = new Blob([preview], { type: 'image/svg+xml' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'threat-model-diagram.svg';
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm" onClick={onClose}>
      <motion.div initial={{ scale: 0.95 }} animate={{ scale: 1 }} exit={{ scale: 0.95 }}
        className="relative w-full max-w-7xl h-[90vh] overflow-hidden rounded-3xl glass-solid shadow-2xl" onClick={e => e.stopPropagation()}>
        
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-border/50">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-primary/10"><Layers className="w-5 h-5 text-primary" /></div>
            <div><h2 className="text-lg font-bold">Diagram Editor</h2><p className="text-xs text-muted-foreground">Edit data flow diagram with zones & trust boundaries</p></div>
          </div>
          <div className="flex items-center gap-2">
            {['split', 'code', 'preview'].map(v => (
              <button key={v} onClick={() => setView(v as any)} className={cn('px-3 py-1.5 rounded-lg text-sm capitalize', view === v ? 'bg-primary text-white' : 'hover:bg-muted')}>
                {v === 'split' ? 'Split' : v === 'code' ? <Code className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            ))}
            <button onClick={downloadSvg} className="p-2 rounded-lg hover:bg-muted" title="Download SVG"><Download className="w-4 h-4" /></button>
            <button onClick={onClose} className="p-2 rounded-xl hover:bg-muted"><X className="w-5 h-5" /></button>
          </div>
        </div>

        <div className="flex h-[calc(90vh-140px)]">
          {/* Sidebar */}
          <div className="w-64 border-r border-border/50 overflow-y-auto">
            <div className="flex border-b border-border/50">
              {[{ id: 'code', icon: Code }, { id: 'zones', icon: Box }, { id: 'boundaries', icon: Shield }, { id: 'components', icon: Layers }, { id: 'flows', icon: ArrowRight }].map(t => (
                <button key={t.id} onClick={() => setActiveTab(t.id as any)} className={cn('flex-1 p-3', activeTab === t.id ? 'border-b-2 border-primary' : 'text-muted-foreground')}>
                  <t.icon className="w-4 h-4 mx-auto" />
                </button>
              ))}
            </div>
            
            <div className="p-3 space-y-3">
              {activeTab === 'zones' && (
                <>
                  <button onClick={addZone} className="w-full flex items-center justify-center gap-2 p-2 rounded-lg border border-dashed border-border hover:border-primary text-sm">
                    <Plus className="w-4 h-4" />Add Zone
                  </button>
                  {zones.map((z, i) => (
                    <div key={z.id} className="p-3 rounded-xl border border-border" style={{ borderLeftColor: z.color, borderLeftWidth: 4 }}>
                      <input value={z.name} onChange={e => setZones(zones.map((x, j) => i === j ? { ...x, name: e.target.value } : x))}
                        className="w-full text-sm font-medium bg-transparent outline-none" />
                      <input value={z.id} onChange={e => setZones(zones.map((x, j) => i === j ? { ...x, id: e.target.value } : x))}
                        className="w-full text-xs text-muted-foreground bg-transparent outline-none" placeholder="Zone ID" />
                      <div className="flex gap-1 mt-2">
                        {ZONE_COLORS.map(c => (
                          <button key={c} onClick={() => setZones(zones.map((x, j) => i === j ? { ...x, color: c } : x))}
                            className={cn('w-5 h-5 rounded', z.color === c && 'ring-2 ring-offset-1')} style={{ backgroundColor: c }} />
                        ))}
                        <button onClick={() => setZones(zones.filter((_, j) => j !== i))} className="ml-auto text-red-500 hover:bg-red-500/10 p-1 rounded"><Trash2 className="w-3 h-3" /></button>
                      </div>
                    </div>
                  ))}
                </>
              )}
              
              {activeTab === 'boundaries' && (
                <>
                  <button onClick={addBoundary} className="w-full flex items-center justify-center gap-2 p-2 rounded-lg border border-dashed border-border hover:border-primary text-sm">
                    <Plus className="w-4 h-4" />Add Trust Boundary
                  </button>
                  {boundaries.map((b, i) => (
                    <div key={b.id} className="p-3 rounded-xl border-2 border-dashed" style={{ borderColor: b.color }}>
                      <input value={b.name} onChange={e => setBoundaries(boundaries.map((x, j) => i === j ? { ...x, name: e.target.value } : x))}
                        className="w-full text-sm font-medium bg-transparent outline-none" />
                      <p className="text-xs text-muted-foreground mt-1">Zones:</p>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {zones.map(z => (
                          <button key={z.id} onClick={() => setBoundaries(boundaries.map((x, j) => i === j ? { ...x, zones: x.zones.includes(z.id) ? x.zones.filter(zz => zz !== z.id) : [...x.zones, z.id] } : x))}
                            className={cn('px-2 py-0.5 rounded text-xs', b.zones.includes(z.id) ? 'bg-primary text-white' : 'bg-muted')}>{z.id}</button>
                        ))}
                      </div>
                      <button onClick={() => setBoundaries(boundaries.filter((_, j) => j !== i))} className="mt-2 text-red-500 text-xs">Remove</button>
                    </div>
                  ))}
                </>
              )}
              
              {activeTab === 'components' && (
                <>
                  <button onClick={addComponent} className="w-full flex items-center justify-center gap-2 p-2 rounded-lg border border-dashed border-border hover:border-primary text-sm">
                    <Plus className="w-4 h-4" />Add Component
                  </button>
                  {components.map((c, i) => (
                    <div key={c.id} className="p-3 rounded-xl border border-border">
                      <input value={c.name} onChange={e => setComponents(components.map((x, j) => i === j ? { ...x, name: e.target.value } : x))}
                        className="w-full text-sm font-medium bg-transparent outline-none" placeholder="Name" />
                      <div className="flex items-center gap-2 mt-2">
                        <select value={c.type} onChange={e => setComponents(components.map((x, j) => i === j ? { ...x, type: e.target.value } : x))}
                          className="flex-1 text-xs bg-muted rounded px-2 py-1">
                          {COMPONENT_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
                        </select>
                        <button onClick={() => setComponents(components.filter((_, j) => j !== i))} className="text-red-500"><Trash2 className="w-3 h-3" /></button>
                      </div>
                      <select value={c.zone || ''} onChange={e => {
                        setComponents(components.map((x, j) => i === j ? { ...x, zone: e.target.value } : x));
                        if (e.target.value) setZones(zones.map(z => z.id === e.target.value ? { ...z, components: [...z.components.filter(cc => cc !== c.id), c.id] } : { ...z, components: z.components.filter(cc => cc !== c.id) }));
                      }} className="w-full text-xs bg-muted rounded px-2 py-1 mt-2">
                        <option value="">No zone</option>
                        {zones.map(z => <option key={z.id} value={z.id}>{z.name}</option>)}
                      </select>
                    </div>
                  ))}
                </>
              )}
              
              {activeTab === 'flows' && (
                <>
                  <button onClick={addFlow} className="w-full flex items-center justify-center gap-2 p-2 rounded-lg border border-dashed border-border hover:border-primary text-sm">
                    <Plus className="w-4 h-4" />Add Data Flow
                  </button>
                  {dataFlows.map((f, i) => (
                    <div key={f.id} className="p-3 rounded-xl border border-border space-y-2">
                      <div className="flex gap-2">
                        <select value={f.from} onChange={e => setDataFlows(dataFlows.map((x, j) => i === j ? { ...x, from: e.target.value } : x))}
                          className="flex-1 text-xs bg-muted rounded px-2 py-1">
                          <option value="">From...</option>
                          {components.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
                        </select>
                        <ArrowRight className="w-4 h-4 text-muted-foreground" />
                        <select value={f.to} onChange={e => setDataFlows(dataFlows.map((x, j) => i === j ? { ...x, to: e.target.value } : x))}
                          className="flex-1 text-xs bg-muted rounded px-2 py-1">
                          <option value="">To...</option>
                          {components.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
                        </select>
                      </div>
                      <input value={f.label} onChange={e => setDataFlows(dataFlows.map((x, j) => i === j ? { ...x, label: e.target.value } : x))}
                        className="w-full text-xs bg-muted rounded px-2 py-1" placeholder="Label" />
                      <div className="flex gap-1">
                        {STRIDE_BADGES.map(s => (
                          <button key={s.id} onClick={() => setDataFlows(dataFlows.map((x, j) => i === j ? { ...x, stride: x.stride?.includes(s.id) ? x.stride.replace(s.id, '') : (x.stride || '') + s.id } : x))}
                            className={cn('w-6 h-6 rounded text-xs font-bold text-white', f.stride?.includes(s.id) ? '' : 'opacity-30')} style={{ backgroundColor: s.color }}>{s.id}</button>
                        ))}
                        <button onClick={() => setDataFlows(dataFlows.filter((_, j) => j !== i))} className="ml-auto text-red-500"><Trash2 className="w-3 h-3" /></button>
                      </div>
                    </div>
                  ))}
                </>
              )}
              
              {activeTab === 'code' && (
                <div className="space-y-2">
                  <button onClick={generateMermaid} className="w-full flex items-center justify-center gap-2 p-2 rounded-lg bg-primary text-white text-sm">
                    <RefreshCw className="w-4 h-4" />Generate from Config
                  </button>
                  <p className="text-xs text-muted-foreground">Or edit Mermaid code directly in the editor</p>
                </div>
              )}
            </div>
          </div>

          {/* Editor & Preview */}
          <div className={cn('flex-1 flex', view === 'code' ? 'flex-col' : view === 'preview' ? 'flex-col' : '')}>
            {(view === 'split' || view === 'code') && (
              <div className={cn('flex-1 flex flex-col', view === 'split' && 'border-r border-border/50')}>
                <div className="p-2 border-b border-border/50 flex items-center gap-2">
                  <Code className="w-4 h-4 text-muted-foreground" />
                  <span className="text-sm font-medium">Mermaid Code</span>
                </div>
                <textarea value={code} onChange={e => setCode(e.target.value)}
                  className="flex-1 p-4 bg-muted/30 font-mono text-sm resize-none outline-none"
                  spellCheck={false} />
              </div>
            )}
            
            {(view === 'split' || view === 'preview') && (
              <div className="flex-1 flex flex-col">
                <div className="p-2 border-b border-border/50 flex items-center gap-2">
                  <Eye className="w-4 h-4 text-muted-foreground" />
                  <span className="text-sm font-medium">Preview</span>
                  {error && <span className="text-xs text-red-500 ml-auto flex items-center gap-1"><AlertTriangle className="w-3 h-3" />{error}</span>}
                </div>
                <div ref={previewRef} className="flex-1 p-4 overflow-auto flex items-center justify-center bg-white/5"
                  dangerouslySetInnerHTML={{ __html: preview }} />
              </div>
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-3 p-4 border-t border-border/50">
          <button onClick={onClose} className="px-4 py-2 rounded-xl border border-border hover:bg-muted">Cancel</button>
          <motion.button whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.98 }}
            onClick={() => onSave(code, { zones, trust_boundaries: boundaries, components, data_flows: dataFlows })}
            className="flex items-center gap-2 px-6 py-2 rounded-xl bg-gradient-to-r from-primary to-purple-600 text-white font-medium">
            <Save className="w-4 h-4" />Save Diagram
          </motion.button>
        </div>
      </motion.div>
    </motion.div>
  );
}


