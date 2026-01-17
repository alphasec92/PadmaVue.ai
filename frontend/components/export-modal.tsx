'use client';

import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  X, Download, FileJson, FileText, CheckCircle2, Loader2,
  Shield, BarChart3, Code, ClipboardList, ChevronRight,
  AlertCircle, FileCheck
} from 'lucide-react';
import { cn } from '@/lib/utils';

interface ExportModalProps {
  isOpen: boolean;
  onClose: () => void;
  analysisId: string;
  projectName?: string;
  methodology?: string;
  threatCount?: number;
}

type ExportFormat = 'pdf' | 'json';
type ReportType = 'full' | 'executive' | 'technical' | 'compliance';

const REPORT_TYPES: { id: ReportType; name: string; description: string; icon: any; color: string }[] = [
  { 
    id: 'full', 
    name: 'Full Report', 
    description: 'Complete analysis with all threats, DFD, and compliance mappings',
    icon: FileCheck,
    color: 'from-watercolor-coral to-watercolor-pink'
  },
  { 
    id: 'executive', 
    name: 'Executive Summary', 
    description: 'High-level overview for leadership and stakeholders',
    icon: BarChart3,
    color: 'from-watercolor-blue to-cyan-600'
  },
  { 
    id: 'technical', 
    name: 'Technical Report', 
    description: 'Detailed findings with DevSecOps rules and attack vectors',
    icon: Code,
    color: 'from-green-500 to-emerald-600'
  },
  { 
    id: 'compliance', 
    name: 'Compliance Report', 
    description: 'NIST 800-53, OWASP ASVS mappings and control coverage',
    icon: ClipboardList,
    color: 'from-watercolor-coral to-orange-500'
  }
];

const API_BASE_URL = process.env.NEXT_PUBLIC_BACKEND_URL || 'http://localhost:8000';

export function ExportModal({ 
  isOpen, 
  onClose, 
  analysisId,
  projectName,
  methodology,
  threatCount 
}: ExportModalProps) {
  const [format, setFormat] = useState<ExportFormat>('pdf');
  const [reportType, setReportType] = useState<ReportType>('full');
  const [includeDfd, setIncludeDfd] = useState(true);
  const [includeMitigations, setIncludeMitigations] = useState(true);
  const [includeCompliance, setIncludeCompliance] = useState(true);
  const [exporting, setExporting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  const handleExport = async () => {
    setExporting(true);
    setError(null);
    setSuccess(false);

    try {
      const response = await fetch(`${API_BASE_URL}/api/export/report`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          analysis_id: analysisId,
          format,
          report_type: reportType,
          include_dfd: includeDfd,
          include_mitigations: includeMitigations,
          include_compliance: includeCompliance
        })
      });

      if (!response.ok) {
        const err = await response.json().catch(() => ({ detail: 'Export failed' }));
        throw new Error(err.detail || 'Export failed');
      }

      // Get the blob
      const blob = await response.blob();
      
      // Create download link
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      
      const timestamp = new Date().toISOString().slice(0, 10);
      const filename = `security_report_${projectName?.replace(/\s+/g, '_') || analysisId}_${timestamp}.${format}`;
      a.download = filename;
      
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);

      setSuccess(true);
      setTimeout(() => {
        onClose();
        setSuccess(false);
      }, 1500);

    } catch (e: any) {
      console.error('Export failed:', e);
      const errorMsg = typeof e === 'string' ? e : (e.message || e.cause || e.toString() || 'Failed to export report');
      setError(errorMsg);
    } finally {
      setExporting(false);
    }
  };

  if (!isOpen) return null;

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm"
        onClick={onClose}
      >
        <motion.div
          initial={{ opacity: 0, scale: 0.95, y: 20 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.95, y: 20 }}
          className="relative w-full max-w-2xl max-h-[90vh] overflow-hidden rounded-3xl bg-background border border-border shadow-2xl"
          onClick={e => e.stopPropagation()}
        >
          {/* Header */}
          <div className="flex items-center justify-between p-5 border-b border-border">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-xl bg-watercolor-coral/10">
                <Download className="w-5 h-5 text-watercolor-coral" />
              </div>
              <div>
                <h2 className="text-lg font-bold">Export Report</h2>
                <p className="text-sm text-muted-foreground">Generate a comprehensive security report</p>
              </div>
            </div>
            <button onClick={onClose} className="p-2 rounded-xl hover:bg-muted transition-colors">
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Content */}
          <div className="p-5 overflow-y-auto max-h-[calc(90vh-180px)] space-y-6">
            {/* Project Info */}
            <div className="flex items-center gap-4 p-4 rounded-xl bg-muted/50">
              <Shield className="w-8 h-8 text-watercolor-coral" />
              <div className="flex-1">
                <p className="font-semibold">{projectName || 'Security Analysis'}</p>
                <div className="flex items-center gap-3 text-sm text-muted-foreground">
                  <span className="px-2 py-0.5 rounded bg-watercolor-coral/20 text-watercolor-coral text-xs font-medium">{methodology || 'STRIDE'}</span>
                  <span>{threatCount || 0} threats identified</span>
                </div>
              </div>
            </div>

            {/* Format Selection */}
            <div>
              <h3 className="font-medium mb-3">Export Format</h3>
              <div className="grid grid-cols-2 gap-3">
                <motion.button
                  whileHover={{ scale: 1.02 }}
                  whileTap={{ scale: 0.98 }}
                  onClick={() => setFormat('pdf')}
                  className={cn(
                    'p-4 rounded-xl border-2 text-left transition-all flex items-center gap-3',
                    format === 'pdf' ? 'border-watercolor-coral bg-watercolor-coral/5' : 'border-border hover:border-watercolor-coral/50'
                  )}
                >
                  <div className={cn('p-2 rounded-lg', format === 'pdf' ? 'bg-red-500/20' : 'bg-muted')}>
                    <FileText className={cn('w-5 h-5', format === 'pdf' ? 'text-red-500' : 'text-muted-foreground')} />
                  </div>
                  <div>
                    <p className="font-medium">PDF Document</p>
                    <p className="text-xs text-muted-foreground">Formatted, printable report</p>
                  </div>
                  {format === 'pdf' && <CheckCircle2 className="w-5 h-5 text-watercolor-coral ml-auto" />}
                </motion.button>

                <motion.button
                  whileHover={{ scale: 1.02 }}
                  whileTap={{ scale: 0.98 }}
                  onClick={() => setFormat('json')}
                  className={cn(
                    'p-4 rounded-xl border-2 text-left transition-all flex items-center gap-3',
                    format === 'json' ? 'border-watercolor-coral bg-watercolor-coral/5' : 'border-border hover:border-watercolor-coral/50'
                  )}
                >
                  <div className={cn('p-2 rounded-lg', format === 'json' ? 'bg-yellow-500/20' : 'bg-muted')}>
                    <FileJson className={cn('w-5 h-5', format === 'json' ? 'text-yellow-500' : 'text-muted-foreground')} />
                  </div>
                  <div>
                    <p className="font-medium">JSON Data</p>
                    <p className="text-xs text-muted-foreground">Structured data for tools</p>
                  </div>
                  {format === 'json' && <CheckCircle2 className="w-5 h-5 text-watercolor-coral ml-auto" />}
                </motion.button>
              </div>
            </div>

            {/* Report Type Selection */}
            <div>
              <h3 className="font-medium mb-3">Report Type</h3>
              <div className="grid grid-cols-2 gap-3">
                {REPORT_TYPES.map(type => (
                  <motion.button
                    key={type.id}
                    whileHover={{ scale: 1.02 }}
                    whileTap={{ scale: 0.98 }}
                    onClick={() => setReportType(type.id)}
                    className={cn(
                      'p-4 rounded-xl border-2 text-left transition-all',
                      reportType === type.id ? 'border-watercolor-coral bg-watercolor-coral/5' : 'border-border hover:border-watercolor-coral/50'
                    )}
                  >
                    <div className="flex items-start gap-3">
                      <div className={cn('p-2 rounded-lg bg-gradient-to-br', type.color)}>
                        <type.icon className="w-4 h-4 text-white" />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <p className="font-medium">{type.name}</p>
                          {reportType === type.id && <CheckCircle2 className="w-4 h-4 text-watercolor-coral" />}
                        </div>
                        <p className="text-xs text-muted-foreground mt-0.5">{type.description}</p>
                      </div>
                    </div>
                  </motion.button>
                ))}
              </div>
            </div>

            {/* Include Options */}
            <div>
              <h3 className="font-medium mb-3">Include in Report</h3>
              <div className="space-y-2">
                {[
                  { id: 'dfd', label: 'Data Flow Diagram', description: 'Mermaid diagram code', checked: includeDfd, onChange: setIncludeDfd },
                  { id: 'mitigations', label: 'Mitigations & Remediation', description: 'Recommended fixes for each threat', checked: includeMitigations, onChange: setIncludeMitigations },
                  { id: 'compliance', label: 'Compliance Mappings', description: 'NIST 800-53 & OWASP ASVS controls', checked: includeCompliance, onChange: setIncludeCompliance },
                ].map(opt => (
                  <label
                    key={opt.id}
                    className={cn(
                      'flex items-center gap-3 p-3 rounded-xl cursor-pointer transition-colors',
                      opt.checked ? 'bg-watercolor-coral/5' : 'hover:bg-muted'
                    )}
                  >
                    <input
                      type="checkbox"
                      checked={opt.checked}
                      onChange={e => opt.onChange(e.target.checked)}
                      className="w-4 h-4 rounded border-border text-watercolor-coral focus:ring-watercolor-coral accent-watercolor-coral"
                    />
                    <div className="flex-1">
                      <p className="font-medium text-sm">{opt.label}</p>
                      <p className="text-xs text-muted-foreground">{opt.description}</p>
                    </div>
                  </label>
                ))}
              </div>
            </div>

            {/* Error Message */}
            <AnimatePresence>
              {error && (
                <motion.div
                  initial={{ opacity: 0, y: -10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -10 }}
                  className="flex items-center gap-3 p-4 rounded-xl bg-red-500/10 border border-red-500/30"
                >
                  <AlertCircle className="w-5 h-5 text-red-500" />
                  <div className="flex-1">
                    <p className="font-medium text-red-500">Export Failed</p>
                    <p className="text-sm text-muted-foreground">{error}</p>
                  </div>
                  <button onClick={() => setError(null)} className="p-1 rounded hover:bg-red-500/20">
                    <X className="w-4 h-4 text-red-500" />
                  </button>
                </motion.div>
              )}
            </AnimatePresence>

            {/* Success Message */}
            <AnimatePresence>
              {success && (
                <motion.div
                  initial={{ opacity: 0, y: -10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -10 }}
                  className="flex items-center gap-3 p-4 rounded-xl bg-green-500/10 border border-green-500/30"
                >
                  <CheckCircle2 className="w-5 h-5 text-green-500" />
                  <p className="font-medium text-green-600 dark:text-green-400">Report downloaded successfully!</p>
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          {/* Footer */}
          <div className="flex items-center justify-between p-5 border-t border-border">
            <p className="text-sm text-muted-foreground">
              {format === 'pdf' ? '📄 PDF includes formatted layout' : '📦 JSON includes all raw data'}
            </p>
            <div className="flex items-center gap-3">
              <button
                onClick={onClose}
                className="px-4 py-2 rounded-xl border border-border hover:bg-muted transition-colors"
              >
                Cancel
              </button>
              <motion.button
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
                onClick={handleExport}
                disabled={exporting}
                className="flex items-center gap-2 px-6 py-2 rounded-xl bg-gradient-to-r from-watercolor-coral to-watercolor-pink text-white font-medium disabled:opacity-50"
              >
                {exporting ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Generating...
                  </>
                ) : (
                  <>
                    <Download className="w-4 h-4" />
                    Export {format.toUpperCase()}
                  </>
                )}
              </motion.button>
            </div>
          </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  );
}

