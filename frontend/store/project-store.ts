import { create } from 'zustand';
import { persist } from 'zustand/middleware';

interface Threat {
  id: string;
  category: string;
  title: string;
  description: string;
  affected_component: string;
  attack_vector: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  overall_risk: number;
  dread_score: {
    damage: number;
    reproducibility: number;
    exploitability: number;
    affected_users: number;
    discoverability: number;
  };
  mitigations: string[];
  compliance_mappings: Record<string, string[]>;
  // PASTA-specific fields
  threat_agent?: string;
  affected_assets?: string[];
  likelihood?: number;
  impact?: number;
  business_impact?: string;
}

interface AnalysisResult {
  analysis_id: string;
  project_id: string;
  methodology: 'STRIDE' | 'PASTA';
  status: string;
  created_at: string;
  summary: {
    total_threats: number;
    by_severity: Record<string, number>;
    by_category?: Record<string, number>;
    average_risk?: number;
  };
  threats: Threat[];
  compliance_summary: Record<string, any>;
  dfd_mermaid?: string;
  devsecops_rules?: Record<string, any>;
  pasta_stages?: Record<string, any>;
}

interface ProjectState {
  // Project info
  projectId: string | null;
  projectName: string | null;
  methodology: 'stride' | 'pasta';
  
  // Analysis results
  currentAnalysis: string | null;
  analysisResult: AnalysisResult | null;
  threats: Threat[];
  
  // Loading states
  isAnalyzing: boolean;
  analysisProgress: number;
  
  // Actions
  setProjectId: (id: string) => void;
  setProjectName: (name: string) => void;
  setMethodology: (methodology: 'stride' | 'pasta') => void;
  setCurrentAnalysis: (id: string | null) => void;
  setAnalysisResult: (result: AnalysisResult) => void;
  setThreats: (threats: Threat[]) => void;
  setIsAnalyzing: (analyzing: boolean) => void;
  setAnalysisProgress: (progress: number) => void;
  reset: () => void;
}

export const useProjectStore = create<ProjectState>()(
  persist(
    (set) => ({
      // Initial state
      projectId: null,
      projectName: null,
      methodology: 'stride',
      currentAnalysis: null,
      analysisResult: null,
      threats: [],
      isAnalyzing: false,
      analysisProgress: 0,
      
      // Actions
      setProjectId: (id) => set({ projectId: id }),
      setProjectName: (name) => set({ projectName: name }),
      setMethodology: (methodology) => set({ methodology }),
      setCurrentAnalysis: (id) => set({ currentAnalysis: id }),
      setAnalysisResult: (result) => set({ analysisResult: result, currentAnalysis: result.analysis_id, threats: result.threats }),
      setThreats: (threats) => set({ threats }),
      setIsAnalyzing: (analyzing) => set({ isAnalyzing: analyzing }),
      setAnalysisProgress: (progress) => set({ analysisProgress: progress }),
      reset: () => set({
        projectId: null,
        projectName: null,
        methodology: 'stride',
        currentAnalysis: null,
        analysisResult: null,
        threats: [],
        isAnalyzing: false,
        analysisProgress: 0,
      }),
    }),
    {
      name: 'security-review-project',
      partialize: (state) => ({
        projectId: state.projectId,
        projectName: state.projectName,
        methodology: state.methodology,
        currentAnalysis: state.currentAnalysis,
      }),
    }
  )
);
