'use client';

import { useState, useEffect, useCallback } from 'react';
import { api, WebSearchStatus } from '@/lib/api';

const WEB_SEARCH_KEY = 'padmavue_web_search_enabled';
const REASONING_LEVEL_KEY = 'padmavue_reasoning_level';
const SHOW_REASONING_KEY = 'padmavue_show_reasoning';

// ===========================================
// Types
// ===========================================

export type ReasoningLevel = 'fast' | 'balanced' | 'deep';

export interface SearchProvider {
  id: string;
  name: string;
  description: string;
  requires_api_key: boolean;
  is_open_source: boolean;
  config_fields: Array<{
    name: string;
    label: string;
    type: string;
    default?: string;
    placeholder?: string;
  }>;
}

export interface ReasoningStatus {
  default_level: string;
  show_summary: boolean;
  levels: Array<{
    id: string;
    name: string;
    description: string;
  }>;
}

export interface ReasoningSummary {
  key_steps: string[];
  assumptions: string[];
  evidence_used: string[];
  confidence: string;
}

// ===========================================
// Web Search Hook
// ===========================================

export interface UseWebSearchResult {
  // User preference
  enabled: boolean;
  setEnabled: (enabled: boolean) => void;
  toggle: () => void;
  
  // Backend status
  status: WebSearchStatus | null;
  providers: SearchProvider[];
  isAvailable: boolean;
  isLoading: boolean;
  
  // Computed
  isActive: boolean; // enabled AND available
  
  // Actions
  refreshStatus: () => Promise<void>;
  refreshProviders: () => Promise<void>;
}

export function useWebSearch(): UseWebSearchResult {
  // User preference from localStorage
  const [enabled, setEnabledState] = useState<boolean>(false);
  
  // Backend status
  const [status, setStatus] = useState<WebSearchStatus | null>(null);
  const [providers, setProviders] = useState<SearchProvider[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  
  // Load preference from localStorage on mount
  useEffect(() => {
    if (typeof window !== 'undefined') {
      const stored = localStorage.getItem(WEB_SEARCH_KEY);
      if (stored !== null) {
        setEnabledState(stored === 'true');
      }
    }
  }, []);
  
  // Fetch backend status
  const refreshStatus = useCallback(async () => {
    setIsLoading(true);
    try {
      const result = await api.getWebSearchStatus();
      setStatus(result);
    } catch (error) {
      console.error('Failed to get web search status:', error);
      setStatus({
        available: false,
        provider: 'none',
        configured: false,
        message: 'Failed to connect to backend'
      });
    } finally {
      setIsLoading(false);
    }
  }, []);
  
  // Fetch available providers
  const refreshProviders = useCallback(async () => {
    try {
      const result = await api.getSearchProviders();
      setProviders(result.providers || []);
    } catch (error) {
      console.error('Failed to get search providers:', error);
    }
  }, []);
  
  // Fetch status on mount
  useEffect(() => {
    refreshStatus();
    refreshProviders();
  }, [refreshStatus, refreshProviders]);
  
  // Set enabled with localStorage persistence
  const setEnabled = useCallback((value: boolean) => {
    setEnabledState(value);
    if (typeof window !== 'undefined') {
      localStorage.setItem(WEB_SEARCH_KEY, String(value));
    }
  }, []);
  
  // Toggle helper
  const toggle = useCallback(() => {
    setEnabled(!enabled);
  }, [enabled, setEnabled]);
  
  // Computed values
  const isAvailable = status?.available ?? false;
  const isActive = enabled && isAvailable;
  
  return {
    enabled,
    setEnabled,
    toggle,
    status,
    providers,
    isAvailable,
    isLoading,
    isActive,
    refreshStatus,
    refreshProviders,
  };
}

// ===========================================
// Reasoning / Thinking Time Hook
// ===========================================

export interface UseReasoningResult {
  // Settings
  level: ReasoningLevel;
  setLevel: (level: ReasoningLevel) => void;
  showSummary: boolean;
  setShowSummary: (show: boolean) => void;
  
  // Backend status
  status: ReasoningStatus | null;
  isLoading: boolean;
  
  // Actions
  refreshStatus: () => Promise<void>;
}

export function useReasoning(): UseReasoningResult {
  // User preferences from localStorage
  const [level, setLevelState] = useState<ReasoningLevel>('balanced');
  const [showSummary, setShowSummaryState] = useState<boolean>(true);
  
  // Backend status
  const [status, setStatus] = useState<ReasoningStatus | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  
  // Load preferences from localStorage on mount
  useEffect(() => {
    if (typeof window !== 'undefined') {
      const storedLevel = localStorage.getItem(REASONING_LEVEL_KEY);
      if (storedLevel && ['fast', 'balanced', 'deep'].includes(storedLevel)) {
        setLevelState(storedLevel as ReasoningLevel);
      }
      
      const storedShow = localStorage.getItem(SHOW_REASONING_KEY);
      if (storedShow !== null) {
        setShowSummaryState(storedShow === 'true');
      }
    }
  }, []);
  
  // Fetch backend status
  const refreshStatus = useCallback(async () => {
    setIsLoading(true);
    try {
      const result = await api.getReasoningStatus();
      setStatus(result);
    } catch (error) {
      console.error('Failed to get reasoning status:', error);
      setStatus({
        default_level: 'balanced',
        show_summary: true,
        levels: [
          { id: 'fast', name: 'Fast', description: 'Quick responses' },
          { id: 'balanced', name: 'Balanced', description: 'Default mode' },
          { id: 'deep', name: 'Deep', description: 'Extensive reasoning' },
        ]
      });
    } finally {
      setIsLoading(false);
    }
  }, []);
  
  // Fetch status on mount
  useEffect(() => {
    refreshStatus();
  }, [refreshStatus]);
  
  // Set level with localStorage persistence
  const setLevel = useCallback((value: ReasoningLevel) => {
    setLevelState(value);
    if (typeof window !== 'undefined') {
      localStorage.setItem(REASONING_LEVEL_KEY, value);
    }
  }, []);
  
  // Set showSummary with localStorage persistence
  const setShowSummary = useCallback((value: boolean) => {
    setShowSummaryState(value);
    if (typeof window !== 'undefined') {
      localStorage.setItem(SHOW_REASONING_KEY, String(value));
    }
  }, []);
  
  return {
    level,
    setLevel,
    showSummary,
    setShowSummary,
    status,
    isLoading,
    refreshStatus,
  };
}
