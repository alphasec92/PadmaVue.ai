'use client';

import { useState, useEffect, useCallback, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  X, Settings, Check, Loader2, Server, Cloud, Cpu, Zap, CheckCircle2, XCircle,
  ChevronRight, ChevronLeft, ExternalLink, Copy, Eye, EyeOff, Sparkles,
  AlertCircle, HelpCircle, Monitor, Moon, Sun, Shield, FileText, Palette,
  RefreshCw, Key, Lock, Target, Terminal, Wifi, WifiOff, Plug, Plus, Trash2, Link,
  Globe, Search, Bot
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { api, Provider, ApiError, MCPServerResponse, MCPServerCreate, MCPTestResult, MCPRegistryServer, MCPImportResult } from '@/lib/api';
import { useTheme } from './theme-provider';
import { useWebSearch, useReasoning, ReasoningLevel } from '@/hooks/use-web-search';

// Fallback provider configurations
const FALLBACK_PROVIDERS: Provider[] = [
  {
    id: 'ollama',
    name: 'Ollama',
    description: 'Run AI models locally on your machine (recommended)',
    requires_api_key: false,
    requires_local: true,
    default_model: 'llama3.2',
    available_models: ['llama3.2', 'llama3.1', 'llama3', 'mistral', 'codellama', 'phi3', 'gemma2', 'qwen2'],
    config_fields: [
      { name: 'base_url', label: 'Server URL', type: 'text', required: false, default: 'http://localhost:11434', placeholder: 'http://localhost:11434 (auto-detects Docker)' },
      { name: 'model', label: 'Model', type: 'combobox', required: true }
    ]
  },
  {
    id: 'openrouter',
    name: 'OpenRouter',
    description: 'Access multiple AI models with one API key',
    requires_api_key: true,
    requires_local: false,
    default_model: 'meta-llama/llama-3.1-8b-instruct:free',
    available_models: ['meta-llama/llama-3.1-8b-instruct:free', 'anthropic/claude-3-haiku', 'openai/gpt-4o-mini', 'google/gemini-flash-1.5'],
    config_fields: [
      { name: 'api_key', label: 'API Key', type: 'password', required: true, placeholder: 'sk-or-...' },
      { name: 'model', label: 'Model', type: 'combobox', required: true }
    ]
  },
  {
    id: 'openai',
    name: 'OpenAI',
    description: 'GPT-4 and GPT-3.5 models',
    requires_api_key: true,
    requires_local: false,
    default_model: 'gpt-4o-mini',
    available_models: ['gpt-4o', 'gpt-4o-mini', 'gpt-4-turbo', 'gpt-3.5-turbo'],
    config_fields: [
      { name: 'api_key', label: 'API Key', type: 'password', required: true, placeholder: 'sk-...' },
      { name: 'model', label: 'Model', type: 'combobox', required: true }
    ]
  },
  {
    id: 'anthropic',
    name: 'Anthropic Claude',
    description: 'Claude 3 family of models',
    requires_api_key: true,
    requires_local: false,
    default_model: 'claude-3-haiku-20240307',
    available_models: ['claude-3-opus-20240229', 'claude-3-sonnet-20240229', 'claude-3-haiku-20240307', 'claude-3-5-sonnet-20241022'],
    config_fields: [
      { name: 'api_key', label: 'API Key', type: 'password', required: true, placeholder: 'sk-ant-...' },
      { name: 'model', label: 'Model', type: 'combobox', required: true }
    ]
  },
  {
    id: 'gemini',
    name: 'Google Gemini',
    description: 'Gemini Pro and Flash models with free tier',
    requires_api_key: true,
    requires_local: false,
    default_model: 'gemini-1.5-flash',
    available_models: ['gemini-1.5-pro', 'gemini-1.5-flash', 'gemini-pro'],
    config_fields: [
      { name: 'api_key', label: 'API Key', type: 'password', required: true, placeholder: 'AI...' },
      { name: 'model', label: 'Model', type: 'combobox', required: true }
    ]
  },
  {
    id: 'lmstudio',
    name: 'LM Studio',
    description: 'Local model server with GUI',
    requires_api_key: false,
    requires_local: true,
    default_model: 'local-model',
    available_models: ['local-model'],
    config_fields: [
      { name: 'base_url', label: 'Server URL', type: 'text', required: false, default: 'http://localhost:1234/v1', placeholder: 'http://localhost:1234/v1' },
      { name: 'model', label: 'Model', type: 'combobox', required: true }
    ]
  }
];

// Provider UI metadata
const PROVIDER_META: Record<string, { icon: any; gradient: string; category: 'recommended' | 'cloud' | 'local'; setupTime: string; cost: string }> = {
  ollama: { icon: Server, gradient: 'from-pink-500 to-rose-600', category: 'recommended', setupTime: '5 min', cost: 'Free' },
  openrouter: { icon: Cloud, gradient: 'from-purple-500 to-violet-600', category: 'recommended', setupTime: '2 min', cost: 'Pay per use' },
  openai: { icon: Cloud, gradient: 'from-green-500 to-emerald-600', category: 'cloud', setupTime: '2 min', cost: '$5-20/mo' },
  anthropic: { icon: Cloud, gradient: 'from-orange-500 to-amber-600', category: 'cloud', setupTime: '2 min', cost: '$5-20/mo' },
  gemini: { icon: Cloud, gradient: 'from-blue-500 to-cyan-600', category: 'cloud', setupTime: '2 min', cost: 'Free tier' },
  vertex: { icon: Cloud, gradient: 'from-blue-600 to-indigo-600', category: 'cloud', setupTime: '10 min', cost: 'Pay per use' },
  bedrock: { icon: Cloud, gradient: 'from-orange-600 to-red-600', category: 'cloud', setupTime: '10 min', cost: 'Pay per use' },
  lmstudio: { icon: Server, gradient: 'from-indigo-500 to-purple-600', category: 'local', setupTime: '10 min', cost: 'Free' },
  mock: { icon: Cpu, gradient: 'from-gray-500 to-gray-600', category: 'local', setupTime: '0 min', cost: 'Free (Demo)' },
};

// Debug information for connection errors
interface ConnectionDebug {
  status: 'checking' | 'connected' | 'error' | 'not_running';
  message: string;
  details?: string;
  steps?: string[];
}

// Test Web Search Button Component
function TestWebSearchButton() {
  const [testing, setTesting] = useState(false);
  const [result, setResult] = useState<{ success: boolean; message: string; results?: any[] } | null>(null);
  
  const runTest = async () => {
    setTesting(true);
    setResult(null);
    try {
      const response = await api.testWebSearch();
      setResult(response);
    } catch (error) {
      setResult({
        success: false,
        message: error instanceof Error ? error.message : 'Test failed'
      });
    } finally {
      setTesting(false);
    }
  };
  
  return (
    <div className="mt-3">
      <button
        onClick={runTest}
        disabled={testing}
        className={cn(
          "flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all",
          "bg-muted hover:bg-muted/80 border border-border"
        )}
      >
        {testing ? (
          <>
            <Loader2 className="w-4 h-4 animate-spin" />
            Testing connection...
          </>
        ) : (
          <>
            <Wifi className="w-4 h-4" />
            Test Web Search Connection
          </>
        )}
      </button>
      
      {result && (
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          className={cn(
            "mt-3 p-3 rounded-lg border text-sm",
            result.success 
              ? "bg-emerald-500/10 border-emerald-500/30" 
              : "bg-red-500/10 border-red-500/30"
          )}
        >
          <div className="flex items-start gap-2">
            {result.success ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-500 mt-0.5" />
            ) : (
              <XCircle className="w-4 h-4 text-red-500 mt-0.5" />
            )}
            <div>
              <p className={cn(
                "font-medium",
                result.success ? "text-emerald-600 dark:text-emerald-400" : "text-red-600 dark:text-red-400"
              )}>
                {result.message}
              </p>
              {result.results && result.results.length > 0 && (
                <div className="mt-2 space-y-1">
                  <p className="text-xs text-muted-foreground">Sample results:</p>
                  {result.results.slice(0, 2).map((r, i) => (
                    <a 
                      key={i} 
                      href={r.url} 
                      target="_blank" 
                      rel="noopener noreferrer"
                      className="block text-xs text-primary hover:underline truncate"
                    >
                      {r.title}
                    </a>
                  ))}
                </div>
              )}
            </div>
          </div>
        </motion.div>
      )}
    </div>
  );
}

interface Props { isOpen: boolean; onClose: () => void; }

type Tab = 'llm' | 'mcp' | 'methodology' | 'appearance' | 'about';

export function SettingsModal({ isOpen, onClose }: Props) {
  const [activeTab, setActiveTab] = useState<Tab>('llm');
  const [providers, setProviders] = useState<Provider[]>(FALLBACK_PROVIDERS);
  const [selected, setSelected] = useState<string | null>(null);
  const [config, setConfig] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState(true);
  const [testing, setTesting] = useState(false);
  const [saving, setSaving] = useState(false);
  const [result, setResult] = useState<{ success: boolean; message: string; latency?: number } | null>(null);
  const [current, setCurrent] = useState<any>(null);
  const [detectedModels, setDetectedModels] = useState<string[]>([]);
  const [showApiKey, setShowApiKey] = useState(false);
  const [copied, setCopied] = useState(false);
  const [backendConnected, setBackendConnected] = useState(false);
  const [showModelSuggestions, setShowModelSuggestions] = useState(false);
  const [connectionDebug, setConnectionDebug] = useState<ConnectionDebug | null>(null);
  const [checkingServer, setCheckingServer] = useState(false);
  
  const modelInputRef = useRef<HTMLInputElement>(null);
  
  // Methodology settings
  const [defaultMethodology, setDefaultMethodology] = useState<'stride' | 'pasta' | 'maestro'>('stride');
  
  // Web Search (Grounded Responses)
  const webSearch = useWebSearch();
  
  // Reasoning / Thinking Time
  const reasoning = useReasoning();
  
  // Theme from context
  const { theme, setTheme } = useTheme();

  // MCP Server state
  const [mcpServers, setMcpServers] = useState<MCPServerResponse[]>([]);
  const [mcpLoading, setMcpLoading] = useState(false);
  const [mcpTesting, setMcpTesting] = useState(false);
  const [mcpTestResult, setMcpTestResult] = useState<MCPTestResult | null>(null);
  const [showAddMcp, setShowAddMcp] = useState(false);
  const [newMcpServer, setNewMcpServer] = useState<MCPServerCreate>({
    name: '',
    uri: '',
    transport: 'http',
    auth_type: 'none',
    enabled: true
  });

  // MCP Registry state
  const [mcpRegistry, setMcpRegistry] = useState<MCPRegistryServer[]>([]);
  const [registryLoading, setRegistryLoading] = useState(false);
  const [showRegistry, setShowRegistry] = useState(false);
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null);
  const [installingServer, setInstallingServer] = useState<string | null>(null);
  const [authInputs, setAuthInputs] = useState<Record<string, string>>({});
  const [importResult, setImportResult] = useState<MCPImportResult | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const llmFileInputRef = useRef<HTMLInputElement>(null);

  const loadMcpServers = useCallback(async () => {
    try {
      setMcpLoading(true);
      const servers = await api.getMCPServers();
      setMcpServers(servers);
    } catch (e) {
      console.error('Failed to load MCP servers:', e);
    } finally {
      setMcpLoading(false);
    }
  }, []);

  const loadMcpRegistry = useCallback(async () => {
    try {
      setRegistryLoading(true);
      const registry = await api.getMCPRegistry(selectedCategory || undefined);
      setMcpRegistry(registry.servers);
    } catch (e) {
      console.error('Failed to load MCP registry:', e);
    } finally {
      setRegistryLoading(false);
    }
  }, [selectedCategory]);

  const installFromRegistry = async (server: MCPRegistryServer) => {
    setInstallingServer(server.id);
    try {
      const authValues = server.requires_auth ? authInputs : undefined;
      await api.installFromRegistry(server.id, authValues);
      await loadMcpServers();
      setAuthInputs({});
    } catch (e) {
      console.error('Failed to install MCP server:', e);
    } finally {
      setInstallingServer(null);
    }
  };

  const handleMcpFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    
    try {
      setMcpLoading(true);
      const result = await api.importMCPConfigFile(file);
      setImportResult(result);
      await loadMcpServers();
    } catch (err: any) {
      console.error('Failed to import MCP config:', err);
      setImportResult({ imported_count: 0, imported: [], errors: [{ name: file.name, error: err.message }] });
    } finally {
      setMcpLoading(false);
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  };

  const handleLLMFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    
    try {
      setLoading(true);
      await api.importLLMConfigFile(file);
      await load();
      setResult({ success: true, message: 'LLM configuration imported successfully' });
    } catch (err: any) {
      console.error('Failed to import LLM config:', err);
      setResult({ success: false, message: err.message || 'Failed to import LLM configuration' });
    } finally {
      setLoading(false);
      if (llmFileInputRef.current) llmFileInputRef.current.value = '';
    }
  };

  const exportMcpConfig = async () => {
    try {
      const config = await api.exportMCPConfig();
      const blob = new Blob([JSON.stringify(config, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'mcp.json';
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      console.error('Failed to export MCP config:', e);
    }
  };

  const testMcpConnection = async () => {
    setMcpTesting(true);
    setMcpTestResult(null);
    try {
      const result = await api.testMCPConnection({
        uri: newMcpServer.uri,
        transport: newMcpServer.transport,
        auth_type: newMcpServer.auth_type,
        auth_credentials: newMcpServer.auth_credentials
      });
      setMcpTestResult(result);
    } catch (e: any) {
      setMcpTestResult({ success: false, error: e.message || 'Connection failed' });
    } finally {
      setMcpTesting(false);
    }
  };

  const addMcpServer = async () => {
    try {
      setMcpLoading(true);
      await api.addMCPServer(newMcpServer);
      setNewMcpServer({ name: '', uri: '', transport: 'http', auth_type: 'none', enabled: true });
      setShowAddMcp(false);
      setMcpTestResult(null);
      await loadMcpServers();
    } catch (e: any) {
      console.error('Failed to add MCP server:', e);
    } finally {
      setMcpLoading(false);
    }
  };

  const deleteMcpServer = async (serverId: string) => {
    try {
      await api.deleteMCPServer(serverId);
      await loadMcpServers();
    } catch (e: any) {
      console.error('Failed to delete MCP server:', e);
    }
  };

  const toggleMcpServer = async (server: MCPServerResponse) => {
    try {
      if (server.connected) {
        await api.disconnectMCPServer(server.id);
      } else {
        await api.connectMCPServer(server.id);
      }
      await loadMcpServers();
    } catch (e: any) {
      console.error('Failed to toggle MCP server:', e);
    }
  };

  const load = useCallback(async () => {
    try {
      setLoading(true);
      const [provs, settings] = await Promise.all([api.getProviders(), api.getCurrentSettings()]);
      setProviders(provs.length > 0 ? provs : FALLBACK_PROVIDERS);
      setCurrent(settings);
      setBackendConnected(true);
      if (settings.llm_provider && settings.llm_provider !== 'none') {
        setSelected(settings.llm_provider);
      }
    } catch (e: any) { 
      console.error('Settings load failed:', e);
      setBackendConnected(false);
      setProviders(FALLBACK_PROVIDERS);
    } finally { 
      setLoading(false); 
    }
  }, []);

  useEffect(() => { 
    if (isOpen) {
      load();
      loadMcpServers();
      loadMcpRegistry();
      const savedMethodology = localStorage.getItem('defaultMethodology') as 'stride' | 'pasta' | null;
      if (savedMethodology) setDefaultMethodology(savedMethodology);
    } else {
      // Reset state when modal closes
      setSelected(null);
      setConfig({});
      setResult(null);
      setConnectionDebug(null);
      setDetectedModels([]);
    }
  }, [isOpen, load]);

  // Auto-detect models when provider is selected
  useEffect(() => {
    if (selected === 'ollama') {
      detectOllamaModels();
    } else if (selected === 'lmstudio') {
      detectLmStudioModels();
    }
  }, [selected]);

  // Re-detect when base_url changes
  useEffect(() => {
    if (selected === 'ollama' && config.base_url) {
      const timer = setTimeout(() => detectOllamaModels(), 500);
      return () => clearTimeout(timer);
    }
  }, [config.base_url]);

  const detectOllamaModels = async () => {
    const url = config.base_url || 'http://localhost:11434';
    setCheckingServer(true);
    setConnectionDebug({ status: 'checking', message: 'Checking Ollama server...' });
    
    try {
      // First try the backend API
      if (backendConnected) {
        const response = await api.getOllamaModels(url);
        if (response.available && response.models && response.models.length > 0) {
          setDetectedModels(response.models);
          setConnectionDebug({
            status: 'connected',
            message: `Found ${response.models.length} model(s)`,
            details: `Connected to Ollama at ${url}`
          });
          // Auto-select first model if none selected
          if (!config.model) {
            setConfig(c => ({ ...c, model: response.models[0] }));
          }
          setCheckingServer(false);
          return;
        }
      }

      // Fallback: try direct fetch to Ollama
      const directResponse = await fetch(`${url}/api/tags`);
      if (directResponse.ok) {
        const data = await directResponse.json();
        const models = data.models?.map((m: any) => m.name) || [];
        if (models.length > 0) {
          setDetectedModels(models);
          setConnectionDebug({
            status: 'connected',
            message: `Found ${models.length} model(s)`,
            details: `Connected to Ollama at ${url}`
          });
          if (!config.model) {
            setConfig(c => ({ ...c, model: models[0] }));
          }
        } else {
          setDetectedModels([]);
          setConnectionDebug({
            status: 'not_running',
            message: 'No models installed',
            details: 'Ollama is running but no models are installed',
            steps: [
              'Open a terminal and run: ollama pull gemma3',
              'Or: ollama pull llama3.2',
              'Wait for the download to complete',
              'Then click Refresh to detect models'
            ]
          });
        }
      } else {
        throw new Error('Ollama server not responding');
      }
    } catch (e: any) {
      setDetectedModels([]);
      setConnectionDebug({
        status: 'error',
        message: 'Cannot connect to Ollama',
        details: e.message || 'Connection refused',
        steps: [
          'Install Ollama: https://ollama.ai',
          'After install, Ollama starts automatically',
          'Download a model: ollama pull gemma3',
          `Check: curl ${url}/api/tags`
        ]
      });
    } finally {
      setCheckingServer(false);
    }
  };

  const detectLmStudioModels = async () => {
    const url = config.base_url || 'http://localhost:1234/v1';
    setCheckingServer(true);
    setConnectionDebug({ status: 'checking', message: 'Checking LM Studio server...' });
    
    try {
      const response = await fetch(`${url}/models`);
      if (response.ok) {
        const data = await response.json();
        const models = data.data?.map((m: any) => m.id) || [];
        setDetectedModels(models);
        
        if (models.length > 0) {
          setConnectionDebug({
            status: 'connected',
            message: `Found ${models.length} model(s)`,
            details: `Connected to LM Studio at ${url}`
          });
          if (!config.model) {
            setConfig(c => ({ ...c, model: models[0] }));
          }
        } else {
          setConnectionDebug({
            status: 'not_running',
            message: 'No models loaded',
            details: 'LM Studio server is running but no model is loaded',
            steps: [
              'Open LM Studio',
              'Go to "Local Server" tab',
              'Load a model before starting the server'
            ]
          });
        }
      } else {
        throw new Error('Server responded with error');
      }
    } catch (e: any) {
      setDetectedModels([]);
      setConnectionDebug({
        status: 'error',
        message: 'Cannot connect to LM Studio',
        details: e.message || 'Connection refused',
        steps: [
          'Download LM Studio from https://lmstudio.ai',
          'Open LM Studio and download a model',
          'Go to "Local Server" tab',
          'Click "Start Server"'
        ]
      });
    } finally {
      setCheckingServer(false);
    }
  };

  const selectProvider = (id: string) => {
    setSelected(id);
    setResult(null);
    setConnectionDebug(null);
    setDetectedModels([]);
    const p = providers.find(x => x.id === id);
    if (p) {
      const defaults: Record<string, string> = { model: p.default_model };
      p.config_fields.forEach(f => f.default && (defaults[f.name] = f.default));
      setConfig(defaults);
    }
  };

  const goBack = () => {
    setSelected(null);
    setConfig({});
    setResult(null);
    setConnectionDebug(null);
    setDetectedModels([]);
  };

  const test = async () => {
    if (!selected || !config.model) {
      setResult({ success: false, message: 'Please select a model first' });
      return;
    }
    
    setTesting(true);
    setResult(null);
    
    try {
      // If backend not connected, show specific error
      if (!backendConnected) {
        setResult({
          success: false,
          message: 'Backend server is not running. Start the backend first.'
        });
        return;
      }

      const r = await api.testProvider({ provider: selected, ...config });
      setResult({ 
        success: r.success, 
        message: r.message,
        latency: r.latency_ms
      });
      
      if (!r.success && selected === 'ollama') {
        setConnectionDebug({
          status: 'error',
          message: 'Test failed',
          details: r.message,
          steps: [
            `Verify the model is installed: ollama list`,
            `Try running: ollama run ${config.model}`,
            'Check Ollama logs for errors'
          ]
        });
      }
    } catch (e: any) { 
      console.error('Test failed:', e);
      setResult({ success: false, message: e.message || 'Connection test failed' });
    } finally { 
      setTesting(false); 
    }
  };

  const save = async () => {
    if (!selected || !config.model) {
      setResult({ success: false, message: 'Please select a model first' });
      return;
    }

    if (!backendConnected) {
      setResult({ success: false, message: 'Backend server is not running. Start the backend first.' });
      return;
    }

    setSaving(true);
    try {
      await api.configureProvider({ provider: selected, ...config });
      setCurrent({ ...current, llm_provider: selected, is_configured: true });
      setResult({ success: true, message: 'Configuration saved successfully!' });
      setTimeout(() => onClose(), 1500);
    } catch (e: any) { 
      setResult({ success: false, message: e.message || 'Save failed' }); 
    } finally { 
      setSaving(false); 
    }
  };

  const copyCommand = (cmd: string) => {
    navigator.clipboard.writeText(cmd);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleMethodologyChange = (methodology: 'stride' | 'pasta' | 'maestro') => {
    setDefaultMethodology(methodology);
    localStorage.setItem('defaultMethodology', methodology);
  };

  const handleModelSelect = (model: string) => {
    setConfig(c => ({ ...c, model }));
    setShowModelSuggestions(false);
    setResult(null);
  };

  const selectedProvider = selected ? providers.find(p => p.id === selected) : null;
  const providerMeta = selected ? PROVIDER_META[selected] : null;
  const ProviderIcon = providerMeta?.icon || Cloud;

  // Get available models
  const availableModels = detectedModels.length > 0 
    ? detectedModels 
    : (selectedProvider?.available_models || []);

  // Filter models based on input
  const filteredModels = availableModels.filter(m => 
    !config.model || m.toLowerCase().includes((config.model || '').toLowerCase())
  );

  // Check if configuration is valid for saving/testing
  const isModelSelected = Boolean(config.model && config.model.trim().length > 0);
  const isApiKeyRequired = selectedProvider?.requires_api_key || false;
  const hasApiKey = Boolean(config.api_key && config.api_key.trim().length > 0);
  const canTest = isModelSelected && (!isApiKeyRequired || hasApiKey);
  const canSave = canTest && backendConnected;

  if (!isOpen) return null;

  const tabs: { id: Tab; label: string; icon: any }[] = [
    { id: 'llm', label: 'AI Provider', icon: Cpu },
    { id: 'mcp', label: 'MCP Servers', icon: Plug },
    { id: 'methodology', label: 'Methodology', icon: Shield },
    { id: 'appearance', label: 'Appearance', icon: Palette },
    { id: 'about', label: 'About', icon: HelpCircle },
  ];

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
          className="relative w-full max-w-3xl max-h-[85vh] overflow-hidden rounded-3xl bg-background border border-border shadow-2xl" 
          onClick={e => e.stopPropagation()}
        >
          {/* Header */}
          <div className="flex items-center justify-between p-5 border-b border-border">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-xl bg-gradient-to-br from-primary to-purple-600">
                <Settings className="w-5 h-5 text-white" />
              </div>
              <div>
                <h2 className="text-lg font-bold">Settings</h2>
                <p className="text-sm text-muted-foreground">Configure your security review platform</p>
              </div>
            </div>
            <button onClick={onClose} className="p-2 rounded-xl hover:bg-muted transition-colors">
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Tabs */}
          <div className="flex border-b border-border px-5 overflow-x-auto">
            {tabs.map(tab => (
              <button
                key={tab.id}
                onClick={() => { setActiveTab(tab.id); setSelected(null); }}
                className={cn(
                  'flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors whitespace-nowrap',
                  activeTab === tab.id 
                    ? 'border-primary text-primary' 
                    : 'border-transparent text-muted-foreground hover:text-foreground'
                )}
              >
                <tab.icon className="w-4 h-4" />
                {tab.label}
              </button>
            ))}
          </div>

          {/* Content */}
          <div className="p-5 overflow-y-auto max-h-[calc(85vh-180px)]">
            {/* LLM Tab */}
            {activeTab === 'llm' && (
              <div className="space-y-6">
                {/* Import Config File */}
                <div className="flex items-center gap-3 p-3 rounded-xl bg-muted/50 border border-border">
                  <span className="text-sm text-muted-foreground">Quick Import:</span>
                  <input
                    type="file"
                    ref={llmFileInputRef}
                    accept=".json"
                    onChange={handleLLMFileUpload}
                    className="hidden"
                  />
                  <button
                    onClick={() => llmFileInputRef.current?.click()}
                    className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-background border border-border hover:border-primary transition-colors"
                  >
                    <FileText className="w-3.5 h-3.5" />
                    Import llm-config.json
                  </button>
                  <span className="text-xs text-muted-foreground ml-auto">
                    Format: {`{ "provider": "...", "model": "...", "api_key": "..." }`}
                  </span>
                </div>

                {/* Backend Warning */}
                {!backendConnected && !loading && (
                  <div className="flex items-start gap-3 p-4 rounded-xl bg-yellow-500/10 border border-yellow-500/30">
                    <AlertCircle className="w-5 h-5 text-yellow-500 mt-0.5" />
                    <div className="flex-1">
                      <p className="font-medium text-yellow-600 dark:text-yellow-400">Backend not connected</p>
                      <p className="text-sm text-muted-foreground mt-1">
                        Start the backend server to save settings:
                      </p>
                      <pre className="mt-2 p-2 rounded-lg bg-muted text-xs overflow-x-auto">
                        <code>cd backend && uvicorn app.main:app --reload</code>
                      </pre>
                    </div>
                    <button onClick={load} className="p-2 rounded-lg hover:bg-yellow-500/20">
                      <RefreshCw className="w-4 h-4 text-yellow-500" />
                    </button>
                  </div>
                )}

                {/* Current Status */}
                {current?.is_configured && !selected && (
                  <div className="flex items-center gap-3 p-4 rounded-xl bg-green-500/10 border border-green-500/30">
                    <CheckCircle2 className="w-5 h-5 text-green-500" />
                    <div className="flex-1">
                      <p className="font-medium text-green-600 dark:text-green-400">LLM Configured</p>
                      <p className="text-sm text-muted-foreground">
                        Currently using: <span className="font-medium">{current.llm_provider}</span>
                        {current.llm_model && <span> ({current.llm_model})</span>}
                      </p>
                    </div>
                  </div>
                )}

                {/* Provider Selection */}
                {!selected && (
                  <div className="space-y-6">
                    <div>
                      <h3 className="text-lg font-semibold mb-1">Choose Your AI Provider</h3>
                      <p className="text-sm text-muted-foreground">Select how you want to power the security analysis</p>
                    </div>

                    {loading ? (
                      <div className="flex flex-col items-center justify-center py-12">
                        <Loader2 className="w-8 h-8 animate-spin text-primary mb-3" />
                        <p className="text-sm text-muted-foreground">Loading providers...</p>
                      </div>
                    ) : (
                      <>
                        {/* Recommended */}
                        <div>
                          <p className="text-xs font-medium text-muted-foreground mb-3 flex items-center gap-2">
                            <Sparkles className="w-3 h-3 text-yellow-500" />
                            RECOMMENDED FOR BEGINNERS
                          </p>
                          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                            {providers.filter(p => PROVIDER_META[p.id]?.category === 'recommended').map(p => {
                              const meta = PROVIDER_META[p.id];
                              const Icon = meta?.icon || Cloud;
                              return (
                                <motion.button
                                  key={p.id}
                                  onClick={() => selectProvider(p.id)}
                                  whileHover={{ scale: 1.02 }}
                                  whileTap={{ scale: 0.98 }}
                                  className="p-4 rounded-xl border-2 border-border hover:border-primary/50 text-left transition-all hover:shadow-lg hover:shadow-primary/10 cursor-pointer"
                                >
                                  <div className="flex items-start gap-3">
                                    <div className={cn('p-2.5 rounded-xl bg-gradient-to-br', meta?.gradient)}>
                                      <Icon className="w-5 h-5 text-white" />
                                    </div>
                                    <div className="flex-1 min-w-0">
                                      <p className="font-semibold">{p.name}</p>
                                      <p className="text-xs text-muted-foreground mt-0.5 line-clamp-2">{p.description}</p>
                                      <div className="flex items-center gap-3 mt-2 text-xs">
                                        <span className="text-green-500 flex items-center gap-1">
                                          <Check className="w-3 h-3" /> {meta?.setupTime}
                                        </span>
                                        <span className="text-blue-500">{meta?.cost}</span>
                                      </div>
                                    </div>
                                    <ChevronRight className="w-5 h-5 text-muted-foreground" />
                                  </div>
                                </motion.button>
                              );
                            })}
                          </div>
                        </div>

                        {/* Cloud Providers */}
                        <div>
                          <p className="text-xs font-medium text-muted-foreground mb-3 flex items-center gap-2">
                            <Cloud className="w-3 h-3" />
                            CLOUD PROVIDERS
                          </p>
                          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                            {providers.filter(p => PROVIDER_META[p.id]?.category === 'cloud').map(p => {
                              const meta = PROVIDER_META[p.id];
                              const Icon = meta?.icon || Cloud;
                              return (
                                <motion.button
                                  key={p.id}
                                  onClick={() => selectProvider(p.id)}
                                  whileHover={{ scale: 1.02 }}
                                  whileTap={{ scale: 0.98 }}
                                  className="p-3 rounded-xl border-2 border-border hover:border-primary/50 text-left transition-all cursor-pointer"
                                >
                                  <div className="flex items-center gap-2">
                                    <div className={cn('p-1.5 rounded-lg bg-gradient-to-br', meta?.gradient)}>
                                      <Icon className="w-4 h-4 text-white" />
                                    </div>
                                    <span className="font-medium text-sm">{p.name}</span>
                                    <ChevronRight className="w-4 h-4 text-muted-foreground ml-auto" />
                                  </div>
                                </motion.button>
                              );
                            })}
                          </div>
                        </div>

                        {/* Local Options */}
                        <div>
                          <p className="text-xs font-medium text-muted-foreground mb-3 flex items-center gap-2">
                            <Server className="w-3 h-3" />
                            LOCAL / OFFLINE
                          </p>
                          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                            {providers.filter(p => PROVIDER_META[p.id]?.category === 'local').map(p => {
                              const meta = PROVIDER_META[p.id];
                              const Icon = meta?.icon || Server;
                              return (
                                <motion.button
                                  key={p.id}
                                  onClick={() => selectProvider(p.id)}
                                  whileHover={{ scale: 1.02 }}
                                  whileTap={{ scale: 0.98 }}
                                  className="p-3 rounded-xl border-2 border-border hover:border-primary/50 text-left transition-all cursor-pointer"
                                >
                                  <div className="flex items-center gap-2">
                                    <div className={cn('p-1.5 rounded-lg bg-gradient-to-br', meta?.gradient)}>
                                      <Icon className="w-4 h-4 text-white" />
                                    </div>
                                    <span className="font-medium text-sm">{p.name}</span>
                                    <ChevronRight className="w-4 h-4 text-muted-foreground ml-auto" />
                                  </div>
                                </motion.button>
                              );
                            })}
                          </div>
                        </div>
                      </>
                    )}
                  </div>
                )}

                {/* Provider Configuration */}
                {selected && selectedProvider && (
                  <div className="space-y-6">
                    {/* Header */}
                    <div className="flex items-center gap-4">
                      <motion.button 
                        onClick={goBack}
                        whileHover={{ scale: 1.05 }}
                        whileTap={{ scale: 0.95 }}
                        className="p-2 rounded-lg border border-border hover:bg-muted transition-colors"
                      >
                        <ChevronLeft className="w-5 h-5" />
                      </motion.button>
                      <div className={cn('p-3 rounded-xl bg-gradient-to-br', providerMeta?.gradient)}>
                        <ProviderIcon className="w-6 h-6 text-white" />
                      </div>
                      <div className="flex-1">
                        <h3 className="text-lg font-semibold">{selectedProvider.name}</h3>
                        <p className="text-sm text-muted-foreground">{selectedProvider.description}</p>
                      </div>
                    </div>

                    {/* Server Status for Local Providers */}
                    {(selected === 'ollama' || selected === 'lmstudio') && (
                      <div className={cn(
                        'p-4 rounded-xl border',
                        connectionDebug?.status === 'connected' ? 'bg-green-500/10 border-green-500/30' :
                        connectionDebug?.status === 'error' || connectionDebug?.status === 'not_running' ? 'bg-red-500/10 border-red-500/30' :
                        'bg-muted/50 border-border'
                      )}>
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center gap-2">
                            {checkingServer ? (
                              <Loader2 className="w-4 h-4 animate-spin text-primary" />
                            ) : connectionDebug?.status === 'connected' ? (
                              <Wifi className="w-4 h-4 text-green-500" />
                            ) : (
                              <WifiOff className="w-4 h-4 text-red-500" />
                            )}
                            <span className={cn(
                              'font-medium',
                              connectionDebug?.status === 'connected' ? 'text-green-600 dark:text-green-400' :
                              connectionDebug?.status === 'error' || connectionDebug?.status === 'not_running' ? 'text-red-600 dark:text-red-400' :
                              'text-muted-foreground'
                            )}>
                              {connectionDebug?.message || 'Checking server...'}
                            </span>
                          </div>
                          <button 
                            onClick={selected === 'ollama' ? detectOllamaModels : detectLmStudioModels}
                            disabled={checkingServer}
                            className="p-1.5 rounded-lg hover:bg-muted disabled:opacity-50"
                            title="Refresh"
                          >
                            <RefreshCw className={cn('w-4 h-4', checkingServer && 'animate-spin')} />
                          </button>
                        </div>
                        
                        {connectionDebug?.details && (
                          <p className="text-sm text-muted-foreground mb-2">{connectionDebug.details}</p>
                        )}
                        
                        {connectionDebug?.steps && connectionDebug.steps.length > 0 && (
                          <div className="mt-3 p-3 rounded-lg bg-muted/50">
                            <p className="text-xs font-medium mb-2 flex items-center gap-1">
                              <Terminal className="w-3 h-3" />
                              Setup Steps:
                            </p>
                            <ol className="text-xs text-muted-foreground space-y-1.5">
                              {connectionDebug.steps.map((step, i) => (
                                <li key={i} className="flex items-start gap-2">
                                  <span className="text-primary font-bold">{i + 1}.</span>
                                  <span className="font-mono break-all">{step}</span>
                                </li>
                              ))}
                            </ol>
                          </div>
                        )}
                      </div>
                    )}

                    {/* API Key for Cloud Providers */}
                    {selectedProvider.requires_api_key && (
                      <div>
                        <label className="block text-sm font-medium mb-2">
                          API Key <span className="text-red-500">*</span>
                        </label>
                        <div className="relative">
                          <input 
                            type={showApiKey ? 'text' : 'password'} 
                            value={config.api_key || ''} 
                            placeholder={`Enter your ${selectedProvider.name} API key`}
                            onChange={e => { setConfig(c => ({ ...c, api_key: e.target.value })); setResult(null); }}
                            className="w-full px-4 py-3 rounded-xl bg-background dark:bg-muted border border-border focus:border-primary focus:ring-2 focus:ring-primary/20 outline-none pr-12" 
                          />
                          <button 
                            type="button"
                            onClick={() => setShowApiKey(!showApiKey)}
                            className="absolute right-3 top-1/2 -translate-y-1/2 p-1.5 rounded-lg hover:bg-muted"
                          >
                            {showApiKey ? <EyeOff className="w-4 h-4 text-muted-foreground" /> : <Eye className="w-4 h-4 text-muted-foreground" />}
                          </button>
                        </div>
                      </div>
                    )}

                    {/* Base URL for Local Providers */}
                    {(selected === 'ollama' || selected === 'lmstudio') && (
                      <div>
                        <label className="block text-sm font-medium mb-2">Server URL</label>
                        <input 
                          type="text" 
                          value={config.base_url || ''} 
                          placeholder={selected === 'ollama' ? 'http://localhost:11434' : 'http://localhost:1234/v1'}
                          onChange={e => { setConfig(c => ({ ...c, base_url: e.target.value })); setResult(null); }}
                          className="w-full px-4 py-3 rounded-xl bg-background dark:bg-muted border border-border focus:border-primary focus:ring-2 focus:ring-primary/20 outline-none" 
                        />
                      </div>
                    )}

                    {/* Model Selection */}
                    <div className="relative">
                      <label className="block text-sm font-medium mb-2">
                        Model <span className="text-red-500">*</span>
                        {detectedModels.length > 0 && (
                          <span className="ml-2 text-xs text-green-500 font-normal">
                            ({detectedModels.length} detected)
                          </span>
                        )}
                      </label>
                      <div className="relative">
                        <input 
                          ref={modelInputRef}
                          type="text"
                          value={config.model || ''} 
                          placeholder="Type or select a model..."
                          onChange={e => { setConfig(c => ({ ...c, model: e.target.value })); setResult(null); }}
                          onFocus={() => setShowModelSuggestions(true)}
                          onBlur={() => setTimeout(() => setShowModelSuggestions(false), 200)}
                          className="w-full px-4 py-3 rounded-xl bg-background dark:bg-muted border border-border focus:border-primary focus:ring-2 focus:ring-primary/20 outline-none pr-10" 
                        />
                        <button 
                          type="button"
                          onClick={() => {
                            setShowModelSuggestions(!showModelSuggestions);
                            modelInputRef.current?.focus();
                          }}
                          className="absolute right-3 top-1/2 -translate-y-1/2 p-1"
                        >
                          <ChevronRight className={cn(
                            "w-4 h-4 text-muted-foreground transition-transform",
                            showModelSuggestions && "rotate-90"
                          )} />
                        </button>
                      </div>
                      
                      {/* Model Dropdown */}
                      <AnimatePresence>
                        {showModelSuggestions && filteredModels.length > 0 && (
                          <motion.div
                            initial={{ opacity: 0, y: -10 }}
                            animate={{ opacity: 1, y: 0 }}
                            exit={{ opacity: 0, y: -10 }}
                            className="absolute z-20 w-full mt-1 max-h-48 overflow-y-auto rounded-xl bg-background border border-border shadow-lg"
                          >
                            {filteredModels.map((model) => (
                              <button
                                key={model}
                                type="button"
                                onMouseDown={(e) => {
                                  e.preventDefault();
                                  handleModelSelect(model);
                                }}
                                className={cn(
                                  'w-full px-4 py-2.5 text-left text-sm hover:bg-muted transition-colors flex items-center justify-between',
                                  config.model === model && 'bg-primary/10 text-primary'
                                )}
                              >
                                <span className="font-mono">{model}</span>
                                {config.model === model && <Check className="w-4 h-4" />}
                              </button>
                            ))}
                          </motion.div>
                        )}
                      </AnimatePresence>
                      
                      <p className="text-xs text-muted-foreground mt-1.5">
                        {detectedModels.length > 0 
                          ? 'Select from detected models or type a custom model name'
                          : 'Type a model name (e.g., llama3.2, gemma3, mistral)'
                        }
                      </p>
                    </div>

                    {/* Result */}
                    <AnimatePresence>
                      {result && (
                        <motion.div 
                          initial={{ opacity: 0, y: -10 }} 
                          animate={{ opacity: 1, y: 0 }} 
                          exit={{ opacity: 0, y: -10 }}
                          className={cn(
                            'flex items-start gap-3 p-4 rounded-xl',
                            result.success ? 'bg-green-500/10 border border-green-500/30' : 'bg-red-500/10 border border-red-500/30'
                          )}
                        >
                          {result.success ? <CheckCircle2 className="w-5 h-5 text-green-500 mt-0.5" /> : <XCircle className="w-5 h-5 text-red-500 mt-0.5" />}
                          <div className="flex-1">
                            <p className={cn('font-medium', result.success ? 'text-green-600 dark:text-green-400' : 'text-red-600 dark:text-red-400')}>
                              {result.success ? 'Success!' : 'Failed'}
                            </p>
                            <p className="text-sm text-muted-foreground">{result.message}</p>
                            {result.latency && <p className="text-xs text-muted-foreground mt-1">Response time: {result.latency}ms</p>}
                          </div>
                        </motion.div>
                      )}
                    </AnimatePresence>

                    {/* Action Buttons */}
                    <div className="flex items-center gap-3 pt-4 border-t border-border">
                      <motion.button 
                        whileHover={canTest ? { scale: 1.02 } : {}} 
                        whileTap={canTest ? { scale: 0.98 } : {}} 
                        onClick={test} 
                        disabled={testing || !canTest}
                        className={cn(
                          "flex-1 flex items-center justify-center gap-2 px-4 py-3 rounded-xl border-2 font-medium transition-all",
                          canTest 
                            ? "border-primary text-primary hover:bg-primary/10 cursor-pointer" 
                            : "border-border text-muted-foreground opacity-50 cursor-not-allowed"
                        )}
                      >
                        {testing ? <Loader2 className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
                        Test Connection
                      </motion.button>
                      <motion.button 
                        whileHover={canSave ? { scale: 1.02 } : {}} 
                        whileTap={canSave ? { scale: 0.98 } : {}} 
                        onClick={save} 
                        disabled={saving || !canSave}
                        className={cn(
                          "flex-1 flex items-center justify-center gap-2 px-4 py-3 rounded-xl font-medium transition-all",
                          canSave 
                            ? "bg-gradient-to-r from-primary to-purple-600 text-white cursor-pointer" 
                            : "bg-muted text-muted-foreground opacity-50 cursor-not-allowed"
                        )}
                      >
                        {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : <Check className="w-4 h-4" />}
                        Save & Activate
                      </motion.button>
                    </div>

                    {/* Help Text */}
                    {!canTest && (
                      <p className="text-xs text-muted-foreground text-center">
                        {!isModelSelected && "Select or type a model name to enable testing"}
                        {isModelSelected && isApiKeyRequired && !hasApiKey && "Enter your API key to enable testing"}
                        {isModelSelected && (!isApiKeyRequired || hasApiKey) && !backendConnected && "Start the backend server to save settings"}
                      </p>
                    )}
                  </div>
                )}
              </div>
            )}

            {/* MCP Servers Tab */}
            {activeTab === 'mcp' && (
              <div className="space-y-6">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-lg font-semibold mb-1">External MCP Servers</h3>
                    <p className="text-sm text-muted-foreground">
                      Connect to Model Context Protocol servers for additional security tools and data sources
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    <motion.button
                      whileHover={{ scale: 1.02 }}
                      whileTap={{ scale: 0.98 }}
                      onClick={() => setShowRegistry(!showRegistry)}
                      className={cn(
                        "flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-colors",
                        showRegistry ? "bg-purple-500/20 text-purple-600 dark:text-purple-400" : "bg-muted hover:bg-muted/80"
                      )}
                    >
                      <Sparkles className="w-4 h-4" />
                      Registry
                    </motion.button>
                    <motion.button
                      whileHover={{ scale: 1.02 }}
                      whileTap={{ scale: 0.98 }}
                      onClick={() => setShowAddMcp(true)}
                      className="flex items-center gap-2 px-3 py-2 rounded-lg bg-primary text-white text-sm font-medium"
                    >
                      <Plus className="w-4 h-4" />
                      Add
                    </motion.button>
                  </div>
                </div>

                {/* Import/Export Bar */}
                <div className="flex items-center gap-3 p-3 rounded-xl bg-muted/50 border border-border">
                  <span className="text-sm text-muted-foreground">Quick Actions:</span>
                  <input
                    type="file"
                    ref={fileInputRef}
                    accept=".json"
                    onChange={handleMcpFileUpload}
                    className="hidden"
                  />
                  <button
                    onClick={() => fileInputRef.current?.click()}
                    className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-background border border-border hover:border-primary transition-colors"
                  >
                    <FileText className="w-3.5 h-3.5" />
                    Import mcp.json
                  </button>
                  <button
                    onClick={exportMcpConfig}
                    className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-background border border-border hover:border-primary transition-colors"
                  >
                    <Copy className="w-3.5 h-3.5" />
                    Export Config
                  </button>
                  <a
                    href="https://github.com/modelcontextprotocol/servers"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-background border border-border hover:border-primary transition-colors ml-auto"
                  >
                    <ExternalLink className="w-3.5 h-3.5" />
                    Browse All Servers
                  </a>
                </div>

                {/* Import Result */}
                {importResult && (
                  <motion.div
                    initial={{ opacity: 0, y: -10 }}
                    animate={{ opacity: 1, y: 0 }}
                    className={cn(
                      "p-3 rounded-lg text-sm",
                      importResult.imported_count > 0 
                        ? "bg-green-500/10 border border-green-500/30 text-green-600 dark:text-green-400"
                        : "bg-red-500/10 border border-red-500/30 text-red-600 dark:text-red-400"
                    )}
                  >
                    <div className="flex items-center justify-between">
                      <span>
                        {importResult.imported_count > 0 
                          ? `✓ Imported ${importResult.imported_count} server(s)`
                          : `✗ Import failed: ${importResult.errors[0]?.error}`
                        }
                      </span>
                      <button onClick={() => setImportResult(null)} className="text-muted-foreground hover:text-foreground">
                        <X className="w-4 h-4" />
                      </button>
                    </div>
                  </motion.div>
                )}

                {/* MCP Server Registry */}
                {showRegistry && (
                  <motion.div
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: 'auto' }}
                    exit={{ opacity: 0, height: 0 }}
                    className="p-4 rounded-xl border-2 border-purple-500/30 bg-purple-500/5 space-y-4"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Sparkles className="w-5 h-5 text-purple-500" />
                        <h4 className="font-semibold">MCP Server Registry</h4>
                      </div>
                      <div className="flex items-center gap-2 text-xs">
                        <button 
                          onClick={() => setSelectedCategory(null)}
                          className={cn("px-2 py-1 rounded-md", !selectedCategory ? "bg-purple-500/20" : "hover:bg-muted")}
                        >
                          All
                        </button>
                        {['Core', 'Developer Tools', 'Security', 'Databases'].map(cat => (
                          <button
                            key={cat}
                            onClick={() => setSelectedCategory(cat)}
                            className={cn("px-2 py-1 rounded-md", selectedCategory === cat ? "bg-purple-500/20" : "hover:bg-muted")}
                          >
                            {cat}
                          </button>
                        ))}
                      </div>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 max-h-80 overflow-y-auto">
                      {registryLoading ? (
                        <div className="col-span-2 text-center py-4">
                          <Loader2 className="w-5 h-5 animate-spin mx-auto" />
                        </div>
                      ) : mcpRegistry.filter(s => !selectedCategory || s.category === selectedCategory).map(server => (
                        <motion.div
                          key={server.id}
                          initial={{ opacity: 0 }}
                          animate={{ opacity: 1 }}
                          className="p-3 rounded-lg border border-border bg-background/50 hover:border-purple-500/50 transition-colors"
                        >
                          <div className="flex items-start justify-between mb-2">
                            <div>
                              <h5 className="font-medium text-sm">{server.name}</h5>
                              <p className="text-xs text-muted-foreground">{server.category}</p>
                            </div>
                            <span className={cn(
                              "px-1.5 py-0.5 text-[10px] rounded-full",
                              server.source === 'official' ? "bg-green-500/10 text-green-600" :
                              server.source === 'docker' ? "bg-blue-500/10 text-blue-600" :
                              "bg-gray-500/10 text-gray-600"
                            )}>
                              {server.source}
                            </span>
                          </div>
                          <p className="text-xs text-muted-foreground mb-3 line-clamp-2">{server.description}</p>
                          
                          {/* Auth fields if required */}
                          {server.requires_auth && server.auth_fields && installingServer === server.id && (
                            <div className="space-y-2 mb-3">
                              {server.auth_fields.map(field => (
                                <input
                                  key={field.name}
                                  type={field.type === 'password' ? 'password' : 'text'}
                                  placeholder={field.label}
                                  value={authInputs[field.name] || ''}
                                  onChange={(e) => setAuthInputs({ ...authInputs, [field.name]: e.target.value })}
                                  className="w-full px-2 py-1.5 text-xs rounded-md bg-muted border border-border focus:border-purple-500 outline-none"
                                />
                              ))}
                            </div>
                          )}
                          
                          <div className="flex items-center gap-2">
                            <motion.button
                              whileHover={{ scale: 1.02 }}
                              whileTap={{ scale: 0.98 }}
                              onClick={() => server.requires_auth ? setInstallingServer(server.id) : installFromRegistry(server)}
                              disabled={installingServer === server.id && server.requires_auth && !Object.keys(authInputs).length}
                              className="flex-1 flex items-center justify-center gap-1.5 px-2 py-1.5 text-xs font-medium rounded-md bg-purple-500/10 text-purple-600 dark:text-purple-400 hover:bg-purple-500/20"
                            >
                              {installingServer === server.id ? (
                                <>
                                  {server.requires_auth && !Object.keys(authInputs).length ? (
                                    <Key className="w-3.5 h-3.5" />
                                  ) : (
                                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                                  )}
                                  {server.requires_auth && !Object.keys(authInputs).length ? 'Enter Credentials' : 'Installing...'}
                                </>
                              ) : (
                                <>
                                  <Plus className="w-3.5 h-3.5" />
                                  Install
                                </>
                              )}
                            </motion.button>
                            {installingServer === server.id && server.requires_auth && Object.keys(authInputs).length > 0 && (
                              <motion.button
                                whileHover={{ scale: 1.02 }}
                                whileTap={{ scale: 0.98 }}
                                onClick={() => installFromRegistry(server)}
                                className="px-2 py-1.5 text-xs font-medium rounded-md bg-green-500/10 text-green-600 hover:bg-green-500/20"
                              >
                                <Check className="w-3.5 h-3.5" />
                              </motion.button>
                            )}
                            {server.docs_url && (
                              <a
                                href={server.docs_url}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="p-1.5 rounded-md hover:bg-muted"
                              >
                                <ExternalLink className="w-3.5 h-3.5" />
                              </a>
                            )}
                          </div>
                        </motion.div>
                      ))}
                    </div>
                  </motion.div>
                )}

                {/* Add New Server Form */}
                {showAddMcp && (
                  <motion.div
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: 'auto' }}
                    exit={{ opacity: 0, height: 0 }}
                    className="p-5 rounded-xl border-2 border-primary/30 bg-primary/5 space-y-4"
                  >
                    <h4 className="font-semibold">Add New MCP Server</h4>
                    
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                      <div>
                        <label className="block text-sm font-medium mb-1.5">Server Name</label>
                        <input
                          type="text"
                          value={newMcpServer.name}
                          onChange={(e) => setNewMcpServer({ ...newMcpServer, name: e.target.value })}
                          placeholder="e.g., GitHub Security Tools"
                          className="w-full px-3 py-2 rounded-lg bg-background dark:bg-muted border border-border focus:border-primary outline-none text-sm"
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-medium mb-1.5">Server URI</label>
                        <input
                          type="url"
                          value={newMcpServer.uri}
                          onChange={(e) => setNewMcpServer({ ...newMcpServer, uri: e.target.value })}
                          placeholder="https://api.example.com/mcp"
                          className="w-full px-3 py-2 rounded-lg bg-background dark:bg-muted border border-border focus:border-primary outline-none text-sm"
                        />
                      </div>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                      <div>
                        <label className="block text-sm font-medium mb-1.5">Transport</label>
                        <select
                          value={newMcpServer.transport}
                          onChange={(e) => setNewMcpServer({ ...newMcpServer, transport: e.target.value })}
                          className="w-full px-3 py-2 rounded-lg bg-background dark:bg-muted border border-border focus:border-primary outline-none text-sm"
                        >
                          <option value="http">Streamable HTTP (Recommended)</option>
                          <option value="sse">Server-Sent Events (SSE)</option>
                          <option value="stdio">Standard I/O (Local)</option>
                        </select>
                      </div>
                      <div>
                        <label className="block text-sm font-medium mb-1.5">Authentication</label>
                        <select
                          value={newMcpServer.auth_type}
                          onChange={(e) => setNewMcpServer({ ...newMcpServer, auth_type: e.target.value })}
                          className="w-full px-3 py-2 rounded-lg bg-background dark:bg-muted border border-border focus:border-primary outline-none text-sm"
                        >
                          <option value="none">No Authentication</option>
                          <option value="api_key">API Key</option>
                          <option value="bearer">Bearer Token</option>
                          <option value="oauth2">OAuth 2.0</option>
                        </select>
                      </div>
                    </div>

                    {(newMcpServer.auth_type === 'api_key' || newMcpServer.auth_type === 'bearer') && (
                      <div>
                        <label className="block text-sm font-medium mb-1.5">
                          {newMcpServer.auth_type === 'api_key' ? 'API Key' : 'Bearer Token'}
                        </label>
                        <input
                          type="password"
                          value={newMcpServer.auth_credentials?.token || newMcpServer.auth_credentials?.api_key || ''}
                          onChange={(e) => setNewMcpServer({ 
                            ...newMcpServer, 
                            auth_credentials: { 
                              [newMcpServer.auth_type === 'api_key' ? 'api_key' : 'token']: e.target.value 
                            } 
                          })}
                          placeholder={newMcpServer.auth_type === 'api_key' ? 'Enter API key' : 'Enter bearer token'}
                          className="w-full px-3 py-2 rounded-lg bg-background dark:bg-muted border border-border focus:border-primary outline-none text-sm"
                        />
                      </div>
                    )}

                    <div>
                      <label className="block text-sm font-medium mb-1.5">Description (Optional)</label>
                      <input
                        type="text"
                        value={newMcpServer.description || ''}
                        onChange={(e) => setNewMcpServer({ ...newMcpServer, description: e.target.value })}
                        placeholder="Brief description of this server's capabilities"
                        className="w-full px-3 py-2 rounded-lg bg-background dark:bg-muted border border-border focus:border-primary outline-none text-sm"
                      />
                    </div>

                    {/* Test Result */}
                    {mcpTestResult && (
                      <div className={cn(
                        "p-3 rounded-lg text-sm",
                        mcpTestResult.success 
                          ? "bg-green-500/10 border border-green-500/30 text-green-600 dark:text-green-400"
                          : "bg-red-500/10 border border-red-500/30 text-red-600 dark:text-red-400"
                      )}>
                        {mcpTestResult.success ? (
                          <div>
                            <div className="font-medium flex items-center gap-2">
                              <CheckCircle2 className="w-4 h-4" />
                              Connection Successful!
                            </div>
                            {mcpTestResult.server_info && (
                              <div className="mt-2 text-xs opacity-80">
                                Discovered: {mcpTestResult.server_info.tools_count} tools, {mcpTestResult.server_info.resources_count} resources
                              </div>
                            )}
                          </div>
                        ) : (
                          <div className="flex items-center gap-2">
                            <XCircle className="w-4 h-4" />
                            {mcpTestResult.error}
                          </div>
                        )}
                      </div>
                    )}

                    <div className="flex items-center gap-3 pt-2">
                      <motion.button
                        whileHover={{ scale: 1.02 }}
                        whileTap={{ scale: 0.98 }}
                        onClick={testMcpConnection}
                        disabled={!newMcpServer.uri || mcpTesting}
                        className="flex items-center gap-2 px-4 py-2 rounded-lg border border-border hover:border-primary text-sm disabled:opacity-50"
                      >
                        {mcpTesting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Wifi className="w-4 h-4" />}
                        Test Connection
                      </motion.button>
                      <motion.button
                        whileHover={{ scale: 1.02 }}
                        whileTap={{ scale: 0.98 }}
                        onClick={addMcpServer}
                        disabled={!newMcpServer.name || !newMcpServer.uri || mcpLoading}
                        className="flex items-center gap-2 px-4 py-2 rounded-lg bg-primary text-white text-sm font-medium disabled:opacity-50"
                      >
                        {mcpLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
                        Add Server
                      </motion.button>
                      <button
                        onClick={() => { setShowAddMcp(false); setMcpTestResult(null); }}
                        className="px-4 py-2 text-sm text-muted-foreground hover:text-foreground"
                      >
                        Cancel
                      </button>
                    </div>
                  </motion.div>
                )}

                {/* Server List */}
                <div className="space-y-3">
                  {mcpLoading && mcpServers.length === 0 ? (
                    <div className="text-center py-8 text-muted-foreground">
                      <Loader2 className="w-6 h-6 animate-spin mx-auto mb-2" />
                      Loading MCP servers...
                    </div>
                  ) : mcpServers.length === 0 ? (
                    <div className="text-center py-8 border-2 border-dashed border-border rounded-xl">
                      <Plug className="w-10 h-10 mx-auto mb-3 text-muted-foreground" />
                      <p className="text-muted-foreground mb-2">No MCP servers configured</p>
                      <p className="text-sm text-muted-foreground">
                        Add external MCP servers to extend your security analysis capabilities
                      </p>
                    </div>
                  ) : (
                    mcpServers.map((server) => (
                      <motion.div
                        key={server.id}
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        className="p-4 rounded-xl border border-border bg-muted/30 hover:border-primary/30 transition-colors"
                      >
                        <div className="flex items-start justify-between">
                          <div className="flex-1">
                            <div className="flex items-center gap-2 mb-1">
                              <h4 className="font-medium">{server.name}</h4>
                              <span className={cn(
                                "px-2 py-0.5 rounded-full text-xs font-medium",
                                server.connected 
                                  ? "bg-green-500/10 text-green-600 dark:text-green-400"
                                  : "bg-gray-500/10 text-gray-600 dark:text-gray-400"
                              )}>
                                {server.connected ? 'Connected' : 'Disconnected'}
                              </span>
                            </div>
                            <p className="text-sm text-muted-foreground mb-2 flex items-center gap-1">
                              <Link className="w-3 h-3" />
                              {server.uri}
                            </p>
                            {server.connected && (
                              <div className="flex items-center gap-3 text-xs text-muted-foreground">
                                <span>{server.tools_count} tools</span>
                                <span>•</span>
                                <span>{server.resources_count} resources</span>
                                <span>•</span>
                                <span>{server.prompts_count} prompts</span>
                              </div>
                            )}
                            {server.description && (
                              <p className="text-xs text-muted-foreground mt-1">{server.description}</p>
                            )}
                          </div>
                          <div className="flex items-center gap-2">
                            <motion.button
                              whileHover={{ scale: 1.05 }}
                              whileTap={{ scale: 0.95 }}
                              onClick={() => toggleMcpServer(server)}
                              className={cn(
                                "p-2 rounded-lg transition-colors",
                                server.connected 
                                  ? "bg-green-500/10 text-green-600 hover:bg-green-500/20"
                                  : "bg-gray-500/10 text-gray-600 hover:bg-gray-500/20"
                              )}
                              title={server.connected ? 'Disconnect' : 'Connect'}
                            >
                              {server.connected ? <WifiOff className="w-4 h-4" /> : <Wifi className="w-4 h-4" />}
                            </motion.button>
                            <motion.button
                              whileHover={{ scale: 1.05 }}
                              whileTap={{ scale: 0.95 }}
                              onClick={() => api.refreshMCPServer(server.id).then(loadMcpServers)}
                              disabled={!server.connected}
                              className="p-2 rounded-lg bg-muted hover:bg-muted/80 text-muted-foreground disabled:opacity-50"
                              title="Refresh"
                            >
                              <RefreshCw className="w-4 h-4" />
                            </motion.button>
                            <motion.button
                              whileHover={{ scale: 1.05 }}
                              whileTap={{ scale: 0.95 }}
                              onClick={() => deleteMcpServer(server.id)}
                              className="p-2 rounded-lg bg-red-500/10 text-red-600 hover:bg-red-500/20"
                              title="Delete"
                            >
                              <Trash2 className="w-4 h-4" />
                            </motion.button>
                          </div>
                        </div>
                      </motion.div>
                    ))
                  )}
                </div>

                {/* Info Box */}
                <div className="p-4 rounded-xl bg-blue-500/10 border border-blue-500/20">
                  <h4 className="font-medium text-blue-600 dark:text-blue-400 mb-2 flex items-center gap-2">
                    <HelpCircle className="w-4 h-4" />
                    What are MCP Servers?
                  </h4>
                  <p className="text-sm text-muted-foreground">
                    Model Context Protocol (MCP) allows AI agents to connect to external tools and data sources.
                    Add MCP servers to enhance your security analysis with specialized capabilities like:
                  </p>
                  <ul className="text-sm text-muted-foreground mt-2 space-y-1 list-disc list-inside">
                    <li>GitHub Security Advisories & Code Scanning</li>
                    <li>NIST NVD & CVE Database Access</li>
                    <li>Cloud Provider Security APIs (AWS, GCP, Azure)</li>
                    <li>Custom Security Knowledge Bases</li>
                  </ul>
                </div>
              </div>
            )}

            {/* Methodology Tab */}
            {activeTab === 'methodology' && (
              <div className="space-y-6">
                <div>
                  <h3 className="text-lg font-semibold mb-1">Default Threat Modeling Methodology</h3>
                  <p className="text-sm text-muted-foreground">Choose which methodology to use by default</p>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                  <motion.button
                    whileHover={{ scale: 1.02 }}
                    whileTap={{ scale: 0.98 }}
                    onClick={() => handleMethodologyChange('stride')}
                    className={cn(
                      'p-4 rounded-xl border-2 text-left transition-all relative overflow-hidden',
                      defaultMethodology === 'stride' ? 'border-blue-500 bg-blue-500/5' : 'border-border hover:border-blue-500/50'
                    )}
                  >
                    <div className="absolute top-0 right-0 w-20 h-20 bg-gradient-to-br from-blue-500/20 to-cyan-500/20 rounded-full blur-2xl" />
                    <div className="relative">
                      <div className="flex items-center gap-2 mb-2">
                        <div className="p-1.5 rounded-lg bg-gradient-to-br from-blue-500 to-cyan-500">
                          <Shield className="w-4 h-4 text-white" />
                        </div>
                        <h4 className="font-semibold">STRIDE</h4>
                        {defaultMethodology === 'stride' && <CheckCircle2 className="w-4 h-4 text-blue-500 ml-auto" />}
                      </div>
                      <p className="text-xs text-muted-foreground mb-3">
                        Microsoft's threat classification model.
                      </p>
                      <div className="flex flex-wrap gap-1">
                        {['Spoofing', 'Tampering', 'Repudiation', 'Info Disclosure', 'DoS', 'Elevation'].map(t => (
                          <span key={t} className="text-[10px] px-1.5 py-0.5 rounded-full bg-blue-500/10 text-blue-600 dark:text-blue-400 font-medium">{t}</span>
                        ))}
                      </div>
                    </div>
                  </motion.button>

                  <motion.button
                    whileHover={{ scale: 1.02 }}
                    whileTap={{ scale: 0.98 }}
                    onClick={() => handleMethodologyChange('pasta')}
                    className={cn(
                      'p-4 rounded-xl border-2 text-left transition-all relative overflow-hidden',
                      defaultMethodology === 'pasta' ? 'border-purple-500 bg-purple-500/5' : 'border-border hover:border-purple-500/50'
                    )}
                  >
                    <div className="absolute top-0 right-0 w-20 h-20 bg-gradient-to-br from-purple-500/20 to-pink-500/20 rounded-full blur-2xl" />
                    <div className="relative">
                      <div className="flex items-center gap-2 mb-2">
                        <div className="p-1.5 rounded-lg bg-gradient-to-br from-purple-500 to-pink-500">
                          <Target className="w-4 h-4 text-white" />
                        </div>
                        <h4 className="font-semibold">PASTA</h4>
                        {defaultMethodology === 'pasta' && <CheckCircle2 className="w-4 h-4 text-purple-500 ml-auto" />}
                      </div>
                      <p className="text-xs text-muted-foreground mb-3">
                        Risk-centric attack simulation.
                      </p>
                      <div className="flex flex-wrap gap-1">
                        {['Objectives', 'Attack Trees', 'Risk Analysis'].map(t => (
                          <span key={t} className="text-[10px] px-1.5 py-0.5 rounded-full bg-purple-500/10 text-purple-600 dark:text-purple-400 font-medium">{t}</span>
                        ))}
                      </div>
                    </div>
                  </motion.button>

                  <motion.button
                    whileHover={{ scale: 1.02 }}
                    whileTap={{ scale: 0.98 }}
                    onClick={() => handleMethodologyChange('maestro')}
                    className={cn(
                      'p-4 rounded-xl border-2 text-left transition-all relative overflow-hidden',
                      defaultMethodology === 'maestro' ? 'border-orange-500 bg-orange-500/5' : 'border-border hover:border-orange-500/50'
                    )}
                  >
                    <div className="absolute top-0 right-0 w-20 h-20 bg-gradient-to-br from-orange-500/20 to-red-500/20 rounded-full blur-2xl" />
                    <span className="absolute top-2 right-2 px-1.5 py-0.5 rounded text-[9px] font-bold uppercase bg-gradient-to-r from-orange-500 to-red-500 text-white">
                      AI
                    </span>
                    <div className="relative">
                      <div className="flex items-center gap-2 mb-2">
                        <div className="p-1.5 rounded-lg bg-gradient-to-br from-orange-500 to-red-500">
                          <Bot className="w-4 h-4 text-white" />
                        </div>
                        <h4 className="font-semibold">MAESTRO</h4>
                        {defaultMethodology === 'maestro' && <CheckCircle2 className="w-4 h-4 text-orange-500 ml-auto" />}
                      </div>
                      <p className="text-xs text-muted-foreground mb-3">
                        CSA's Agentic AI framework.
                      </p>
                      <div className="flex flex-wrap gap-1">
                        {['Autonomous', 'Multi-Agent', 'Tool Abuse', 'Memory', 'Goals', 'LLM Trust'].map(t => (
                          <span key={t} className="text-[10px] px-1.5 py-0.5 rounded-full bg-orange-500/10 text-orange-600 dark:text-orange-400 font-medium">{t}</span>
                        ))}
                      </div>
                    </div>
                  </motion.button>
                </div>

                {/* Web Search / Grounded Responses */}
                <div className="pt-6 border-t border-border">
                  <div className="mb-4">
                    <h3 className="text-lg font-semibold mb-1 flex items-center gap-2">
                      <Globe className="w-5 h-5" />
                      Web Search (Grounded Responses)
                    </h3>
                    <p className="text-sm text-muted-foreground">
                      Enable web search for factual answers with citations. When disabled, the AI uses internal knowledge only.
                    </p>
                  </div>

                  <div className="space-y-3">
                    {/* Current Session Toggle */}
                    <div className="flex items-center justify-between p-4 rounded-xl border border-border bg-muted/30">
                      <div className="flex items-center gap-3">
                        <div className={cn(
                          "p-2 rounded-lg",
                          webSearch.enabled ? "bg-emerald-500/20" : "bg-muted"
                        )}>
                          <Search className={cn(
                            "w-5 h-5",
                            webSearch.enabled ? "text-emerald-500" : "text-muted-foreground"
                          )} />
                        </div>
                        <div>
                          <p className="font-medium">Web Search (Current Session)</p>
                          <p className="text-xs text-muted-foreground">
                            {webSearch.isLoading ? (
                              'Checking availability...'
                            ) : webSearch.isAvailable ? (
                              <span className="text-emerald-500">Available ({webSearch.status?.provider})</span>
                            ) : (
                              <span className="text-amber-500">Not configured</span>
                            )}
                          </p>
                        </div>
                      </div>
                      
                      {/* Toggle Switch */}
                      <button
                        onClick={() => webSearch.setEnabled(!webSearch.enabled)}
                        className={cn(
                          "relative w-12 h-6 rounded-full transition-colors",
                          webSearch.enabled ? "bg-emerald-500" : "bg-muted-foreground/30"
                        )}
                      >
                        <motion.div
                          initial={false}
                          animate={{ x: webSearch.enabled ? 24 : 2 }}
                          transition={{ type: "spring", stiffness: 500, damping: 30 }}
                          className="absolute top-1 w-4 h-4 rounded-full bg-white shadow"
                        />
                      </button>
                    </div>

                    {/* Default Enable Toggle - Always use for grounded responses */}
                    <div className="flex items-center justify-between p-4 rounded-xl border border-primary/30 bg-primary/5">
                      <div className="flex items-center gap-3">
                        <div className={cn(
                          "p-2 rounded-lg",
                          webSearch.defaultEnabled ? "bg-primary/20" : "bg-muted"
                        )}>
                          <Globe className={cn(
                            "w-5 h-5",
                            webSearch.defaultEnabled ? "text-primary" : "text-muted-foreground"
                          )} />
                        </div>
                        <div>
                          <p className="font-medium">Always Enable for Grounded Responses</p>
                          <p className="text-xs text-muted-foreground">
                            Automatically enable web search in all new chats for fact-checked answers
                          </p>
                        </div>
                      </div>
                      
                      {/* Toggle Switch */}
                      <button
                        onClick={() => webSearch.setDefaultEnabled(!webSearch.defaultEnabled)}
                        className={cn(
                          "relative w-12 h-6 rounded-full transition-colors",
                          webSearch.defaultEnabled ? "bg-primary" : "bg-muted-foreground/30"
                        )}
                      >
                        <motion.div
                          initial={false}
                          animate={{ x: webSearch.defaultEnabled ? 24 : 2 }}
                          transition={{ type: "spring", stiffness: 500, damping: 30 }}
                          className="absolute top-1 w-4 h-4 rounded-full bg-white shadow"
                        />
                      </button>
                    </div>

                    {/* Test Connection Button */}
                    {webSearch.isAvailable && (
                      <TestWebSearchButton />
                    )}
                  </div>

                  {/* Available Providers */}
                  {webSearch.providers.length > 0 && (
                    <div className="mt-4 space-y-2">
                      <p className="text-sm font-medium">Available Providers:</p>
                      <div className="grid grid-cols-2 gap-2">
                        {webSearch.providers.map(provider => (
                          <motion.div 
                            key={provider.id}
                            whileHover={{ scale: 1.01 }}
                            onClick={() => {
                              // Copy the provider ID to clipboard for .env setup
                              navigator.clipboard.writeText(`SEARCH_PROVIDER=${provider.id}`);
                              setResult({ success: true, message: `Copied SEARCH_PROVIDER=${provider.id} - add this to your .env file` });
                              setTimeout(() => setResult(null), 3000);
                            }}
                            className={cn(
                              "p-3 rounded-lg border text-sm cursor-pointer transition-all",
                              webSearch.status?.provider === provider.id 
                                ? "border-emerald-500 bg-emerald-500/10 ring-2 ring-emerald-500/20" 
                                : "border-border bg-muted/30 hover:border-primary/50 hover:bg-muted/50"
                            )}
                            title={`Click to copy: SEARCH_PROVIDER=${provider.id}`}
                          >
                            <div className="flex items-center gap-2">
                              <span className="font-medium">{provider.name}</span>
                              {provider.is_open_source && (
                                <span className="text-[10px] px-1.5 py-0.5 rounded bg-blue-500/20 text-blue-500">OSS</span>
                              )}
                              {webSearch.status?.provider === provider.id && (
                                <CheckCircle2 className="w-4 h-4 text-emerald-500 ml-auto" />
                              )}
                              {provider.requires_api_key && webSearch.status?.provider !== provider.id && (
                                <Key className="w-3 h-3 text-muted-foreground ml-auto" />
                              )}
                            </div>
                            <p className="text-xs text-muted-foreground mt-1">{provider.description}</p>
                            {provider.requires_api_key && webSearch.status?.provider !== provider.id && (
                              <p className="text-[10px] text-amber-500 mt-1">Requires API key</p>
                            )}
                          </motion.div>
                        ))}
                      </div>
                      <p className="text-xs text-muted-foreground mt-2">
                        Click a provider to copy its env variable. Then add it to your <code className="px-1 py-0.5 bg-muted rounded">.env</code> file and restart the backend.
                      </p>
                    </div>
                  )}

                  {/* Status Info */}
                  {webSearch.enabled && !webSearch.isAvailable && !webSearch.isLoading && (
                    <div className="mt-3 p-3 rounded-lg bg-amber-500/10 border border-amber-500/30">
                      <div className="flex items-start gap-2">
                        <AlertCircle className="w-4 h-4 text-amber-500 mt-0.5 flex-shrink-0" />
                        <div className="text-sm">
                          <p className="font-medium text-amber-500">Web search not configured</p>
                          <p className="text-muted-foreground mt-1">
                            <strong>Recommended:</strong> Set up SearXNG (open-source, self-hosted):
                          </p>
                          <div className="mt-2 p-2 bg-muted rounded-lg space-y-2">
                            <div className="flex items-center justify-between">
                              <code className="text-xs font-mono break-all">docker compose -f infra/docker/compose/docker-compose.search.yml up -d</code>
                              <button
                                onClick={() => {
                                  navigator.clipboard.writeText('docker compose -f infra/docker/compose/docker-compose.search.yml up -d');
                                  setCopied(true);
                                  setTimeout(() => setCopied(false), 2000);
                                }}
                                className="p-1 rounded hover:bg-muted-foreground/10 flex-shrink-0"
                                title="Copy command"
                              >
                                {copied ? <Check className="w-3 h-3 text-emerald-500" /> : <Copy className="w-3 h-3" />}
                              </button>
                            </div>
                          </div>
                          <p className="text-muted-foreground mt-2 text-xs">
                            After starting SearXNG, add <code className="px-1 py-0.5 bg-muted rounded text-xs">SEARCH_PROVIDER=searxng</code> to your .env and restart.
                          </p>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Safety Warning */}
                  <div className="mt-3 flex items-start gap-2 text-xs text-muted-foreground">
                    <HelpCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
                    <p>
                      When enabled, queries may be sent to a search provider for verification. 
                      <strong className="text-foreground"> Avoid pasting secrets or sensitive data</strong> when web search is active.
                    </p>
                  </div>
                </div>

                {/* Thinking Time / Reasoning Control */}
                <div className="pt-6 border-t border-border">
                  <div className="mb-4">
                    <h3 className="text-lg font-semibold mb-1 flex items-center gap-2">
                      <Sparkles className="w-5 h-5" />
                      Thinking Time
                    </h3>
                    <p className="text-sm text-muted-foreground">
                      Control how deeply the AI reasons before responding.
                    </p>
                  </div>

                  {/* Reasoning Level Selector */}
                  <div className="grid grid-cols-3 gap-2">
                    {[
                      { id: 'fast', name: 'Fast', icon: Zap, desc: 'Quick responses', color: 'blue' },
                      { id: 'balanced', name: 'Balanced', icon: Target, desc: 'Default mode', color: 'emerald' },
                      { id: 'deep', name: 'Deep', icon: Sparkles, desc: 'Extensive reasoning', color: 'purple' },
                    ].map(level => (
                      <motion.button
                        key={level.id}
                        whileHover={{ scale: 1.02 }}
                        whileTap={{ scale: 0.98 }}
                        onClick={() => reasoning.setLevel(level.id as ReasoningLevel)}
                        className={cn(
                          'p-3 rounded-xl border-2 text-center transition-all',
                          reasoning.level === level.id 
                            ? `border-${level.color}-500 bg-${level.color}-500/10` 
                            : 'border-border hover:border-primary/50'
                        )}
                      >
                        <level.icon className={cn(
                          'w-5 h-5 mx-auto mb-1',
                          reasoning.level === level.id ? `text-${level.color}-500` : 'text-muted-foreground'
                        )} />
                        <p className="text-sm font-medium">{level.name}</p>
                        <p className="text-xs text-muted-foreground">{level.desc}</p>
                      </motion.button>
                    ))}
                  </div>

                  {/* Show Reasoning Summary Toggle */}
                  <div className="mt-4 flex items-center justify-between p-3 rounded-lg border border-border bg-muted/30">
                    <div>
                      <p className="text-sm font-medium">Show Reasoning Summary</p>
                      <p className="text-xs text-muted-foreground">
                        Display key steps and assumptions (not raw chain-of-thought)
                      </p>
                    </div>
                    <button
                      onClick={() => reasoning.setShowSummary(!reasoning.showSummary)}
                      className={cn(
                        "relative w-10 h-5 rounded-full transition-colors",
                        reasoning.showSummary ? "bg-primary" : "bg-muted-foreground/30"
                      )}
                    >
                      <motion.div
                        initial={false}
                        animate={{ x: reasoning.showSummary ? 20 : 2 }}
                        transition={{ type: "spring", stiffness: 500, damping: 30 }}
                        className="absolute top-0.5 w-4 h-4 rounded-full bg-white shadow"
                      />
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* Appearance Tab */}
            {activeTab === 'appearance' && (
              <div className="space-y-6">
                <div>
                  <h3 className="text-lg font-semibold mb-1">Theme</h3>
                  <p className="text-sm text-muted-foreground">Choose your preferred color scheme</p>
                </div>

                <div className="grid grid-cols-3 gap-3">
                  {[
                    { id: 'light', label: 'Light', icon: Sun, desc: 'Light background' },
                    { id: 'dark', label: 'Dark', icon: Moon, desc: 'Dark background' },
                    { id: 'system', label: 'System', icon: Monitor, desc: 'Match OS' },
                  ].map(t => (
                    <motion.button
                      key={t.id}
                      whileHover={{ scale: 1.02 }}
                      whileTap={{ scale: 0.98 }}
                      onClick={() => setTheme(t.id as any)}
                      className={cn(
                        'p-4 rounded-xl border-2 text-center transition-all',
                        theme === t.id ? 'border-primary bg-primary/5' : 'border-border hover:border-primary/50'
                      )}
                    >
                      <t.icon className={cn('w-6 h-6 mx-auto mb-2', theme === t.id ? 'text-primary' : 'text-muted-foreground')} />
                      <p className="font-medium text-sm">{t.label}</p>
                      <p className="text-xs text-muted-foreground mt-1">{t.desc}</p>
                    </motion.button>
                  ))}
                </div>
              </div>
            )}

            {/* About Tab */}
            {activeTab === 'about' && (
              <div className="space-y-6">
                <div className="text-center py-6">
                  <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-primary to-purple-600 flex items-center justify-center mx-auto mb-4">
                    <Shield className="w-8 h-8 text-white" />
                  </div>
                  <h3 className="text-xl font-bold">PadmaVue.ai</h3>
                  <p className="text-sm text-muted-foreground">Version 1.0.0</p>
                </div>

                <div className="space-y-3">
                  <div className="p-4 rounded-xl bg-muted/50 border border-border">
                    <h4 className="font-medium mb-2">About</h4>
                    <p className="text-sm text-muted-foreground">
                      AI-powered security review platform for threat modeling and security analysis.
                    </p>
                  </div>

                  <div className="p-4 rounded-xl bg-muted/50 border border-border">
                    <h4 className="font-medium mb-2">Features</h4>
                    <ul className="text-sm text-muted-foreground space-y-1">
                      <li className="flex items-center gap-2"><CheckCircle2 className="w-4 h-4 text-green-500" /> STRIDE & PASTA threat modeling</li>
                      <li className="flex items-center gap-2"><CheckCircle2 className="w-4 h-4 text-green-500" /> AI Security Architect chat</li>
                      <li className="flex items-center gap-2"><CheckCircle2 className="w-4 h-4 text-green-500" /> DREAD risk scoring</li>
                      <li className="flex items-center gap-2"><CheckCircle2 className="w-4 h-4 text-green-500" /> Multi-LLM provider support</li>
                    </ul>
                  </div>
                </div>
              </div>
            )}
          </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  );
}
