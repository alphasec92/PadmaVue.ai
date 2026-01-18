const API_BASE_URL = process.env.NEXT_PUBLIC_BACKEND_URL || 'http://localhost:8000';

// Error class with detailed information
export class ApiError extends Error {
  cause: string;
  solution: string;
  statusCode?: number;

  constructor(message: string, cause: string, solution: string, statusCode?: number) {
    super(message);
    this.name = 'ApiError';
    this.cause = cause;
    this.solution = solution;
    this.statusCode = statusCode;
  }
}

// Parse error response into helpful message
function parseApiError(error: any, statusCode?: number, endpoint?: string): ApiError {
  // Handle FastAPI validation errors (array of error objects)
  let detail: string;
  if (Array.isArray(error?.detail)) {
    // Format validation errors nicely
    detail = error.detail.map((err: any) => {
      const field = Array.isArray(err.loc) ? err.loc.join('.') : 'field';
      return `${field}: ${err.msg || 'validation error'}`;
    }).join('; ');
  } else if (Array.isArray(error)) {
    // Direct array of validation errors
    detail = error.map((err: any) => {
      const field = Array.isArray(err.loc) ? err.loc.join('.') : 'field';
      return `${field}: ${err.msg || 'validation error'}`;
    }).join('; ');
  } else {
    detail = error?.detail || error?.message || String(error);
  }
  
  // Network/Connection errors
  if (detail.includes('Failed to fetch') || detail.includes('NetworkError') || detail.includes('Network request failed')) {
    return new ApiError(
      'Cannot connect to backend server',
      'The backend server at http://localhost:8000 is not running or not accessible',
      'Start the backend server:\n1. Open terminal\n2. cd backend\n3. source venv/bin/activate\n4. uvicorn app.main:app --reload --port 8000'
    );
  }

  // LLM/Provider errors
  if (detail.includes('LLM') || detail.includes('provider') || detail.includes('No API key') || detail.includes('model')) {
    return new ApiError(
      'LLM provider not configured',
      'No AI model is configured to process requests',
      'Click the ⚙️ Settings icon in the navbar to configure an LLM:\n• Ollama (free, local): Run "ollama run llama3.2"\n• OpenRouter: Get API key from openrouter.ai\n• OpenAI: Use your API key',
      statusCode
    );
  }

  // Rate limiting
  if (statusCode === 429 || detail.includes('rate') || detail.includes('Too many')) {
    return new ApiError(
      'Rate limit exceeded',
      'Too many requests sent in a short time',
      'Wait 10-30 seconds and try again',
      429
    );
  }

  // Timeout errors
  if (detail.includes('timeout') || detail.includes('Timeout') || detail.includes('timed out')) {
    return new ApiError(
      'Request timed out',
      'The server took too long to respond (AI processing can be slow)',
      'Try again. If using Ollama, ensure you have enough RAM (8GB+). Consider using a smaller model.',
      statusCode
    );
  }

  // Server errors
  if (statusCode === 500 || detail.includes('Internal') || detail.includes('server error')) {
    return new ApiError(
      'Server error',
      'The backend encountered an error while processing your request',
      'Check backend terminal for error logs. Common causes:\n• Ollama model not running\n• Invalid API key\n• Memory/resource issues',
      500
    );
  }

  // Validation errors
  if (statusCode === 422 || detail.includes('validation') || detail.includes('Validation')) {
    return new ApiError(
      'Invalid request',
      detail,
      'Check your input and try again',
      422
    );
  }

  // Auth errors
  if (statusCode === 401 || statusCode === 403) {
    return new ApiError(
      'Authentication error',
      'Invalid or missing API credentials',
      'Check your API key in Settings and ensure it\'s valid',
      statusCode
    );
  }

  // Not found
  if (statusCode === 404) {
    return new ApiError(
      'Resource not found',
      `The requested resource (${endpoint}) was not found`,
      'This endpoint may not exist or the resource was deleted',
      404
    );
  }

  // Generic error
  return new ApiError(
    detail || 'Request failed',
    `Server returned status ${statusCode || 'unknown'}`,
    'Check the backend logs for more details. If the issue persists, try restarting the backend server.',
    statusCode
  );
}

// Generic request function for direct API calls
export async function apiRequest<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const url = `${API_BASE_URL}${endpoint}`;
  
  try {
    const response = await fetch(url, options);
    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: `HTTP ${response.status}` }));
      throw parseApiError(error, response.status, endpoint);
    }
    return response.json();
  } catch (err: any) {
    if (err instanceof ApiError) throw err;
    throw parseApiError({ detail: err.message }, undefined, endpoint);
  }
}

interface IngestResponse {
  project_id: string;
  status: string;
  files_processed: number;
  document_count: number;
}

interface AnalysisRequest {
  project_id: string;
  methodology: 'stride' | 'pasta';
  analysis_type?: string;
  include_dfd?: boolean;
  include_compliance?: boolean;
  include_devsecops?: boolean;
  compliance_frameworks?: string[];
  severity_threshold?: string;
  // MAESTRO (Agentic AI) overlay settings
  include_maestro?: boolean;
  force_maestro?: boolean;
  maestro_confidence_threshold?: number;
}

// MAESTRO Applicability result
interface MaestroApplicability {
  applicable: boolean;
  confidence: number;
  status: 'detected' | 'not_detected' | 'forced';
  reasons: string[];
  evidence: Array<{
    source: string;
    snippet: string;
    signal_type: string;
    file?: string;
    confidence: number;
  }>;
  signals?: Record<string, string[]>;
  checked_at?: string;
}

interface OWASPMapping {
  owasp_top_10?: string[];
  owasp_api?: string[];
  owasp_llm?: string[];
  agentic_ai?: string[];
}

interface Threat {
  id: string;
  category: string;
  title: string;
  description: string;
  affected_component: string;
  attack_vector: string;
  severity: string;
  overall_risk: number;
  dread_score: Record<string, number>;
  mitigations: string[];
  compliance_mappings: Record<string, string[]>;
  owasp_mappings?: OWASPMapping;
  threat_agent?: string;
  affected_assets?: string[];
  business_impact?: string;
  stride_category?: string;
  status?: string;
  zone?: string;
  trust_boundary?: string;
  // MAESTRO-specific fields
  methodology?: 'stride' | 'pasta' | 'maestro';
  evidence?: Array<{
    source: string;
    snippet: string;
  }>;
  trust_level?: 'high' | 'medium' | 'low';
}

interface AnalysisResponse {
  analysis_id: string;
  project_id: string;
  methodology: string;
  status: string;
  created_at: string;
  completed_at?: string;
  summary: Record<string, any>;
  threats: Threat[];
  compliance_summary: Record<string, any>;
  dfd_mermaid?: string;
  devsecops_rules?: Record<string, any>;
  pasta_stages?: Record<string, any>;
  // MAESTRO (Agentic AI) results
  maestro_applicability?: MaestroApplicability;
  maestro_threats?: Threat[];
  metadata?: {
    zones?: Zone[];
    trust_boundaries?: TrustBoundary[];
    components?: any[];
    data_flows?: any[];
    diagram?: {
      mermaid_code?: string;
      zones?: Zone[];
      trust_boundaries?: TrustBoundary[];
    };
  };
}

interface DFDResponse {
  project_id: string;
  mermaid_code: string;
  diagram_type: string;
  components: Array<{ id: string; name: string; type: string }>;
  threats_annotated: number;
}

interface Methodology {
  id: string;
  name: string;
  description: string;
  best_for: string;
  complexity: string;
}

class ApiClient {
  private baseUrl: string;

  constructor(baseUrl: string = API_BASE_URL) {
    this.baseUrl = baseUrl;
  }

  // Public request method for generic API calls
  async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    return this._request(endpoint, options);
  }

  private async _request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    const url = `${this.baseUrl}${endpoint}`;
    
    try {
      const response = await fetch(url, {
        ...options,
        headers: {
          ...options.headers,
        },
      });

      if (!response.ok) {
        const error = await response.json().catch(() => ({ detail: `HTTP ${response.status}` }));
        throw parseApiError(error, response.status, endpoint);
      }

      return response.json();
    } catch (err: any) {
      if (err instanceof ApiError) throw err;
      throw parseApiError({ detail: err.message }, undefined, endpoint);
    }
  }

  // Health check
  async health(): Promise<{ status: string; version: string }> {
    return this.request('/health');
  }

  // Get available methodologies
  async getMethodologies(): Promise<Methodology[]> {
    return this.request('/api/analyze/methodologies');
  }

  // Ingest documents
  async ingest(
    formData: FormData,
    onProgress?: (progress: number) => void
  ): Promise<IngestResponse> {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      
      xhr.upload.addEventListener('progress', (event) => {
        if (event.lengthComputable && onProgress) {
          const progress = Math.round((event.loaded / event.total) * 100);
          onProgress(progress);
        }
      });
      
      xhr.addEventListener('load', () => {
        if (xhr.status >= 200 && xhr.status < 300) {
          resolve(JSON.parse(xhr.responseText));
        } else {
          const error = JSON.parse(xhr.responseText);
          reject(new Error(error.detail || 'Upload failed'));
        }
      });
      
      xhr.addEventListener('error', () => {
        reject(new Error('Network error'));
      });
      
      xhr.open('POST', `${this.baseUrl}/api/ingest`);
      xhr.send(formData);
    });
  }

  // Run analysis
  async analyze(request: AnalysisRequest): Promise<AnalysisResponse> {
    return this.request('/api/analyze', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        project_id: request.project_id,
        methodology: request.methodology,
        analysis_type: request.analysis_type || 'full',
        include_dfd: request.include_dfd ?? true,
        include_compliance: request.include_compliance ?? true,
        include_devsecops: request.include_devsecops ?? true,
        compliance_frameworks: request.compliance_frameworks || ['NIST_800_53', 'OWASP_ASVS'],
        severity_threshold: request.severity_threshold || 'low',
        // MAESTRO (Agentic AI) overlay parameters
        include_maestro: request.include_maestro ?? false,
        force_maestro: request.force_maestro ?? false,
        maestro_confidence_threshold: request.maestro_confidence_threshold ?? 0.6,
      }),
    });
  }

  // Get analysis results
  async getAnalysis(analysisId: string): Promise<AnalysisResponse> {
    return this.request(`/api/analyze/${analysisId}`);
  }

  // Get DFD
  async getDFD(projectId: string): Promise<DFDResponse> {
    return this.request(`/api/dfd/${projectId}`);
  }

  // Get report
  async getReport(projectId: string): Promise<any> {
    return this.request(`/api/report/${projectId}`);
  }

  // Compare methodologies
  async compareMethodologies(
    projectId: string,
    severityThreshold: string = 'low'
  ): Promise<any> {
    return this.request(`/api/analyze/compare?project_id=${projectId}&severity_threshold=${severityThreshold}`, {
      method: 'POST',
    });
  }

  // List projects
  async listProjects(): Promise<any> {
    return this.request('/api/ingest');
  }

  // Delete project
  async deleteProject(projectId: string): Promise<void> {
    return this.request(`/api/ingest/${projectId}`, {
      method: 'DELETE',
    });
  }

  // ==========================================
  // Settings API
  // ==========================================

  // Get all available providers
  async getProviders(): Promise<Provider[]> {
    return this.request('/api/settings/providers');
  }

  // Get current settings
  async getCurrentSettings(): Promise<CurrentSettings> {
    return this.request('/api/settings/current');
  }

  // Configure provider
  async configureProvider(config: ProviderConfig): Promise<{ status: string; provider: string; model: string; message: string }> {
    return this.request('/api/settings/configure', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(config),
    });
  }

  // Test provider connection
  async testProvider(config: ProviderConfig): Promise<TestResult> {
    return this.request('/api/settings/test', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(config),
    });
  }

  // Get Ollama models
  async getOllamaModels(baseUrl: string = 'http://localhost:11434'): Promise<{ available: boolean; models: string[]; error?: string }> {
    return this.request(`/api/settings/ollama/models?base_url=${encodeURIComponent(baseUrl)}`);
  }

  // Reset settings
  async resetSettings(): Promise<{ status: string; message: string }> {
    return this.request('/api/settings/reset', {
      method: 'POST',
    });
  }

  // ==========================================
  // Threat Management API
  // ==========================================

  async getThreats(analysisId: string): Promise<{ threats: Threat[]; count: number }> {
    return this.request(`/api/threats/${analysisId}`);
  }

  async createThreat(threat: ThreatCreate): Promise<{ id: string; threat: Threat }> {
    return this.request('/api/threats', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(threat),
    });
  }

  async updateThreat(threatId: string, updates: Partial<Threat>): Promise<{ threat: Threat }> {
    return this.request(`/api/threats/${threatId}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(updates),
    });
  }

  async deleteThreat(threatId: string): Promise<void> {
    return this.request(`/api/threats/${threatId}`, { method: 'DELETE' });
  }

  async updateMitigations(threatId: string, mitigations: string[], status?: string): Promise<any> {
    return this.request(`/api/threats/${threatId}/mitigations`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mitigations, status }),
    });
  }

  // ==========================================
  // Diagram Management API
  // ==========================================

  async getDiagram(analysisId: string): Promise<DiagramData> {
    return this.request(`/api/threats/${analysisId}/diagram`);
  }

  async updateDiagram(analysisId: string, data: DiagramUpdate): Promise<any> {
    return this.request(`/api/threats/${analysisId}/diagram`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
  }

  async addZone(analysisId: string, zone: Zone): Promise<any> {
    return this.request(`/api/threats/${analysisId}/zones`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(zone),
    });
  }

  async addTrustBoundary(analysisId: string, boundary: TrustBoundary): Promise<any> {
    return this.request(`/api/threats/${analysisId}/trust-boundaries`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(boundary),
    });
  }

  async exportThreatModel(analysisId: string): Promise<ThreatModelExport> {
    return this.request(`/api/threats/${analysisId}/export`);
  }

  // ============ MCP Server Management ============

  async getMCPServers(): Promise<MCPServerResponse[]> {
    return this.request('/api/mcp/servers');
  }

  async addMCPServer(server: MCPServerCreate): Promise<any> {
    return this.request('/api/mcp/servers', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(server),
    });
  }

  async updateMCPServer(serverId: string, update: MCPServerUpdate): Promise<any> {
    return this.request(`/api/mcp/servers/${serverId}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(update),
    });
  }

  async deleteMCPServer(serverId: string): Promise<any> {
    return this.request(`/api/mcp/servers/${serverId}`, {
      method: 'DELETE',
    });
  }

  async connectMCPServer(serverId: string): Promise<any> {
    return this.request(`/api/mcp/servers/${serverId}/connect`, {
      method: 'POST',
    });
  }

  async disconnectMCPServer(serverId: string): Promise<any> {
    return this.request(`/api/mcp/servers/${serverId}/disconnect`, {
      method: 'POST',
    });
  }

  async testMCPConnection(config: MCPTestConnection): Promise<MCPTestResult> {
    return this.request('/api/mcp/test-connection', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(config),
    });
  }

  async getMCPTools(): Promise<{ total: number; tools: MCPTool[] }> {
    return this.request('/api/mcp/tools');
  }

  async getMCPResources(): Promise<{ total: number; resources: MCPResource[] }> {
    return this.request('/api/mcp/resources');
  }

  async callMCPTool(serverId: string, toolName: string, args: Record<string, any>): Promise<any> {
    return this.request('/api/mcp/tools/call', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        server_id: serverId,
        tool_name: toolName,
        arguments: args,
      }),
    });
  }

  async refreshMCPServer(serverId: string): Promise<any> {
    return this.request(`/api/mcp/servers/${serverId}/refresh`, {
      method: 'POST',
    });
  }

  // ============ MCP Registry ============

  async getMCPRegistry(category?: string): Promise<MCPRegistryResponse> {
    const params = category ? `?category=${encodeURIComponent(category)}` : '';
    return this.request(`/api/mcp/registry${params}`);
  }

  async installFromRegistry(registryId: string, authValues?: Record<string, string>): Promise<any> {
    return this.request(`/api/mcp/registry/${registryId}/install`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: authValues ? JSON.stringify(authValues) : undefined,
    });
  }

  // ============ Config File Import ============

  async importMCPConfig(config: MCPConfigImport): Promise<MCPImportResult> {
    return this.request('/api/mcp/import/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(config),
    });
  }

  async importMCPConfigFile(file: File): Promise<MCPImportResult> {
    const formData = new FormData();
    formData.append('file', file);
    return this.request('/api/mcp/import/file', {
      method: 'POST',
      body: formData,
    });
  }

  async importLLMConfig(config: LLMConfigImport): Promise<any> {
    return this.request('/api/mcp/import/llm-config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(config),
    });
  }

  async importLLMConfigFile(file: File): Promise<any> {
    const formData = new FormData();
    formData.append('file', file);
    return this.request('/api/mcp/import/llm-file', {
      method: 'POST',
      body: formData,
    });
  }

  async exportMCPConfig(): Promise<{ servers: Record<string, any>; inputs: any[] }> {
    return this.request('/api/mcp/export/config');
  }

  // ============ Web Search (Grounded Responses) ============

  async getWebSearchStatus(): Promise<WebSearchStatus> {
    return this.request('/api/architect-chat/web-search/status');
  }

  async getSearchProviders(): Promise<SearchProvidersResponse> {
    return this.request('/api/architect-chat/web-search/providers');
  }

  async testWebSearch(): Promise<{ success: boolean; message: string; results?: any[] }> {
    return this.request('/api/architect-chat/web-search/test');
  }

  // ============ Reasoning / Thinking Time ============

  async getReasoningStatus(): Promise<ReasoningStatus> {
    return this.request('/api/architect-chat/reasoning/status');
  }
}

// MCP Types
interface MCPServerResponse {
  id: string;
  name: string;
  uri: string;
  transport: string;
  auth_type: string;
  enabled: boolean;
  connected: boolean;
  description?: string;
  tags: string[];
  tools_count: number;
  resources_count: number;
  prompts_count: number;
  created_at: string;
  updated_at: string;
}

interface MCPServerCreate {
  name: string;
  uri: string;
  transport?: string;
  auth_type?: string;
  auth_credentials?: Record<string, string>;
  description?: string;
  tags?: string[];
  enabled?: boolean;
}

interface MCPServerUpdate {
  name?: string;
  uri?: string;
  transport?: string;
  auth_type?: string;
  auth_credentials?: Record<string, string>;
  description?: string;
  tags?: string[];
  enabled?: boolean;
}

interface MCPTestConnection {
  uri: string;
  transport?: string;
  auth_type?: string;
  auth_credentials?: Record<string, string>;
}

interface MCPTestResult {
  success: boolean;
  error?: string;
  server_info?: {
    tools_count: number;
    resources_count: number;
    prompts_count: number;
    tools: { name: string; description: string }[];
    resources: { name: string; uri: string }[];
  };
}

interface MCPTool {
  name: string;
  description: string;
  server_id: string;
  input_schema: Record<string, any>;
}

interface MCPResource {
  uri: string;
  name: string;
  description: string;
  mime_type?: string;
  server_id: string;
}

// MCP Registry Types
interface MCPRegistryServer {
  id: string;
  name: string;
  description: string;
  category: string;
  source: 'official' | 'community' | 'docker';
  config: Record<string, any>;
  requires_auth?: boolean;
  auth_fields?: { name: string; label: string; type: string; default?: string }[];
  tags: string[];
  docs_url?: string;
}

interface MCPRegistryResponse {
  total: number;
  servers: MCPRegistryServer[];
  categories: string[];
  sources: string[];
}

interface MCPConfigImport {
  servers: Record<string, any>;
  inputs?: any[];
}

interface MCPImportResult {
  imported_count: number;
  imported: { id: string; name: string; transport: string; connected: boolean }[];
  errors: { name: string; error: string }[];
}

interface LLMConfigImport {
  provider: string;
  model?: string;
  api_key?: string;
  base_url?: string;
  extra?: Record<string, any>;
}

// Additional types for settings
interface Provider {
  id: string;
  name: string;
  description: string;
  requires_api_key: boolean;
  requires_local: boolean;
  default_model: string;
  available_models: string[];
  config_fields: Array<{
    name: string;
    label: string;
    type: string;
    required: boolean;
    default?: string;
    placeholder?: string;
  }>;
}

interface CurrentSettings {
  llm_provider: string;
  llm_model?: string;
  debug: boolean;
  log_level: string;
  is_configured: boolean;
}

interface ProviderConfig {
  provider: string;
  api_key?: string;
  model?: string;
  base_url?: string;
  project_id?: string;
  region?: string;
  access_key?: string;
  secret_key?: string;
  location?: string;
}

interface TestResult {
  success: boolean;
  message: string;
  latency_ms?: number;
  model_used?: string;
}

interface ThreatCreate {
  analysis_id: string;
  title: string;
  description: string;
  category?: string;
  severity?: string;
  affected_component?: string;
  attack_vector?: string;
  mitigations?: string[];
  dread_score?: Record<string, number>;
  zone?: string;
  trust_boundary?: string;
  stride_category?: string;
  status?: string;
}

interface Zone {
  id: string;
  name: string;
  description?: string;
  color?: string;
  components: string[];
}

interface TrustBoundary {
  id: string;
  name: string;
  zones: string[];
  style?: string;
  color?: string;
}

interface DiagramData {
  analysis_id: string;
  mermaid_code: string;
  metadata?: {
    zones?: Zone[];
    trust_boundaries?: TrustBoundary[];
    components?: any[];
    data_flows?: any[];
  };
}

interface DiagramUpdate {
  mermaid_code: string;
  zones?: Zone[];
  trust_boundaries?: TrustBoundary[];
  components?: any[];
  data_flows?: any[];
}

interface ThreatModelExport {
  version: string;
  exported_at: string;
  project: any;
  analysis: any;
  diagram: any;
  threats: Threat[];
  compliance: any;
  summary: any;
}

interface WebSearchStatus {
  available: boolean;
  provider: string;
  configured: boolean;
  message: string;
  requires_api_key?: boolean;
  is_open_source?: boolean;
}

interface SearchProvider {
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

interface SearchProvidersResponse {
  providers: SearchProvider[];
  current: string;
  configured: boolean;
}

interface ReasoningStatus {
  default_level: string;
  show_summary: boolean;
  levels: Array<{
    id: string;
    name: string;
    description: string;
  }>;
}

export const api = new ApiClient();
export type { 
  IngestResponse, 
  AnalysisRequest, 
  AnalysisResponse, 
  Threat, 
  OWASPMapping, 
  DFDResponse, 
  Methodology,
  Provider,
  CurrentSettings,
  ProviderConfig,
  TestResult,
  ThreatCreate,
  Zone,
  TrustBoundary,
  DiagramData,
  DiagramUpdate,
  ThreatModelExport,
  MCPServerResponse,
  MCPServerCreate,
  MCPServerUpdate,
  MCPTestConnection,
  MCPTestResult,
  MCPTool,
  MCPResource,
  MCPRegistryServer,
  MCPRegistryResponse,
  MCPConfigImport,
  MCPImportResult,
  LLMConfigImport,
  WebSearchStatus,
  SearchProvider,
  SearchProvidersResponse,
  ReasoningStatus
};
