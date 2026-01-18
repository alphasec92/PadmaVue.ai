'use client';

import { useState, useCallback, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { motion, AnimatePresence } from 'framer-motion';
import { useDropzone } from 'react-dropzone';
import { 
  Upload, 
  FileText, 
  X, 
  CheckCircle2, 
  AlertCircle,
  Loader2,
  ArrowRight,
  File,
  FileCode,
  FileJson,
  Sparkles,
  MessageSquare,
  Bot,
  Zap,
  WifiOff,
  Settings,
  RefreshCw,
  HelpCircle
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { MethodologySelector, type MethodologySettings } from '@/components/methodology-selector';
import { useProjectStore } from '@/store/project-store';
import { api } from '@/lib/api';
import { SettingsModal } from '@/components/settings-modal';

const acceptedFileTypes = {
  'application/pdf': ['.pdf'],
  'text/markdown': ['.md'],
  'text/plain': ['.txt'],
  'application/json': ['.json'],
  'text/yaml': ['.yaml', '.yml'],
  'application/xml': ['.xml'],
  'text/x-python': ['.py'],
  'text/javascript': ['.js', '.ts'],
  'application/x-terraform': ['.tf'],
};

const getFileIcon = (filename: string) => {
  const ext = filename.split('.').pop()?.toLowerCase();
  switch (ext) {
    case 'json':
    case 'yaml':
    case 'yml':
      return FileJson;
    case 'py':
    case 'js':
    case 'ts':
    case 'tf':
      return FileCode;
    default:
      return FileText;
  }
};

interface ErrorDetails {
  message: string;
  cause?: string;
  solution?: string;
  isLLMConfig?: boolean;
}

// Parse error into detailed format
function parseError(err: any): ErrorDetails {
  const message = err.message || 'An unknown error occurred';
  
  // Network errors
  if (message.includes('Failed to fetch') || message.includes('Network error') || message.includes('NetworkError')) {
    return {
      message: 'Cannot connect to the backend server',
      cause: 'The backend server is not running or not accessible at http://localhost:8000',
      solution: 'Start the backend server:\n1. Open a terminal\n2. cd backend\n3. source venv/bin/activate\n4. uvicorn app.main:app --reload --port 8000'
    };
  }
  
  // CORS errors
  if (message.includes('CORS') || message.includes('cross-origin')) {
    return {
      message: 'Cross-origin request blocked',
      cause: 'The backend server is not configured to accept requests from the frontend',
      solution: 'Check that the backend CORS settings include http://localhost:3000'
    };
  }
  
  // LLM not configured
  if (message.toLowerCase().includes('llm') || 
      message.toLowerCase().includes('provider not configured') || 
      message.toLowerCase().includes('no llm') ||
      message.toLowerCase().includes('mock mode') ||
      message.toLowerCase().includes('api key') ||
      message.toLowerCase().includes('ollama') && message.toLowerCase().includes('not running') ||
      message.toLowerCase().includes('connection refused')) {
    return {
      message: 'LLM Provider Not Configured',
      cause: 'No AI model is configured to process your request',
      solution: 'Configure an LLM provider (Ollama, OpenAI, Anthropic, etc.) to enable AI-powered threat modeling.',
      isLLMConfig: true
    };
  }
  
  // File too large
  if (message.includes('too large') || message.includes('size')) {
    return {
      message: 'File too large',
      cause: 'One or more files exceed the maximum allowed size of 10MB',
      solution: 'Remove large files or split them into smaller parts'
    };
  }
  
  // Rate limiting
  if (message.includes('rate') || message.includes('429') || message.includes('Too many')) {
    return {
      message: 'Too many requests',
      cause: 'You\'ve exceeded the rate limit for API requests',
      solution: 'Wait a few seconds and try again'
    };
  }
  
  // Server errors
  if (message.includes('500') || message.includes('Internal')) {
    return {
      message: 'Server error',
      cause: 'The backend encountered an internal error while processing your request',
      solution: 'Check the backend logs for details. If using Ollama, ensure the model is running.'
    };
  }
  
  // Timeout
  if (message.includes('timeout') || message.includes('Timeout')) {
    return {
      message: 'Request timed out',
      cause: 'The server took too long to respond (LLM processing can be slow)',
      solution: 'Try again. If using a local LLM like Ollama, ensure you have enough RAM/GPU memory.'
    };
  }
  
  // Default
  return { message };
}

export default function UploadPage() {
  const router = useRouter();
  const { setProjectId, setMethodology } = useProjectStore();
  
  const [files, setFiles] = useState<File[]>([]);
  const [projectName, setProjectName] = useState('');
  const [description, setDescription] = useState('');
  // Methodology settings with MAESTRO overlay support
  const [methodologySettings, setMethodologySettings] = useState<MethodologySettings>({
    primary: 'stride',
    includeMaestro: false,
    forceMaestro: false,
    maestroConfidenceThreshold: 0.6
  });
  const [uploading, setUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [error, setError] = useState<ErrorDetails | null>(null);
  const [inputMode, setInputMode] = useState<'files' | 'chat'>('files');
  const [backendStatus, setBackendStatus] = useState<'checking' | 'connected' | 'disconnected'>('checking');
  const [showSettings, setShowSettings] = useState(false);

  // Check backend on mount
  useEffect(() => {
    checkBackend();
  }, []);

  const checkBackend = async () => {
    setBackendStatus('checking');
    try {
      await api.health();
      setBackendStatus('connected');
    } catch (e) {
      setBackendStatus('disconnected');
    }
  };

  const onDrop = useCallback((acceptedFiles: File[]) => {
    setFiles(prev => [...prev, ...acceptedFiles]);
    setError(null);
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: acceptedFileTypes,
    maxSize: 10 * 1024 * 1024, // 10MB
  });

  const removeFile = (index: number) => {
    setFiles(prev => prev.filter((_, i) => i !== index));
  };

  const handleSubmit = async () => {
    // If chat mode, redirect to architect
    if (inputMode === 'chat') {
      router.push('/architect');
      return;
    }

    if (files.length === 0) {
      setError({ 
        message: 'No files selected',
        cause: 'You need to upload at least one file to analyze',
        solution: 'Drag and drop files into the upload area, or click to browse. Alternatively, use the "Chat with AI" mode to describe your architecture.'
      });
      return;
    }

    if (!projectName.trim()) {
      setError({
        message: 'Project name required',
        cause: 'Every project needs a name for identification',
        solution: 'Enter a name for your project in the "Project Name" field above'
      });
      return;
    }

    setUploading(true);
    setError(null);

    try {
      // Create FormData
      const formData = new FormData();
      formData.append('project_name', projectName);
      formData.append('description', description);
      files.forEach(file => {
        formData.append('files', file);
      });

      // Step 1: Upload and ingest files
      setUploadProgress(30);
      const ingestResponse = await api.ingest(formData, (progress) => {
        setUploadProgress(Math.min(progress * 0.5, 50)); // First 50% is upload
      });

      // Store project info
      setProjectId(ingestResponse.project_id);
      // Map maestro to stride for the store (maestro is an overlay, not a base methodology)
      const baseMethodology = methodologySettings.primary === 'maestro' ? 'stride' : methodologySettings.primary;
      setMethodology(baseMethodology);

      // Step 2: Run security analysis with MAESTRO overlay if enabled
      setUploadProgress(60);
      const analysisResponse = await api.analyze({
        project_id: ingestResponse.project_id,
        methodology: baseMethodology,
        include_dfd: true,
        include_compliance: true,
        include_devsecops: true,
        // MAESTRO (Agentic AI) overlay parameters
        include_maestro: methodologySettings.includeMaestro,
        force_maestro: methodologySettings.forceMaestro,
        maestro_confidence_threshold: methodologySettings.maestroConfidenceThreshold,
      });

      setUploadProgress(100);

      // Navigate to review page with analysis_id
      router.push(`/review?analysis_id=${analysisResponse.analysis_id}`);
    } catch (err: any) {
      setError(parseError(err));
    } finally {
      setUploading(false);
      setUploadProgress(0);
    }
  };

  return (
    <div className="px-4 sm:px-6 lg:px-8 py-8">
      <div className="mx-auto max-w-4xl">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="text-center mb-12"
        >
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full glass mb-6">
            <Sparkles className="w-4 h-4 text-watercolor-coral" />
            <span className="text-sm font-medium">Step 1 of 3</span>
          </div>
          <h1 className="heading-lg mb-4">Start Security Analysis</h1>
          <p className="body-lg max-w-2xl mx-auto">
            Upload documents or chat with our AI Security Architect to analyze your system
          </p>
        </motion.div>

        {/* Backend Status Banner */}
        <AnimatePresence>
          {backendStatus === 'disconnected' && (
            <motion.div
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              className="mb-6 p-4 rounded-xl bg-red-500/10 border border-red-500/30"
            >
              <div className="flex items-start gap-3">
                <WifiOff className="w-5 h-5 text-red-500 mt-0.5" />
                <div className="flex-1">
                  <p className="font-medium text-red-500">Backend not connected</p>
                  <p className="text-sm text-muted-foreground mt-1">
                    Start the backend server to continue:
                  </p>
                  <pre className="mt-2 p-2 rounded bg-muted text-xs overflow-x-auto">
                    <code>cd backend && source venv/bin/activate && uvicorn app.main:app --reload</code>
                  </pre>
                </div>
                <button onClick={checkBackend} className="p-2 rounded-lg hover:bg-muted">
                  <RefreshCw className="w-4 h-4" />
                </button>
              </div>
            </motion.div>
          )}
          {backendStatus === 'checking' && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="mb-6 p-3 rounded-xl bg-muted/50 flex items-center gap-3"
            >
              <Loader2 className="w-4 h-4 animate-spin text-watercolor-coral" />
              <span className="text-sm">Checking backend connection...</span>
            </motion.div>
          )}
        </AnimatePresence>

        <div className="space-y-8">
          {/* Input Mode Toggle */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.05 }}
            className="p-2 rounded-2xl glass"
          >
            <div className="flex gap-2">
              <button
                onClick={() => setInputMode('files')}
                className={cn(
                  'flex-1 flex items-center justify-center gap-3 px-6 py-4 rounded-xl font-medium transition-all',
                  inputMode === 'files' 
                    ? 'bg-gradient-to-r from-watercolor-coral to-watercolor-pink text-white shadow-lg shadow-watercolor-coral/25' 
                    : 'hover:bg-muted'
                )}
              >
                <Upload className="w-5 h-5" />
                <span>Upload Files</span>
              </button>
              <button
                onClick={() => setInputMode('chat')}
                className={cn(
                  'flex-1 flex items-center justify-center gap-3 px-6 py-4 rounded-xl font-medium transition-all',
                  inputMode === 'chat' 
                    ? 'bg-gradient-to-r from-watercolor-coral to-watercolor-pink text-white shadow-lg shadow-watercolor-coral/25' 
                    : 'hover:bg-muted'
                )}
              >
                <Bot className="w-5 h-5" />
                <span>Chat with AI</span>
              </button>
            </div>
          </motion.div>

          {/* Chat Mode Info */}
          <AnimatePresence mode="wait">
            {inputMode === 'chat' && (
              <motion.div
                key="chat-info"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                className="p-6 rounded-2xl glass border-2 border-watercolor-coral/30"
              >
                <div className="flex items-start gap-4">
                  <div className="p-3 rounded-xl bg-gradient-to-br from-watercolor-coral to-watercolor-pink">
                    <MessageSquare className="w-6 h-6 text-white" />
                  </div>
                  <div className="flex-1">
                    <h3 className="text-lg font-semibold mb-2">Security Architect Chat</h3>
                    <p className="text-muted-foreground mb-4">
                      Don't have documentation? No problem! Our AI Security Architect will guide you through 
                      a conversation to understand your system architecture and generate a comprehensive threat model.
                    </p>
                    <ul className="space-y-2 text-sm text-muted-foreground">
                      <li className="flex items-center gap-2">
                        <CheckCircle2 className="w-4 h-4 text-green-500" />
                        Describe your architecture in plain English
                      </li>
                      <li className="flex items-center gap-2">
                        <CheckCircle2 className="w-4 h-4 text-green-500" />
                        Paste code snippets or config files directly
                      </li>
                      <li className="flex items-center gap-2">
                        <CheckCircle2 className="w-4 h-4 text-green-500" />
                        AI infers details and asks smart follow-up questions
                      </li>
                      <li className="flex items-center gap-2">
                        <CheckCircle2 className="w-4 h-4 text-green-500" />
                        Resume anytime - your session is saved
                      </li>
                    </ul>
                  </div>
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Project Info - Show for both modes */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className={cn("p-6 rounded-2xl glass", inputMode === 'chat' && 'opacity-50 pointer-events-none')}
          >
            <h2 className="text-lg font-semibold mb-4">Project Information</h2>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-2">
                  Project Name {inputMode === 'files' && <span className="text-red-500">*</span>}
                </label>
                <input
                  type="text"
                  value={projectName}
                  onChange={(e) => setProjectName(e.target.value)}
                  placeholder="e.g., E-Commerce Platform"
                  disabled={inputMode === 'chat'}
                  className="w-full px-4 py-3 rounded-xl bg-background dark:bg-muted border border-border focus:border-primary focus:ring-2 focus:ring-primary/20 outline-none transition-all disabled:opacity-50"
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-2">Description (optional)</label>
                <textarea
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="Brief description of your system..."
                  rows={3}
                  disabled={inputMode === 'chat'}
                  className="w-full px-4 py-3 rounded-xl bg-background dark:bg-muted border border-border focus:border-primary focus:ring-2 focus:ring-primary/20 outline-none transition-all resize-none disabled:opacity-50"
                />
              </div>
            </div>
            {inputMode === 'chat' && (
              <p className="text-xs text-muted-foreground mt-3 flex items-center gap-1">
                <HelpCircle className="w-3 h-3" />
                Project details will be collected during the chat
              </p>
            )}
          </motion.div>

          {/* Methodology Selection */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
            className="p-6 rounded-2xl glass"
          >
            <MethodologySelector
              settings={methodologySettings}
              onSettingsChange={setMethodologySettings}
              disabled={uploading}
            />
          </motion.div>

          {/* File Upload - Only show in files mode */}
          <AnimatePresence mode="wait">
            {inputMode === 'files' && (
              <motion.div
                key="file-upload"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                transition={{ delay: 0.3 }}
                className="p-6 rounded-2xl glass"
              >
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-lg font-semibold">Upload Files</h2>
                  <span className="text-xs text-muted-foreground px-2 py-1 rounded-full bg-muted">
                    Optional - or use Chat mode
                  </span>
                </div>
                
                {/* Dropzone */}
                <div
                  {...getRootProps()}
                  className={cn(
                    'relative p-8 rounded-xl border-2 border-dashed transition-all cursor-pointer',
                    'hover:border-watercolor-coral hover:bg-watercolor-coral/5',
                    isDragActive 
                      ? 'border-watercolor-coral bg-watercolor-coral/10' 
                      : 'border-border',
                    uploading && 'pointer-events-none opacity-50'
                  )}
                >
                  <input {...getInputProps()} />
                  <div className="text-center">
                    <motion.div
                      animate={isDragActive ? { scale: 1.1, y: -5 } : { scale: 1, y: 0 }}
                      className="w-16 h-16 rounded-2xl bg-watercolor-coral/10 flex items-center justify-center mx-auto mb-4"
                    >
                      <Upload className={cn(
                        'w-8 h-8 transition-colors',
                        isDragActive ? 'text-watercolor-coral' : 'text-muted-foreground'
                      )} />
                    </motion.div>
                    <p className="text-lg font-medium mb-2">
                      {isDragActive ? 'Drop files here' : 'Drag & drop files here'}
                    </p>
                    <p className="text-sm text-muted-foreground mb-4">
                      or click to browse
                    </p>
                    <p className="text-xs text-muted-foreground">
                      Supported: PDF, Markdown, YAML, JSON, Python, JavaScript, Terraform (max 10MB)
                    </p>
                  </div>
                </div>

                {/* File List */}
                <AnimatePresence>
                  {files.length > 0 && (
                    <motion.div
                      initial={{ opacity: 0, height: 0 }}
                      animate={{ opacity: 1, height: 'auto' }}
                      exit={{ opacity: 0, height: 0 }}
                      className="mt-4 space-y-2"
                    >
                      {files.map((file, index) => {
                        const Icon = getFileIcon(file.name);
                        return (
                          <motion.div
                            key={`${file.name}-${index}`}
                            initial={{ opacity: 0, x: -20 }}
                            animate={{ opacity: 1, x: 0 }}
                            exit={{ opacity: 0, x: 20 }}
                            className="flex items-center gap-3 p-3 rounded-xl bg-muted/50"
                          >
                            <Icon className="w-5 h-5 text-muted-foreground" />
                            <div className="flex-1 min-w-0">
                              <p className="text-sm font-medium truncate">{file.name}</p>
                              <p className="text-xs text-muted-foreground">
                                {(file.size / 1024).toFixed(1)} KB
                              </p>
                            </div>
                            <button
                              onClick={() => removeFile(index)}
                              className="p-1 rounded-lg hover:bg-destructive/10 text-muted-foreground hover:text-destructive transition-colors"
                            >
                              <X className="w-4 h-4" />
                            </button>
                          </motion.div>
                        );
                      })}
                    </motion.div>
                  )}
                </AnimatePresence>

                {/* No files hint */}
                {files.length === 0 && (
                  <p className="text-xs text-muted-foreground mt-4 text-center">
                    No files? Switch to <button onClick={() => setInputMode('chat')} className="text-watercolor-coral hover:underline">Chat with AI</button> mode
                  </p>
                )}
              </motion.div>
            )}
          </AnimatePresence>

          {/* Error with detailed info */}
          <AnimatePresence>
            {error && (
              <motion.div
                initial={{ opacity: 0, y: -10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                className={cn(
                  "p-4 rounded-xl",
                  error.isLLMConfig 
                    ? "bg-amber-500/10 border border-amber-500/30"
                    : "bg-destructive/10 border border-destructive/30"
                )}
              >
                <div className="flex items-start gap-3">
                  {error.isLLMConfig ? (
                    <Settings className="w-5 h-5 text-amber-500 flex-shrink-0 mt-0.5" />
                  ) : (
                    <AlertCircle className="w-5 h-5 text-destructive flex-shrink-0 mt-0.5" />
                  )}
                  <div className="flex-1">
                    <p className={cn(
                      "font-medium",
                      error.isLLMConfig ? "text-amber-600 dark:text-amber-400" : "text-destructive"
                    )}>
                      {error.message}
                    </p>
                    {error.cause && (
                      <p className="text-sm text-muted-foreground mt-1">
                        <span className="font-medium">Cause:</span> {error.cause}
                      </p>
                    )}
                    {error.solution && (
                      <div className="mt-2 p-3 rounded-lg bg-muted/50">
                        <p className="text-sm font-medium mb-1 flex items-center gap-1">
                          <Zap className="w-3 h-3 text-watercolor-coral" />
                          Solution:
                        </p>
                        <p className="text-sm text-muted-foreground whitespace-pre-wrap">{error.solution}</p>
                      </div>
                    )}
                    {error.isLLMConfig && (
                      <div className="mt-3 flex items-center gap-3">
                        <button
                          onClick={() => {
                            setShowSettings(true);
                            setError(null);
                          }}
                          className="flex items-center gap-2 px-4 py-2 bg-amber-500 hover:bg-amber-600 text-white rounded-lg text-sm font-medium transition-colors"
                        >
                          <Settings className="w-4 h-4" />
                          Configure in Settings
                        </button>
                        <span className="text-xs text-muted-foreground">
                          Choose Ollama, OpenAI, Anthropic, or another provider
                        </span>
                      </div>
                    )}
                  </div>
                  <button 
                    onClick={() => setError(null)} 
                    className={cn(
                      "p-1 rounded-lg",
                      error.isLLMConfig ? "hover:bg-amber-500/20" : "hover:bg-destructive/20"
                    )}
                  >
                    <X className={cn(
                      "w-4 h-4",
                      error.isLLMConfig ? "text-amber-500" : "text-destructive"
                    )} />
                  </button>
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Submit */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.4 }}
            className="flex justify-end"
          >
            <motion.button
              onClick={handleSubmit}
              disabled={uploading || backendStatus !== 'connected'}
              whileHover={{ scale: backendStatus === 'connected' ? 1.02 : 1 }}
              whileTap={{ scale: backendStatus === 'connected' ? 0.98 : 1 }}
              className={cn(
                'flex items-center gap-3 px-8 py-4 rounded-xl font-semibold',
                inputMode === 'chat' 
                  ? 'bg-gradient-to-r from-watercolor-slate to-watercolor-blue text-white shadow-lg shadow-watercolor-slate/25'
                  : 'bg-gradient-to-r from-watercolor-coral to-watercolor-pink text-white shadow-lg shadow-watercolor-coral/25',
                'disabled:opacity-50 disabled:cursor-not-allowed disabled:shadow-none'
              )}
            >
              {uploading ? (
                <>
                  <Loader2 className="w-5 h-5 animate-spin" />
                  <span>Uploading... {uploadProgress}%</span>
                </>
              ) : inputMode === 'chat' ? (
                <>
                  <span>Start Chat</span>
                  <MessageSquare className="w-5 h-5" />
                </>
              ) : (
                <>
                  <span>{files.length > 0 ? 'Start Analysis' : 'Continue Without Files'}</span>
                  <ArrowRight className="w-5 h-5" />
                </>
              )}
            </motion.button>
          </motion.div>

          {/* Upload Progress */}
          <AnimatePresence>
            {uploading && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 backdrop-blur-sm"
              >
                <div className="p-8 rounded-2xl glass-solid text-center max-w-sm w-full mx-4">
                  <div className="w-20 h-20 rounded-full bg-watercolor-coral/10 flex items-center justify-center mx-auto mb-6">
                    <Loader2 className="w-10 h-10 text-watercolor-coral animate-spin" />
                  </div>
                  <h3 className="text-xl font-semibold mb-2">
                    {uploadProgress < 50 ? 'Uploading Files' : uploadProgress < 90 ? 'Running Analysis' : 'Finishing Up'}
                  </h3>
                  <p className="text-sm text-muted-foreground mb-6">
                    {uploadProgress < 50 
                      ? 'Uploading and ingesting your documents...' 
                      : uploadProgress < 90 
                        ? `Running ${methodologySettings.primary.toUpperCase()} threat analysis...`
                        : 'Generating threat model and DFD...'}
                  </p>
                  <div className="h-2 bg-muted rounded-full overflow-hidden">
                    <motion.div
                      className="h-full bg-gradient-to-r from-watercolor-coral to-watercolor-pink"
                      initial={{ width: 0 }}
                      animate={{ width: `${uploadProgress}%` }}
                      transition={{ duration: 0.3 }}
                    />
                  </div>
                  <p className="text-sm text-muted-foreground mt-2">{uploadProgress}%</p>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>

      {/* Settings Modal */}
      <SettingsModal isOpen={showSettings} onClose={() => setShowSettings(false)} />
    </div>
  );
}
