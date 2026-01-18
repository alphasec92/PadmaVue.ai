'use client';

import { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Shield, Send, Bot, User, Sparkles, CheckCircle2, XCircle,
  Loader2, BarChart3, RefreshCw, ArrowRight, FileText, AlertTriangle,
  ChevronDown, ChevronRight, Zap, History, Trash2, Globe, Search, ExternalLink,
  Settings, Brain
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { api } from '@/lib/api';
import { useWebSearch, useReasoning, ReasoningSummary } from '@/hooks/use-web-search';
import { SettingsModal } from '@/components/settings-modal';
import Link from 'next/link';

// Helper to detect LLM configuration errors
const isLLMConfigError = (error: string): boolean => {
  const patterns = [
    /llm.*not configured/i,
    /provider.*not configured/i,
    /no.*provider/i,
    /mock.*mode/i,
    /configure.*llm/i,
    /api.*key.*required/i,
    /api.*key.*missing/i,
    /api.*key.*invalid/i,
    /authentication.*failed/i,
    /ollama.*not.*running/i,
    /connection.*refused.*11434/i,
    /failed.*connect.*ollama/i,
  ];
  return patterns.some(p => p.test(error));
};

interface Message {
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
  analysis?: string;
  followUpQuestions?: string[];
  completenessScore?: number;
  readyForThreatModel?: boolean;
  webSearchUsed?: boolean;
  sources?: { title: string; url: string; snippet?: string; citation_id?: number }[];
  confidenceLevel?: string;
  reasoningSummary?: ReasoningSummary;
  reasoningLevel?: string;
}

interface Session {
  session_id: string;
  created_at: string;
  updated_at: string;
  completeness_score: number;
  ready_for_threat_model: boolean;
  turns: number;
}

interface WorldModel {
  system_type?: string;
  components?: string[];
  data_types?: string[];
  auth_method?: string;
  network_exposure?: string;
  compliance?: string[];
  ai_involved?: boolean;
}

export default function AIArchitectPage() {
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [worldModel, setWorldModel] = useState<WorldModel>({});
  const [completenessScore, setCompletenessScore] = useState(0);
  const [readyForThreatModel, setReadyForThreatModel] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [sessions, setSessions] = useState<Session[]>([]);
  const [showSessions, setShowSessions] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [projectName, setProjectName] = useState('');
  const [projectNameError, setProjectNameError] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  
  // Web Search (Grounded Responses)
  const webSearch = useWebSearch();
  
  // Reasoning / Thinking Time
  const reasoning = useReasoning();

  // Load sessions on mount
  useEffect(() => {
    loadSessions();
  }, []);

  // Scroll to bottom when messages change
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const loadSessions = async () => {
    try {
      const response = await api.request<{ sessions: Session[] }>('/api/architect-chat/sessions');
      setSessions(response.sessions || []);
    } catch (e) {
      console.error('Failed to load sessions:', e);
    }
  };

  const loadSession = async (sid: string) => {
    try {
      const session = await api.request<any>(`/api/architect-chat/session/${sid}`);
      setSessionId(sid);
      setWorldModel(session.world_model || {});
      setCompletenessScore(session.completeness_score || 0);
      setReadyForThreatModel(session.ready_for_threat_model || false);
      
      // Convert conversation history to messages
      const msgs: Message[] = [];
      const history = session.conversation_history || [];
      for (let i = 0; i < history.length; i += 2) {
        const userMsg = history[i];
        const assistantMsg = history[i + 1];
        
        if (userMsg) {
          msgs.push({
            role: 'user',
            content: userMsg.content,
            timestamp: new Date().toISOString()
          });
        }
        
        if (assistantMsg) {
          try {
            const parsed = JSON.parse(assistantMsg.content);
            msgs.push({
              role: 'assistant',
              content: parsed.analysis || assistantMsg.content,
              timestamp: new Date().toISOString(),
              followUpQuestions: parsed.follow_up_questions,
              completenessScore: parsed.completeness_score,
              readyForThreatModel: parsed.ready_for_threat_model
            });
          } catch {
            msgs.push({
              role: 'assistant',
              content: assistantMsg.content,
              timestamp: new Date().toISOString()
            });
          }
        }
      }
      setMessages(msgs);
      setShowSessions(false);
    } catch (e) {
      console.error('Failed to load session:', e);
    }
  };

  const deleteSession = async (sid: string) => {
    try {
      await api.request(`/api/architect-chat/session/${sid}`, { method: 'DELETE' });
      await loadSessions();
      if (sessionId === sid) {
        startNewSession();
      }
    } catch (e) {
      console.error('Failed to delete session:', e);
    }
  };

  const startNewSession = () => {
    setSessionId(null);
    setMessages([]);
    setWorldModel({});
    setCompletenessScore(0);
    setReadyForThreatModel(false);
    setResult(null);
    setError(null);
    setProjectName('');
    setProjectNameError(false);
  };

  const sendMessage = async () => {
    if (!input.trim() || loading) return;
    
    const userMessage = input.trim();
    setInput('');
    setError(null);
    
    // Add user message immediately
    setMessages(prev => [...prev, {
      role: 'user',
      content: userMessage,
      timestamp: new Date().toISOString()
    }]);
    
    setLoading(true);
    
    try {
      const response = await api.request<{
        session_id: string;
        response: string;
        analysis?: string;
        completeness_score: number;
        missing_info: string[];
        follow_up_questions: string[];
        ready_for_threat_model: boolean;
        world_model: WorldModel;
        web_search_used: boolean;
        sources: { title: string; url: string; snippet?: string; citation_id?: number }[];
        confidence_level: string;
        reasoning_summary?: ReasoningSummary;
        reasoning_level: string;
      }>('/api/architect-chat/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: userMessage,
          session_id: sessionId,
          web_search_enabled: webSearch.enabled,
          reasoning_level: reasoning.level
        })
      });
      
      setSessionId(response.session_id);
      setWorldModel(response.world_model);
      setCompletenessScore(response.completeness_score);
      setReadyForThreatModel(response.ready_for_threat_model);
      
      // Add assistant message with web search and reasoning data
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: response.analysis || response.response,
        timestamp: new Date().toISOString(),
        followUpQuestions: response.follow_up_questions,
        completenessScore: response.completeness_score,
        readyForThreatModel: response.ready_for_threat_model,
        webSearchUsed: response.web_search_used,
        sources: response.sources,
        confidenceLevel: response.confidence_level,
        reasoningSummary: response.reasoning_summary,
        reasoningLevel: response.reasoning_level
      }]);
      
      // Refresh sessions list
      await loadSessions();
      
    } catch (e: any) {
      const errorMsg = typeof e === 'string' ? e : (e.message || e.cause || e.toString() || 'Failed to get response from AI');
      setError(errorMsg);
      // Remove the user message on error
      setMessages(prev => prev.slice(0, -1));
    } finally {
      setLoading(false);
    }
  };

  const generateThreatModel = async () => {
    // Validate project name
    if (!projectName.trim()) {
      setProjectNameError(true);
      setError('Project Name is required before generating a threat model');
      return;
    }
    
    if (!sessionId || generating) return;
    
    setGenerating(true);
    setError(null);
    setProjectNameError(false);
    
    try {
      const response = await api.request<{
        success: boolean;
        analysis_id: string;
        project_id: string;
        threats_count: number;
        threats: any[];
        summary: any;
        dfd_mermaid: string;
        recommendations: string[];
      }>('/api/architect-chat/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: sessionId, project_name: projectName.trim() })
      });
      
      setResult(response);
      
    } catch (e: any) {
      const errorMsg = typeof e === 'string' ? e : (e.message || e.cause || e.toString() || 'Failed to generate threat model');
      setError(errorMsg);
    } finally {
      setGenerating(false);
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  return (
    <div className="min-h-screen bg-background">
      <div className="max-w-6xl mx-auto p-4">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <motion.div 
              whileHover={{ rotate: [0, -10, 10, -5, 5, 0] }}
              transition={{ duration: 0.5 }}
              className="p-2 bg-gradient-to-br from-watercolor-coral to-watercolor-pink rounded-xl shadow-lg shadow-watercolor-coral/20"
            >
              <Shield className="w-6 h-6 text-white" />
            </motion.div>
            <div>
              <h1 className="text-2xl font-bold bg-gradient-to-r from-watercolor-coral to-watercolor-blue bg-clip-text text-transparent">AI Security Consultant</h1>
              <p className="text-sm text-muted-foreground">
                Intelligent threat modeling through conversation
              </p>
            </div>
          </div>
          
          <div className="flex items-center gap-2">
            {/* Web Search Toggle */}
            <button
              onClick={() => webSearch.toggle()}
              className={cn(
                "flex items-center gap-2 px-3 py-2 rounded-lg transition-all border",
                webSearch.enabled 
                  ? "bg-emerald-500/10 border-emerald-500/50 text-emerald-600 dark:text-emerald-400" 
                  : "bg-muted border-transparent hover:bg-muted/80"
              )}
              title={webSearch.enabled ? "Web search enabled - click to disable" : "Enable web search for grounded responses"}
            >
              <Globe className={cn("w-4 h-4", webSearch.enabled && "animate-pulse")} />
              <span className="text-sm hidden sm:inline">
                {webSearch.enabled ? "Web-grounded" : "Local"}
              </span>
              {webSearch.enabled && !webSearch.isAvailable && (
                <span className="w-2 h-2 rounded-full bg-amber-500 animate-pulse" title="Web search not configured" />
              )}
            </button>
            
            <button
              onClick={() => setShowSessions(!showSessions)}
              className={cn(
                "flex items-center gap-2 px-3 py-2 rounded-lg transition-all",
                showSessions ? "bg-primary text-white" : "bg-muted hover:bg-muted/80"
              )}
            >
              <History className="w-4 h-4" />
              Sessions
            </button>
            <button
              onClick={startNewSession}
              className="flex items-center gap-2 px-3 py-2 bg-muted hover:bg-muted/80 rounded-lg transition-all"
            >
              <RefreshCw className="w-4 h-4" />
              New
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
          {/* Main Chat Area */}
          <div className="lg:col-span-3 space-y-4">
            {/* Sessions Panel */}
            <AnimatePresence>
              {showSessions && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  exit={{ opacity: 0, height: 0 }}
                  className="bg-muted/50 rounded-xl p-4"
                >
                  <h3 className="font-semibold mb-3">Previous Sessions</h3>
                  {sessions.length === 0 ? (
                    <p className="text-sm text-muted-foreground">No previous sessions</p>
                  ) : (
                    <div className="space-y-2 max-h-48 overflow-auto">
                      {sessions.map(session => (
                        <div
                          key={session.session_id}
                          className={cn(
                            "flex items-center justify-between p-3 rounded-lg transition-all cursor-pointer",
                            sessionId === session.session_id
                              ? "bg-primary/10 border border-primary"
                              : "bg-background hover:bg-muted"
                          )}
                          onClick={() => loadSession(session.session_id)}
                        >
                          <div>
                            <div className="text-sm font-medium">
                              {new Date(session.created_at).toLocaleDateString()}
                            </div>
                            <div className="text-xs text-muted-foreground">
                              {session.turns} messages • {Math.round(session.completeness_score * 100)}% complete
                            </div>
                          </div>
                          <div className="flex items-center gap-2">
                            {session.ready_for_threat_model && (
                              <CheckCircle2 className="w-4 h-4 text-green-500" />
                            )}
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                deleteSession(session.session_id);
                              }}
                              className="p-1 hover:bg-red-500/10 rounded"
                            >
                              <Trash2 className="w-4 h-4 text-red-500" />
                            </button>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </motion.div>
              )}
            </AnimatePresence>

            {/* Chat Messages */}
            <div className="bg-muted/30 rounded-xl border border-border min-h-[500px] max-h-[600px] overflow-auto p-4">
              {messages.length === 0 ? (
                <div className="h-full flex flex-col items-center justify-center text-center p-8">
                  <motion.div
                    animate={{ y: [0, -5, 0] }}
                    transition={{ duration: 2, repeat: Infinity }}
                  >
                    <Bot className="w-16 h-16 text-watercolor-coral/50 mb-4" />
                  </motion.div>
                  <h3 className="text-xl font-semibold mb-2 bg-gradient-to-r from-watercolor-coral to-watercolor-blue bg-clip-text text-transparent">Start a Conversation</h3>
                  <p className="text-muted-foreground max-w-md mb-6">
                    Describe your system architecture, and I'll help you identify security threats
                    and create a comprehensive threat model.
                  </p>
                  <div className="flex flex-wrap gap-2 justify-center">
                    {[
                      "I'm building a web app with React and Node.js",
                      "We have a microservices architecture on AWS",
                      "I need to review security for our payment system"
                    ].map((suggestion, i) => (
                      <motion.button
                        key={i}
                        whileHover={{ scale: 1.02, borderColor: 'hsl(5 64% 69% / 0.5)' }}
                        onClick={() => setInput(suggestion)}
                        className="px-3 py-2 bg-muted hover:bg-watercolor-coral/10 rounded-lg text-sm transition-all border border-transparent"
                      >
                        {suggestion}
                      </motion.button>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="space-y-4">
                  {messages.map((msg, idx) => (
                    <motion.div
                      key={idx}
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: 0 }}
                      className={cn(
                        "flex gap-3",
                        msg.role === 'user' ? "justify-end" : "justify-start"
                      )}
                    >
                      {msg.role === 'assistant' && (
                        <div className="w-8 h-8 rounded-full bg-watercolor-coral/10 flex items-center justify-center flex-shrink-0">
                          <Bot className="w-5 h-5 text-watercolor-coral" />
                        </div>
                      )}
                      
                      <div className={cn(
                        "max-w-[80%] rounded-xl p-4",
                        msg.role === 'user'
                          ? "bg-gradient-to-r from-watercolor-coral to-watercolor-pink text-white shadow-lg shadow-watercolor-coral/20"
                          : "bg-muted"
                      )}>
                        {/* Web-grounded badge */}
                        {msg.role === 'assistant' && msg.webSearchUsed && (
                          <div className="flex items-center gap-1.5 mb-2 text-xs text-emerald-600 dark:text-emerald-400">
                            <Globe className="w-3.5 h-3.5" />
                            <span>Web-grounded response</span>
                          </div>
                        )}
                        
                        <p className="whitespace-pre-wrap">{msg.content}</p>
                        
                        {/* Sources section */}
                        {msg.sources && msg.sources.length > 0 && (
                          <div className="mt-4 pt-3 border-t border-border/50">
                            <p className="text-sm font-medium mb-2 flex items-center gap-1.5">
                              <Search className="w-3.5 h-3.5" />
                              Sources
                            </p>
                            <ul className="space-y-2">
                              {msg.sources.map((source, i) => (
                                <li key={i} className="text-sm">
                                  <a 
                                    href={source.url} 
                                    target="_blank" 
                                    rel="noopener noreferrer"
                                    className="flex items-start gap-2 text-primary hover:underline"
                                  >
                                    <ExternalLink className="w-3.5 h-3.5 mt-0.5 flex-shrink-0" />
                                    <span>[{source.citation_id || i + 1}] {source.title}</span>
                                  </a>
                                </li>
                              ))}
                            </ul>
                          </div>
                        )}
                        
                        {/* Reasoning Summary (collapsible) */}
                        {msg.reasoningSummary && reasoning.showSummary && (
                          <details className="mt-4 pt-3 border-t border-border/50">
                            <summary className="text-sm font-medium cursor-pointer flex items-center gap-1.5 text-muted-foreground hover:text-foreground">
                              <Sparkles className="w-3.5 h-3.5" />
                              Reasoning Summary
                              <span className="text-xs ml-2 px-1.5 py-0.5 rounded bg-muted">
                                {msg.reasoningLevel || 'balanced'}
                              </span>
                            </summary>
                            <div className="mt-2 text-sm space-y-2 text-muted-foreground">
                              {msg.reasoningSummary.key_steps?.length > 0 && (
                                <div>
                                  <p className="font-medium text-foreground text-xs uppercase tracking-wide">Key Steps</p>
                                  <ul className="mt-1 space-y-1">
                                    {msg.reasoningSummary.key_steps.slice(0, 5).map((step, i) => (
                                      <li key={i} className="flex items-start gap-1.5">
                                        <span className="text-primary">•</span>
                                        <span>{step}</span>
                                      </li>
                                    ))}
                                  </ul>
                                </div>
                              )}
                              {msg.reasoningSummary.assumptions?.length > 0 && (
                                <div>
                                  <p className="font-medium text-foreground text-xs uppercase tracking-wide">Assumptions</p>
                                  <ul className="mt-1 space-y-1">
                                    {msg.reasoningSummary.assumptions.slice(0, 3).map((assumption, i) => (
                                      <li key={i} className="flex items-start gap-1.5">
                                        <span className="text-amber-500">•</span>
                                        <span>{assumption}</span>
                                      </li>
                                    ))}
                                  </ul>
                                </div>
                              )}
                              {msg.reasoningSummary.confidence && (
                                <p className="text-xs">
                                  <span className="font-medium">Confidence:</span>{' '}
                                  <span className={cn(
                                    msg.reasoningSummary.confidence === 'high' && 'text-emerald-500',
                                    msg.reasoningSummary.confidence === 'medium' && 'text-amber-500',
                                    msg.reasoningSummary.confidence === 'low' && 'text-red-500'
                                  )}>
                                    {msg.reasoningSummary.confidence}
                                  </span>
                                </p>
                              )}
                            </div>
                          </details>
                        )}
                        
                        {msg.followUpQuestions && msg.followUpQuestions.length > 0 && (
                          <div className="mt-4 pt-3 border-t border-border/50">
                            <p className="text-sm font-medium mb-2">Questions for you:</p>
                            <ul className="space-y-1">
                              {msg.followUpQuestions.map((q, i) => (
                                <li key={i} className="text-sm flex items-start gap-2">
                                  <span className="text-primary">•</span>
                                  {q}
                                </li>
                              ))}
                            </ul>
                          </div>
                        )}
                        
                        {msg.readyForThreatModel && (
                          <div className="mt-3 p-2 bg-green-500/10 rounded-lg flex items-center gap-2">
                            <CheckCircle2 className="w-4 h-4 text-green-500" />
                            <span className="text-sm text-green-600 dark:text-green-400">
                              Ready to generate threat model!
                            </span>
                          </div>
                        )}
                      </div>
                      
                      {msg.role === 'user' && (
                        <div className="w-8 h-8 rounded-full bg-muted flex items-center justify-center flex-shrink-0">
                          <User className="w-5 h-5" />
                        </div>
                      )}
                    </motion.div>
                  ))}
                  
                  {loading && (
                    <motion.div
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      className="flex gap-3"
                    >
                      <div className="w-8 h-8 rounded-full bg-watercolor-coral/10 flex items-center justify-center">
                        <Bot className="w-5 h-5 text-watercolor-coral" />
                      </div>
                      <div className="bg-muted rounded-xl p-4">
                        <div className="flex items-center gap-2">
                          <Loader2 className="w-4 h-4 animate-spin text-watercolor-coral" />
                          <span className="text-sm">Analyzing...</span>
                        </div>
                      </div>
                    </motion.div>
                  )}
                  
                  <div ref={messagesEndRef} />
                </div>
              )}
            </div>

            {/* Error Display */}
            <AnimatePresence>
              {error && (
                <motion.div
                  initial={{ opacity: 0, y: -10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -10 }}
                  className={cn(
                    "p-4 rounded-xl flex items-start gap-3",
                    isLLMConfigError(error) 
                      ? "bg-amber-500/10 border border-amber-500/30" 
                      : "bg-red-500/10 border border-red-500/30"
                  )}
                >
                  {isLLMConfigError(error) ? (
                    <Settings className="w-5 h-5 text-amber-500 flex-shrink-0 mt-0.5" />
                  ) : (
                    <XCircle className="w-5 h-5 text-red-500 flex-shrink-0 mt-0.5" />
                  )}
                  <div className="flex-1">
                    <p className={cn(
                      "font-medium",
                      isLLMConfigError(error) 
                        ? "text-amber-600 dark:text-amber-400" 
                        : "text-red-600 dark:text-red-400"
                    )}>
                      {isLLMConfigError(error) ? "LLM Provider Not Configured" : "Error"}
                    </p>
                    <p className="text-sm text-muted-foreground">{error}</p>
                    {isLLMConfigError(error) && (
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
                    className="text-muted-foreground hover:text-foreground flex-shrink-0"
                  >
                    ×
                  </button>
                </motion.div>
              )}
            </AnimatePresence>

            {/* Input Area */}
            <div className="bg-muted/30 rounded-xl border border-border p-3">
              <div className="flex gap-3">
                <textarea
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  onKeyPress={handleKeyPress}
                  placeholder="Describe your system architecture..."
                  className="flex-1 bg-background dark:bg-muted rounded-lg px-4 py-3 resize-none focus:outline-none focus:ring-2 focus:ring-primary/50"
                  rows={2}
                  disabled={loading}
                />
                <button
                  onClick={sendMessage}
                  disabled={!input.trim() || loading}
                  className={cn(
                    "px-4 rounded-lg transition-all flex items-center justify-center",
                    input.trim() && !loading
                      ? "bg-gradient-to-r from-watercolor-coral to-watercolor-pink text-white hover:shadow-lg hover:shadow-watercolor-coral/30"
                      : "bg-muted text-muted-foreground cursor-not-allowed"
                  )}
                >
                  {loading ? (
                    <Loader2 className="w-5 h-5 animate-spin" />
                  ) : (
                    <Send className="w-5 h-5" />
                  )}
                </button>
              </div>
            </div>

            {/* Generate Button */}
            {readyForThreatModel && !result && (
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                className={cn(
                  "p-4 rounded-xl border",
                  !projectName.trim() 
                    ? "bg-amber-500/10 border-amber-500/30" 
                    : "bg-green-500/10 border-green-500/30"
                )}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    {!projectName.trim() ? (
                      <AlertTriangle className="w-6 h-6 text-amber-500" />
                    ) : (
                      <CheckCircle2 className="w-6 h-6 text-green-500" />
                    )}
                    <div>
                      <p className={cn(
                        "font-semibold",
                        !projectName.trim() 
                          ? "text-amber-600 dark:text-amber-400" 
                          : "text-green-600 dark:text-green-400"
                      )}>
                        {!projectName.trim() 
                          ? "Enter Project Name to Continue" 
                          : "Ready to Generate Threat Model"}
                      </p>
                      <p className="text-sm text-muted-foreground">
                        {!projectName.trim() 
                          ? "Project name is required" 
                          : `Completeness: ${Math.round(completenessScore * 100)}%`}
                      </p>
                    </div>
                  </div>
                  <button
                    onClick={generateThreatModel}
                    disabled={generating || !projectName.trim()}
                    className={cn(
                      "flex items-center gap-2 px-5 py-2.5 text-white rounded-lg transition-all",
                      !projectName.trim() 
                        ? "bg-amber-600/50 cursor-not-allowed" 
                        : "bg-green-600 hover:bg-green-700"
                    )}
                  >
                    {generating ? (
                      <>
                        <Loader2 className="w-5 h-5 animate-spin" />
                        Generating...
                      </>
                    ) : (
                      <>
                        <Zap className="w-5 h-5" />
                        Generate Threat Model
                      </>
                    )}
                  </button>
                </div>
              </motion.div>
            )}

            {/* Result Display */}
            <AnimatePresence>
              {result && (
                <motion.div
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="p-6 bg-gradient-to-br from-green-500/10 to-blue-500/10 border border-green-500/30 rounded-xl"
                >
                  <div className="flex items-start gap-4">
                    <div className="p-3 bg-green-500/20 rounded-xl">
                      <CheckCircle2 className="w-8 h-8 text-green-500" />
                    </div>
                    <div className="flex-1">
                      <h3 className="text-xl font-bold text-green-600 dark:text-green-400 mb-2">
                        🎉 Threat Model Generated!
                      </h3>
                      
                      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 my-4">
                        <div className="p-3 bg-background/50 rounded-lg text-center">
                          <div className="text-2xl font-bold">{result.threats_count}</div>
                          <div className="text-xs text-muted-foreground">Threats</div>
                        </div>
                        <div className="p-3 bg-red-500/10 rounded-lg text-center">
                          <div className="text-2xl font-bold text-red-500">{result.summary?.critical || 0}</div>
                          <div className="text-xs text-muted-foreground">Critical</div>
                        </div>
                        <div className="p-3 bg-orange-500/10 rounded-lg text-center">
                          <div className="text-2xl font-bold text-orange-500">{result.summary?.high || 0}</div>
                          <div className="text-xs text-muted-foreground">High</div>
                        </div>
                        <div className="p-3 bg-yellow-500/10 rounded-lg text-center">
                          <div className="text-2xl font-bold text-yellow-500">{result.summary?.medium || 0}</div>
                          <div className="text-xs text-muted-foreground">Medium</div>
                        </div>
                      </div>
                      
                      <div className="flex gap-3 mt-4">
                        <Link
                          href={`/review?analysis_id=${result.analysis_id}`}
                          className="flex-1 flex items-center justify-center gap-2 px-4 py-3 bg-gradient-to-r from-watercolor-coral to-watercolor-pink text-white rounded-xl font-medium shadow-lg shadow-watercolor-coral/20 hover:shadow-watercolor-coral/30 transition-shadow"
                        >
                          <FileText className="w-5 h-5" />
                          View Full Analysis
                          <ArrowRight className="w-4 h-4" />
                        </Link>
                        <Link
                          href={`/dfd?analysis_id=${result.analysis_id}`}
                          className="px-4 py-3 bg-watercolor-blue/20 text-watercolor-blue rounded-xl font-medium hover:bg-watercolor-blue/30 transition-colors"
                        >
                          View DFD
                        </Link>
                      </div>
                    </div>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          {/* Right Sidebar - World Model */}
          <div className="space-y-4">
            {/* Project Information - Required */}
            <div className={cn(
              "bg-muted/30 rounded-xl border p-4 transition-colors",
              projectNameError ? "border-red-500 bg-red-500/5" : "border-border"
            )}>
              <h3 className="font-semibold mb-3 flex items-center gap-2">
                <FileText className="w-4 h-4" />
                Project Information
              </h3>
              <div className="space-y-3">
                <div>
                  <label className="block text-sm font-medium mb-2">
                    Project Name <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="text"
                    value={projectName}
                    onChange={(e) => {
                      setProjectName(e.target.value);
                      if (e.target.value.trim()) setProjectNameError(false);
                    }}
                    placeholder="e.g., E-Commerce Platform"
                    className={cn(
                      "w-full px-3 py-2 rounded-lg bg-background border outline-none transition-all text-sm",
                      projectNameError 
                        ? "border-red-500 focus:border-red-500 focus:ring-2 focus:ring-red-500/20" 
                        : "border-border focus:border-primary focus:ring-2 focus:ring-primary/20"
                    )}
                  />
                  {projectNameError && (
                    <p className="mt-1 text-xs text-red-500 flex items-center gap-1">
                      <AlertTriangle className="w-3 h-3" />
                      Required before generating threat model
                    </p>
                  )}
                </div>
              </div>
            </div>
            
            {/* Completeness */}
            <div className="bg-muted/30 rounded-xl border border-border p-4">
              <h3 className="font-semibold mb-3 flex items-center gap-2">
                <BarChart3 className="w-4 h-4" />
                Analysis Progress
              </h3>
              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span>Completeness</span>
                  <span className={cn(
                    completenessScore >= 0.7 ? "text-green-500" :
                    completenessScore >= 0.4 ? "text-yellow-500" : "text-red-500"
                  )}>
                    {Math.round(completenessScore * 100)}%
                  </span>
                </div>
                <div className="h-2 bg-muted rounded-full overflow-hidden">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${completenessScore * 100}%` }}
                    className={cn(
                      "h-full rounded-full transition-all",
                      completenessScore >= 0.7 ? "bg-green-500" :
                      completenessScore >= 0.4 ? "bg-yellow-500" : "bg-red-500"
                    )}
                  />
                </div>
                <p className="text-xs text-muted-foreground">
                  {completenessScore < 0.4 ? "Need more information" :
                   completenessScore < 0.7 ? "Almost there, a few more details needed" :
                   "Ready to generate threat model!"}
                </p>
              </div>
            </div>

            {/* World Model */}
            <div className="bg-muted/30 rounded-xl border border-border p-4">
              <h3 className="font-semibold mb-3 flex items-center gap-2">
                <Sparkles className="w-4 h-4" />
                Identified Context
              </h3>
              
              <div className="space-y-3 text-sm">
                {worldModel.system_type && (
                  <div>
                    <span className="text-muted-foreground">System Type:</span>
                    <p className="font-medium">{worldModel.system_type}</p>
                  </div>
                )}
                
                {worldModel.components && worldModel.components.length > 0 && (
                  <div>
                    <span className="text-muted-foreground">Components:</span>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {worldModel.components.map((c, i) => (
                        <span key={i} className="px-2 py-0.5 bg-primary/10 rounded text-xs">
                          {c}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
                
                {worldModel.data_types && worldModel.data_types.length > 0 && (
                  <div>
                    <span className="text-muted-foreground">Data Types:</span>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {worldModel.data_types.map((d, i) => (
                        <span key={i} className="px-2 py-0.5 bg-orange-500/10 text-orange-600 rounded text-xs">
                          {d}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
                
                {worldModel.auth_method && (
                  <div>
                    <span className="text-muted-foreground">Auth Method:</span>
                    <p className="font-medium">{worldModel.auth_method}</p>
                  </div>
                )}
                
                {worldModel.network_exposure && (
                  <div>
                    <span className="text-muted-foreground">Network Exposure:</span>
                    <p className="font-medium">{worldModel.network_exposure}</p>
                  </div>
                )}
                
                {worldModel.compliance && worldModel.compliance.length > 0 && (
                  <div>
                    <span className="text-muted-foreground">Compliance:</span>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {worldModel.compliance.map((c, i) => (
                        <span key={i} className="px-2 py-0.5 bg-blue-500/10 text-blue-600 rounded text-xs">
                          {c}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
                
                {worldModel.ai_involved && (
                  <div className="flex items-center gap-2 p-2 bg-purple-500/10 rounded-lg">
                    <Sparkles className="w-4 h-4 text-purple-500" />
                    <span className="text-purple-600 text-xs">AI/ML Components Detected</span>
                  </div>
                )}
                
                {Object.keys(worldModel).length === 0 && (
                  <p className="text-muted-foreground text-center py-4">
                    Start chatting to build context
                  </p>
                )}
              </div>
            </div>

            {/* Tips */}
            <div className="bg-watercolor-coral/5 border border-watercolor-coral/20 rounded-xl p-4">
              <h3 className="font-semibold mb-2 flex items-center gap-2 text-watercolor-coral">
                <AlertTriangle className="w-4 h-4" />
                Tips
              </h3>
              <ul className="text-xs text-muted-foreground space-y-1">
                <li>• Be specific about technologies used</li>
                <li>• Mention data types you handle (PII, payments)</li>
                <li>• Describe authentication mechanisms</li>
                <li>• List third-party integrations</li>
                <li>• Mention compliance requirements</li>
              </ul>
            </div>
          </div>
        </div>
      </div>

      {/* Settings Modal */}
      <SettingsModal isOpen={showSettings} onClose={() => setShowSettings(false)} />
    </div>
  );
}

