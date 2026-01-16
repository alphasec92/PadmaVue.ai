'use client';

import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Shield, Sparkles, CheckCircle2, ChevronRight, ChevronDown,
  Server, Database, Lock, Globe, Key, FileText, AlertTriangle,
  Cloud, Users, RefreshCw, Zap, ArrowRight, Info, Loader2,
  Building, Network, Eye, ShieldCheck, HelpCircle, Brain, Bot, Cpu, Edit3, XCircle
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { api } from '@/lib/api';

// ===========================================
// Question Configuration
// ===========================================

interface QuestionOption {
  value: string;
  label: string;
  description?: string;
  icon?: any;
  isOther?: boolean;
}

interface Question {
  id: string;
  category: string;
  question: string;
  description: string;
  examples?: string[];
  type: 'select' | 'multiselect' | 'text' | 'textarea';
  options?: QuestionOption[];
  placeholder?: string;
  required?: boolean;
  showIf?: (answers: Record<string, any>) => boolean;
  allowOther?: boolean;
}

const QUESTIONS: Question[] = [
  // Architecture Overview
  {
    id: 'architecture_type',
    category: 'Architecture Overview',
    question: 'What type of system are you building?',
    description: 'Select ALL that apply (e.g., a web app with API and microservices)',
    type: 'multiselect',
    required: true,
    allowOther: true,
    options: [
      { value: 'web_app', label: 'Web Application', description: 'Frontend + Backend + Database', icon: Globe },
      { value: 'api', label: 'API / Backend Service', description: 'REST or GraphQL API', icon: Server },
      { value: 'integration', label: 'System Integration', description: 'Connecting two or more systems', icon: Network },
      { value: 'microservices', label: 'Microservices', description: 'Multiple interconnected services', icon: Cloud },
      { value: 'mobile_backend', label: 'Mobile App Backend', description: 'Backend for iOS/Android app', icon: Server },
      { value: 'data_pipeline', label: 'Data Pipeline', description: 'ETL, data processing', icon: Database },
      { value: 'serverless', label: 'Serverless / Functions', description: 'Lambda, Cloud Functions', icon: Cloud },
      { value: 'batch_job', label: 'Batch Job / Scheduled Task', description: 'Cron jobs, background processing', icon: Server },
      { value: 'event_driven', label: 'Event-Driven System', description: 'Message queues, pub/sub', icon: Network },
      { value: 'other', label: 'Other (specify below)', description: 'Custom system type', icon: Edit3, isOther: true },
    ],
  },
  {
    id: 'system_description',
    category: 'Architecture Overview',
    question: 'Briefly describe your system',
    description: 'What does it do? What problem does it solve?',
    examples: ['E-commerce platform for selling products', 'Salesforce to ServiceNow ticket sync', 'Customer portal with user authentication'],
    type: 'textarea',
    placeholder: 'e.g., A Next.js web app that allows users to manage their subscriptions...',
    required: true,
  },
  {
    id: 'components',
    category: 'Architecture Overview',
    question: 'What are the main components/systems?',
    description: 'List all systems, services, or platforms involved',
    examples: ['React frontend', 'Node.js API', 'PostgreSQL', 'Redis cache', 'Salesforce', 'AWS S3'],
    type: 'textarea',
    placeholder: 'e.g., Next.js frontend, FastAPI backend, PostgreSQL database, Redis cache, Stripe payments',
  },

  // AI/ML Section
  {
    id: 'uses_ai',
    category: 'AI & Machine Learning',
    question: 'Does this system involve AI or Machine Learning?',
    description: 'Is this change related to AI in any way?',
    type: 'select',
    required: true,
    options: [
      { value: 'yes_new', label: 'Yes - Introducing new AI solution', description: 'Building or adding AI capabilities', icon: Brain },
      { value: 'yes_backend', label: 'Yes - Using AI in backend', description: 'AI/ML for processing or decisions', icon: Cpu },
      { value: 'yes_llm', label: 'Yes - Using LLM/GenAI', description: 'ChatGPT, Claude, custom LLM', icon: Bot },
      { value: 'yes_training', label: 'Yes - Training/deploying models', description: 'ML model development', icon: Brain },
      { value: 'no', label: 'No - Not AI related', description: 'Traditional software', icon: Server },
    ],
  },
  {
    id: 'ai_type',
    category: 'AI & Machine Learning',
    question: 'What type of AI/ML is involved?',
    description: 'Select all that apply',
    type: 'multiselect',
    allowOther: true,
    showIf: (answers) => answers.uses_ai && answers.uses_ai !== 'no',
    options: [
      { value: 'llm', label: 'Large Language Model (LLM)', description: 'GPT, Claude, Llama, etc.', icon: Bot },
      { value: 'classification', label: 'Classification/Prediction', description: 'ML models for categorization', icon: Brain },
      { value: 'recommendation', label: 'Recommendation System', description: 'Personalized suggestions', icon: Users },
      { value: 'computer_vision', label: 'Computer Vision', description: 'Image/video analysis', icon: Eye },
      { value: 'nlp', label: 'NLP (non-LLM)', description: 'Text analysis, sentiment', icon: FileText },
      { value: 'anomaly', label: 'Anomaly Detection', description: 'Fraud, outlier detection', icon: AlertTriangle },
      { value: 'embedding', label: 'Embeddings/Vector Search', description: 'Semantic search, RAG', icon: Database },
      { value: 'other', label: 'Other (specify below)', icon: Edit3, isOther: true },
    ],
  },
  {
    id: 'ai_provider',
    category: 'AI & Machine Learning',
    question: 'What AI/ML provider or platform do you use?',
    description: 'Select all that apply',
    type: 'multiselect',
    allowOther: true,
    showIf: (answers) => answers.uses_ai && answers.uses_ai !== 'no',
    options: [
      { value: 'openai', label: 'OpenAI (GPT)', description: 'ChatGPT, GPT-4', icon: Bot },
      { value: 'anthropic', label: 'Anthropic (Claude)', icon: Bot },
      { value: 'google', label: 'Google (Gemini, Vertex AI)', icon: Cloud },
      { value: 'aws', label: 'AWS (Bedrock, SageMaker)', icon: Cloud },
      { value: 'azure', label: 'Azure OpenAI / ML', icon: Cloud },
      { value: 'huggingface', label: 'Hugging Face', icon: Brain },
      { value: 'self_hosted', label: 'Self-hosted models', description: 'Ollama, vLLM, etc.', icon: Server },
      { value: 'custom', label: 'Custom trained models', icon: Cpu },
      { value: 'other', label: 'Other (specify below)', icon: Edit3, isOther: true },
    ],
  },
  {
    id: 'ai_data_handling',
    category: 'AI & Machine Learning',
    question: 'What data is sent to AI systems?',
    description: 'What information does the AI process?',
    type: 'multiselect',
    allowOther: true,
    showIf: (answers) => answers.uses_ai && answers.uses_ai !== 'no',
    options: [
      { value: 'user_prompts', label: 'User prompts/queries', description: 'Direct user input', icon: Users },
      { value: 'user_data', label: 'User data (PII)', description: 'Names, emails, etc.', icon: AlertTriangle },
      { value: 'business_docs', label: 'Business documents', description: 'Internal docs, reports', icon: FileText },
      { value: 'code', label: 'Source code', description: 'Code analysis/generation', icon: Cpu },
      { value: 'customer_data', label: 'Customer data', description: 'CRM, transactions', icon: Building },
      { value: 'public_only', label: 'Public data only', description: 'No sensitive data', icon: Globe },
      { value: 'other', label: 'Other (specify below)', icon: Edit3, isOther: true },
    ],
  },
  {
    id: 'ai_security_concerns',
    category: 'AI & Machine Learning',
    question: 'AI-specific security concerns?',
    description: 'What AI risks are you worried about?',
    type: 'multiselect',
    allowOther: true,
    showIf: (answers) => answers.uses_ai && answers.uses_ai !== 'no',
    options: [
      { value: 'prompt_injection', label: 'Prompt Injection', description: 'Malicious prompts', icon: AlertTriangle },
      { value: 'data_leakage', label: 'Data Leakage to AI', description: 'Sensitive data in prompts', icon: Eye },
      { value: 'model_theft', label: 'Model Theft/Extraction', description: 'Protecting proprietary models', icon: Lock },
      { value: 'bias', label: 'Bias & Fairness', description: 'Discriminatory outputs', icon: Users },
      { value: 'hallucination', label: 'Hallucinations', description: 'False/made-up info', icon: Brain },
      { value: 'cost_abuse', label: 'Cost/Token Abuse', description: 'API cost attacks', icon: Building },
      { value: 'compliance', label: 'AI Compliance', description: 'EU AI Act, regulations', icon: FileText },
      { value: 'other', label: 'Other (specify below)', icon: Edit3, isOther: true },
    ],
  },

  // Data Flows
  {
    id: 'data_types',
    category: 'Data & Flows',
    question: 'What types of data does your system handle?',
    description: 'Select all that apply',
    type: 'multiselect',
    allowOther: true,
    options: [
      { value: 'user_credentials', label: 'User Credentials', description: 'Passwords, tokens', icon: Key },
      { value: 'pii', label: 'Personal Information (PII)', description: 'Names, emails, addresses', icon: Users },
      { value: 'financial', label: 'Financial Data', description: 'Payment info, transactions', icon: Building },
      { value: 'health', label: 'Health Data (PHI)', description: 'Medical records', icon: ShieldCheck },
      { value: 'business', label: 'Business Data', description: 'Internal documents, reports', icon: FileText },
      { value: 'public', label: 'Public Data Only', description: 'No sensitive data', icon: Globe },
      { value: 'other', label: 'Other (specify below)', icon: Edit3, isOther: true },
    ],
  },
  {
    id: 'data_flow_description',
    category: 'Data & Flows',
    question: 'How does data flow through your system?',
    description: 'Describe the main data flows between components',
    examples: ['User submits form → API validates → saves to DB', 'Salesforce webhook → Lambda → ServiceNow API'],
    type: 'textarea',
    placeholder: 'e.g., Users upload files via web UI → API processes and stores in S3 → metadata saved to PostgreSQL',
  },

  // Authentication
  {
    id: 'auth_method',
    category: 'Authentication & Authorization',
    question: 'How do users and systems authenticate?',
    description: 'Select ALL methods used (users may use SSO while services use API keys)',
    type: 'multiselect',
    allowOther: true,
    options: [
      { value: 'sso', label: 'Single Sign-On (SSO)', description: 'Corporate/enterprise login', icon: Building },
      { value: 'oauth', label: 'OAuth 2.0 / OpenID Connect', description: 'Social login, delegated auth', icon: Lock },
      { value: 'jwt', label: 'JWT Tokens', description: 'Stateless auth tokens', icon: Key },
      { value: 'api_key', label: 'API Keys', description: 'Static keys for services', icon: Key },
      { value: 'saml', label: 'SAML', description: 'Enterprise federation', icon: Building },
      { value: 'basic', label: 'Username/Password', description: 'Traditional login', icon: Users },
      { value: 'service_account', label: 'Service Accounts', description: 'System-to-system auth', icon: Server },
      { value: 'mfa', label: 'Multi-Factor Auth (MFA)', description: '2FA, OTP, biometric', icon: ShieldCheck },
      { value: 'mtls', label: 'Mutual TLS (mTLS)', description: 'Certificate-based auth', icon: Lock },
      { value: 'iam_roles', label: 'Cloud IAM Roles', description: 'AWS/GCP/Azure roles', icon: Cloud },
      { value: 'none', label: 'No Authentication', description: 'Public access', icon: Globe },
      { value: 'other', label: 'Other (specify below)', icon: Edit3, isOther: true },
    ],
  },
  {
    id: 'auth_provider',
    category: 'Authentication & Authorization',
    question: 'What authentication providers do you use?',
    description: 'Select ALL providers (you may use multiple)',
    type: 'multiselect',
    allowOther: true,
    showIf: (answers) => {
      const methods = answers.auth_method || [];
      return Array.isArray(methods) ? !methods.includes('none') || methods.length > 1 : methods !== 'none';
    },
    options: [
      { value: 'auth0', label: 'Auth0', icon: Lock },
      { value: 'cognito', label: 'AWS Cognito', icon: Cloud },
      { value: 'firebase', label: 'Firebase Auth', icon: Cloud },
      { value: 'okta', label: 'Okta', icon: Building },
      { value: 'azure_ad', label: 'Azure AD / Entra ID', icon: Cloud },
      { value: 'google', label: 'Google Identity', icon: Cloud },
      { value: 'ping', label: 'Ping Identity', icon: Building },
      { value: 'keycloak', label: 'Keycloak', description: 'Self-hosted', icon: Server },
      { value: 'custom', label: 'Custom / Self-hosted', icon: Server },
      { value: 'builtin', label: 'Built-in / No Provider', icon: Server },
      { value: 'other', label: 'Other (specify below)', icon: Edit3, isOther: true },
    ],
  },
  {
    id: 'authorization',
    category: 'Authentication & Authorization',
    question: 'How is authorization handled?',
    description: 'Select ALL authorization methods used',
    type: 'multiselect',
    allowOther: true,
    showIf: (answers) => {
      const methods = answers.auth_method || [];
      return Array.isArray(methods) ? !methods.includes('none') || methods.length > 1 : methods !== 'none';
    },
    options: [
      { value: 'rbac', label: 'Role-Based (RBAC)', description: 'Admin, User, Viewer roles', icon: Users },
      { value: 'abac', label: 'Attribute-Based (ABAC)', description: 'Fine-grained policies', icon: ShieldCheck },
      { value: 'acl', label: 'Access Control Lists', description: 'Per-resource permissions', icon: FileText },
      { value: 'pbac', label: 'Policy-Based (PBAC)', description: 'OPA, Cedar policies', icon: Shield },
      { value: 'scopes', label: 'OAuth Scopes', description: 'API permission scopes', icon: Key },
      { value: 'groups', label: 'Group-Based', description: 'AD/LDAP groups', icon: Users },
      { value: 'simple', label: 'Simple (All or Nothing)', description: 'Authenticated = full access', icon: Lock },
      { value: 'other', label: 'Other (specify below)', icon: Edit3, isOther: true },
    ],
  },

  // Security Controls
  {
    id: 'network_security',
    category: 'Security Controls',
    question: 'What network security is in place?',
    description: 'Select all that apply',
    type: 'multiselect',
    allowOther: true,
    options: [
      { value: 'https', label: 'HTTPS/TLS', description: 'Encrypted connections', icon: Lock },
      { value: 'waf', label: 'Web Application Firewall', description: 'CloudFlare, AWS WAF', icon: Shield },
      { value: 'vpc', label: 'VPC / Private Network', description: 'Network isolation', icon: Network },
      { value: 'vpn', label: 'VPN Access', description: 'Secure remote access', icon: Lock },
      { value: 'firewall', label: 'Firewall Rules', description: 'IP restrictions', icon: Shield },
      { value: 'ddos', label: 'DDoS Protection', description: 'Attack mitigation', icon: ShieldCheck },
      { value: 'zero_trust', label: 'Zero Trust Network', description: 'Never trust, always verify', icon: Eye },
      { value: 'other', label: 'Other (specify below)', icon: Edit3, isOther: true },
    ],
  },
  {
    id: 'secrets_management',
    category: 'Security Controls',
    question: 'How are secrets and credentials stored?',
    description: 'Select ALL methods used (you may use different tools for different environments)',
    type: 'multiselect',
    allowOther: true,
    options: [
      { value: 'vault', label: 'HashiCorp Vault', icon: Lock },
      { value: 'aws_secrets', label: 'AWS Secrets Manager', icon: Cloud },
      { value: 'aws_ssm', label: 'AWS Parameter Store', icon: Cloud },
      { value: 'azure_keyvault', label: 'Azure Key Vault', icon: Cloud },
      { value: 'gcp_secrets', label: 'Google Secret Manager', icon: Cloud },
      { value: 'env_vars', label: 'Environment Variables', icon: Server },
      { value: 'doppler', label: 'Doppler', icon: Lock },
      { value: 'cyberark', label: 'CyberArk', icon: Lock },
      { value: 'k8s_secrets', label: 'Kubernetes Secrets', icon: Cloud },
      { value: 'config_files', label: 'Config Files', description: '⚠️ Not recommended', icon: AlertTriangle },
      { value: 'other', label: 'Other (specify below)', icon: Edit3, isOther: true },
    ],
  },

  // Compliance
  {
    id: 'compliance',
    category: 'Compliance & Regulations',
    question: 'Which compliance frameworks apply?',
    description: 'Select all that apply to your organization',
    type: 'multiselect',
    allowOther: true,
    options: [
      { value: 'gdpr', label: 'GDPR', description: 'EU data protection', icon: Globe },
      { value: 'hipaa', label: 'HIPAA', description: 'US healthcare', icon: ShieldCheck },
      { value: 'pci_dss', label: 'PCI-DSS', description: 'Payment card data', icon: Building },
      { value: 'soc2', label: 'SOC 2', description: 'Service organization controls', icon: Shield },
      { value: 'iso27001', label: 'ISO 27001', description: 'Information security', icon: Shield },
      { value: 'ccpa', label: 'CCPA', description: 'California privacy', icon: Globe },
      { value: 'fedramp', label: 'FedRAMP', description: 'US federal', icon: Building },
      { value: 'eu_ai_act', label: 'EU AI Act', description: 'AI regulations', icon: Brain },
      { value: 'none', label: 'None / Unknown', icon: HelpCircle },
      { value: 'other', label: 'Other (specify below)', icon: Edit3, isOther: true },
    ],
  },

  // Additional Context
  {
    id: 'threat_concerns',
    category: 'Additional Context',
    question: 'Any specific security concerns?',
    description: 'What threats are you most worried about?',
    examples: ['Data breaches', 'Insider threats', 'API abuse', 'Account takeover'],
    type: 'textarea',
    placeholder: 'e.g., Worried about API rate limiting, need to prevent data scraping...',
  },
  {
    id: 'additional_info',
    category: 'Additional Context',
    question: 'Anything else we should know?',
    description: 'Any other relevant context for the threat model',
    type: 'textarea',
    placeholder: 'e.g., We have a pen test scheduled next month, specific regulatory requirements...',
  },
];

const CATEGORIES = [
  { id: 'Architecture Overview', icon: Server, color: 'from-blue-500 to-cyan-500' },
  { id: 'AI & Machine Learning', icon: Brain, color: 'from-violet-500 to-purple-600' },
  { id: 'Data & Flows', icon: Database, color: 'from-purple-500 to-pink-500' },
  { id: 'Authentication & Authorization', icon: Lock, color: 'from-green-500 to-emerald-500' },
  { id: 'Security Controls', icon: Shield, color: 'from-orange-500 to-amber-500' },
  { id: 'Compliance & Regulations', icon: FileText, color: 'from-red-500 to-rose-500' },
  { id: 'Additional Context', icon: Info, color: 'from-gray-500 to-slate-500' },
];

// ===========================================
// Components
// ===========================================

function QuestionCard({ question, value, onChange, answers, customValues, onCustomChange }: {
  question: Question;
  value: any;
  onChange: (value: any) => void;
  answers: Record<string, any>;
  customValues: Record<string, string>;
  onCustomChange: (id: string, value: string) => void;
}) {
  // Check if question should be shown
  if (question.showIf && !question.showIf(answers)) {
    return null;
  }

  const hasOtherSelected = question.type === 'select' 
    ? value === 'other'
    : Array.isArray(value) && value.includes('other');

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="bg-background rounded-xl border border-border p-5 hover:border-primary/30 transition-colors"
    >
      <div className="flex items-start gap-3 mb-4">
        <div className="flex-1">
          <h3 className="font-semibold text-foreground flex items-center gap-2">
            {question.question}
            {question.required && <span className="text-red-500 text-sm">*</span>}
          </h3>
          <p className="text-sm text-muted-foreground mt-1">{question.description}</p>
          {question.examples && (
            <p className="text-xs text-muted-foreground mt-2 italic">
              Examples: {question.examples.join(', ')}
            </p>
          )}
        </div>
      </div>

      {/* Select Input */}
      {question.type === 'select' && question.options && (
        <div className="space-y-3">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {question.options.map((option) => {
              const Icon = option.icon || CheckCircle2;
              const isSelected = value === option.value;
              return (
                <button
                  key={option.value}
                  onClick={() => onChange(option.value)}
                  className={cn(
                    'flex items-start gap-3 p-3 rounded-lg border-2 text-left transition-all',
                    isSelected
                      ? 'border-primary bg-primary/5'
                      : 'border-border hover:border-primary/50',
                    option.isOther && 'col-span-full'
                  )}
                >
                  <Icon className={cn('w-5 h-5 mt-0.5', isSelected ? 'text-primary' : 'text-muted-foreground')} />
                  <div className="flex-1 min-w-0">
                    <p className={cn('font-medium text-sm', isSelected && 'text-primary')}>{option.label}</p>
                    {option.description && (
                      <p className="text-xs text-muted-foreground truncate">{option.description}</p>
                    )}
                  </div>
                  {isSelected && <CheckCircle2 className="w-4 h-4 text-primary" />}
                </button>
              );
            })}
          </div>
          
          {/* Custom input for "Other" */}
          {hasOtherSelected && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              className="mt-3"
            >
              <input
                type="text"
                value={customValues[question.id] || ''}
                onChange={(e) => onCustomChange(question.id, e.target.value)}
                placeholder="Please specify..."
                className="w-full px-4 py-3 rounded-lg bg-primary/5 border-2 border-primary/30 focus:border-primary focus:ring-2 focus:ring-primary/20 outline-none text-sm"
                autoFocus
              />
            </motion.div>
          )}
        </div>
      )}

      {/* Multi-select Input */}
      {question.type === 'multiselect' && question.options && (
        <div className="space-y-3">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {question.options.map((option) => {
              const Icon = option.icon || CheckCircle2;
              const selected = Array.isArray(value) ? value : [];
              const isSelected = selected.includes(option.value);
              return (
                <button
                  key={option.value}
                  onClick={() => {
                    if (isSelected) {
                      onChange(selected.filter((v: string) => v !== option.value));
                    } else {
                      onChange([...selected, option.value]);
                    }
                  }}
                  className={cn(
                    'flex items-start gap-3 p-3 rounded-lg border-2 text-left transition-all',
                    isSelected
                      ? 'border-primary bg-primary/5'
                      : 'border-border hover:border-primary/50',
                    option.isOther && 'col-span-full'
                  )}
                >
                  <div className={cn(
                    'w-5 h-5 rounded border-2 flex items-center justify-center mt-0.5 flex-shrink-0',
                    isSelected ? 'border-primary bg-primary' : 'border-muted-foreground'
                  )}>
                    {isSelected && <CheckCircle2 className="w-3 h-3 text-white" />}
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className={cn('font-medium text-sm', isSelected && 'text-primary')}>{option.label}</p>
                    {option.description && (
                      <p className="text-xs text-muted-foreground truncate">{option.description}</p>
                    )}
                  </div>
                </button>
              );
            })}
          </div>
          
          {/* Custom input for "Other" */}
          {hasOtherSelected && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              className="mt-3"
            >
              <input
                type="text"
                value={customValues[question.id] || ''}
                onChange={(e) => onCustomChange(question.id, e.target.value)}
                placeholder="Please specify other options (comma separated)..."
                className="w-full px-4 py-3 rounded-lg bg-primary/5 border-2 border-primary/30 focus:border-primary focus:ring-2 focus:ring-primary/20 outline-none text-sm"
                autoFocus
              />
            </motion.div>
          )}
        </div>
      )}

      {/* Text Input */}
      {question.type === 'text' && (
        <input
          type="text"
          value={value || ''}
          onChange={(e) => onChange(e.target.value)}
          placeholder={question.placeholder}
          className="w-full px-4 py-3 rounded-lg bg-muted/50 border border-border focus:border-primary focus:ring-2 focus:ring-primary/20 outline-none text-sm"
        />
      )}

      {/* Textarea Input */}
      {question.type === 'textarea' && (
        <textarea
          value={value || ''}
          onChange={(e) => onChange(e.target.value)}
          placeholder={question.placeholder}
          rows={3}
          className="w-full px-4 py-3 rounded-lg bg-muted/50 border border-border focus:border-primary focus:ring-2 focus:ring-primary/20 outline-none text-sm resize-none"
        />
      )}
    </motion.div>
  );
}

function CategorySection({ category, questions, answers, onAnswer, customValues, onCustomChange }: {
  category: typeof CATEGORIES[0];
  questions: Question[];
  answers: Record<string, any>;
  onAnswer: (id: string, value: any) => void;
  customValues: Record<string, string>;
  onCustomChange: (id: string, value: string) => void;
}) {
  const [expanded, setExpanded] = useState(true);
  const Icon = category.icon;
  
  const visibleQuestions = questions.filter(q => !q.showIf || q.showIf(answers));
  const answeredCount = visibleQuestions.filter(q => {
    const val = answers[q.id];
    return val !== undefined && val !== '' && (Array.isArray(val) ? val.length > 0 : true);
  }).length;

  if (visibleQuestions.length === 0) return null;

  return (
    <div className="mb-8">
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex items-center gap-3 w-full mb-4 group"
      >
        <div className={cn('p-2 rounded-lg bg-gradient-to-br', category.color)}>
          <Icon className="w-5 h-5 text-white" />
        </div>
        <div className="flex-1 text-left">
          <h2 className="font-semibold text-lg">{category.id}</h2>
          <p className="text-sm text-muted-foreground">
            {answeredCount} of {visibleQuestions.length} answered
          </p>
        </div>
        <div className="flex items-center gap-2">
          {answeredCount === visibleQuestions.length && visibleQuestions.length > 0 && (
            <CheckCircle2 className="w-5 h-5 text-green-500" />
          )}
          {expanded ? (
            <ChevronDown className="w-5 h-5 text-muted-foreground" />
          ) : (
            <ChevronRight className="w-5 h-5 text-muted-foreground" />
          )}
        </div>
      </button>
      
      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="space-y-4 ml-2 pl-4 border-l-2 border-border"
          >
            {questions.map((question) => (
              <QuestionCard
                key={question.id}
                question={question}
                value={answers[question.id]}
                onChange={(value) => onAnswer(question.id, value)}
                answers={answers}
                customValues={customValues}
                onCustomChange={onCustomChange}
              />
            ))}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

function ProgressBar({ answers }: { answers: Record<string, any> }) {
  const totalRequired = QUESTIONS.filter(q => q.required).length;
  const answeredRequired = QUESTIONS.filter(q => {
    if (!q.required) return false;
    const val = answers[q.id];
    return val !== undefined && val !== '' && (Array.isArray(val) ? val.length > 0 : true);
  }).length;
  
  const visibleOptional = QUESTIONS.filter(q => !q.required && (!q.showIf || q.showIf(answers)));
  const answeredOptional = visibleOptional.filter(q => {
    const val = answers[q.id];
    return val !== undefined && val !== '' && (Array.isArray(val) ? val.length > 0 : true);
  }).length;
  
  const progress = ((answeredRequired / totalRequired) * 70 + (answeredOptional / Math.max(visibleOptional.length, 1)) * 30);
  
  return (
    <div className="bg-background rounded-xl border border-border p-4 mb-6">
      <div className="flex items-center justify-between mb-2">
        <span className="text-sm font-medium">Completion Progress</span>
        <span className="text-sm text-muted-foreground">{Math.round(progress)}%</span>
      </div>
      <div className="h-2 bg-muted rounded-full overflow-hidden">
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${progress}%` }}
          className="h-full bg-gradient-to-r from-primary to-purple-500 rounded-full"
        />
      </div>
      <p className="text-xs text-muted-foreground mt-2">
        {answeredRequired}/{totalRequired} required • {answeredOptional}/{visibleOptional.length} optional
      </p>
    </div>
  );
}

// ===========================================
// Main Page
// ===========================================

export default function ArchitectPage() {
  const [answers, setAnswers] = useState<Record<string, any>>({});
  const [customValues, setCustomValues] = useState<Record<string, string>>({});
  const [generating, setGenerating] = useState(false);
  const [methodology, setMethodology] = useState<'stride' | 'pasta'>('stride');
  const [result, setResult] = useState<any>(null);

  // Load saved answers from localStorage
  useEffect(() => {
    const saved = localStorage.getItem('architect_answers');
    const savedCustom = localStorage.getItem('architect_custom_values');
    if (saved) {
      try {
        setAnswers(JSON.parse(saved));
      } catch (e) {
        console.error('Failed to load saved answers');
      }
    }
    if (savedCustom) {
      try {
        setCustomValues(JSON.parse(savedCustom));
      } catch (e) {
        console.error('Failed to load saved custom values');
      }
    }
  }, []);

  // Save answers to localStorage
  useEffect(() => {
    if (Object.keys(answers).length > 0) {
      localStorage.setItem('architect_answers', JSON.stringify(answers));
    }
    if (Object.keys(customValues).length > 0) {
      localStorage.setItem('architect_custom_values', JSON.stringify(customValues));
    }
  }, [answers, customValues]);

  const handleAnswer = (id: string, value: any) => {
    setAnswers(prev => ({ ...prev, [id]: value }));
  };

  const handleCustomChange = (id: string, value: string) => {
    setCustomValues(prev => ({ ...prev, [id]: value }));
  };

  const handleReset = () => {
    if (confirm('Clear all answers and start over?')) {
      setAnswers({});
      setCustomValues({});
      localStorage.removeItem('architect_answers');
      localStorage.removeItem('architect_custom_values');
      setResult(null);
    }
  };

  const handleGenerate = async () => {
    setGenerating(true);
    setResult(null);
    
    try {
      // Merge custom values with answers
      const mergedAnswers = { ...answers };
      Object.entries(customValues).forEach(([key, value]) => {
        if (value && answers[key]) {
          mergedAnswers[`${key}_custom`] = value;
        }
      });

      // Build the form data for the API
      const formData = {
        methodology,
        ...mergedAnswers,
      };

      // Call the backend to generate threat model
      const response = await api.request<{
        success: boolean;
        project_id: string;
        analysis_id: string;
        threats_count: number;
        summary: any;
        redirect_url: string;
      }>('/api/architect/analyze-form', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData),
      });

      setResult({
        success: response.success,
        context: formData,
        analysisId: response.analysis_id,
        projectId: response.project_id,
        threatsCount: response.threats_count,
        summary: response.summary,
        redirectUrl: response.redirect_url,
        message: 'Analysis context collected successfully!',
      });

    } catch (error: any) {
      console.error('Generation failed:', error);
      setResult({
        success: false,
        error: error?.message || 'Failed to generate threat model',
        cause: error?.cause || 'The backend server may be unavailable or encountered an error',
        solution: error?.solution || 'Make sure the backend is running at http://localhost:8000'
      });
    } finally {
      setGenerating(false);
    }
  };

  const isReadyToGenerate = 
    (Array.isArray(answers.architecture_type) ? answers.architecture_type.length > 0 : !!answers.architecture_type) && 
    answers.system_description && 
    answers.uses_ai;

  // Group questions by category
  const questionsByCategory = CATEGORIES.map(cat => ({
    category: cat,
    questions: QUESTIONS.filter(q => q.category === cat.id),
  }));

  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-background to-muted/30 py-8 px-4">
      <div className="max-w-4xl mx-auto">
        {/* Header */}
        <div className="text-center mb-8">
          <motion.div
            initial={{ scale: 0.9, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary/10 text-primary text-sm font-medium mb-4"
          >
            <Sparkles className="w-4 h-4" />
            AI-Powered Security Analysis
          </motion.div>
          <h1 className="text-3xl font-bold mb-2">Threat Model Builder</h1>
          <p className="text-muted-foreground max-w-2xl mx-auto">
            Answer the questions below to describe your system architecture. We'll generate a comprehensive 
            threat model using {methodology === 'stride' ? 'STRIDE' : 'PASTA'} methodology.
          </p>
        </div>

        {/* Methodology Selector */}
        <div className="flex items-center justify-center gap-4 mb-8">
          <span className="text-sm text-muted-foreground">Methodology:</span>
          <div className="flex rounded-lg border border-border overflow-hidden">
            <button
              onClick={() => setMethodology('stride')}
              className={cn(
                'px-4 py-2 text-sm font-medium transition-colors',
                methodology === 'stride'
                  ? 'bg-blue-500 text-white'
                  : 'bg-background text-muted-foreground hover:text-foreground'
              )}
            >
              STRIDE
            </button>
            <button
              onClick={() => setMethodology('pasta')}
              className={cn(
                'px-4 py-2 text-sm font-medium transition-colors',
                methodology === 'pasta'
                  ? 'bg-purple-500 text-white'
                  : 'bg-background text-muted-foreground hover:text-foreground'
              )}
            >
              PASTA
            </button>
          </div>
        </div>

        {/* Progress Bar */}
        <ProgressBar answers={answers} />

        {/* Questions */}
        <div className="space-y-2">
          {questionsByCategory.map(({ category, questions }) => (
            <CategorySection
              key={category.id}
              category={category}
              questions={questions}
              answers={answers}
              onAnswer={handleAnswer}
              customValues={customValues}
              onCustomChange={handleCustomChange}
            />
          ))}
        </div>

        {/* Actions */}
        <div className="sticky bottom-4 mt-8">
          <div className="bg-background/95 backdrop-blur-sm rounded-xl border border-border p-4 shadow-lg">
            <div className="flex items-center justify-between gap-4">
              <button
                onClick={handleReset}
                className="px-4 py-2 text-sm text-muted-foreground hover:text-foreground transition-colors"
              >
                <RefreshCw className="w-4 h-4 inline mr-2" />
                Reset
              </button>
              
              <div className="flex items-center gap-3">
                {!isReadyToGenerate && (
                  <p className="text-sm text-muted-foreground">
                    Complete required fields to continue
                  </p>
                )}
                <motion.button
                  whileHover={isReadyToGenerate ? { scale: 1.02 } : {}}
                  whileTap={isReadyToGenerate ? { scale: 0.98 } : {}}
                  onClick={handleGenerate}
                  disabled={!isReadyToGenerate || generating}
                  className={cn(
                    'flex items-center gap-2 px-6 py-3 rounded-xl font-medium transition-all',
                    isReadyToGenerate
                      ? 'bg-gradient-to-r from-primary to-purple-600 text-white shadow-lg shadow-primary/25'
                      : 'bg-muted text-muted-foreground cursor-not-allowed'
                  )}
                >
                  {generating ? (
                    <>
                      <Loader2 className="w-5 h-5 animate-spin" />
                      Analyzing...
                    </>
                  ) : (
                    <>
                      <Zap className="w-5 h-5" />
                      Generate Threat Model
                      <ArrowRight className="w-4 h-4" />
                    </>
                  )}
                </motion.button>
              </div>
            </div>
          </div>
        </div>

        {/* Result Preview */}
        <AnimatePresence>
          {result && !result.success && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              className="mt-8 p-6 bg-red-500/10 border border-red-500/30 rounded-xl"
            >
              <div className="flex items-start gap-3">
                <XCircle className="w-6 h-6 text-red-500 mt-0.5" />
                <div className="flex-1">
                  <h3 className="font-semibold text-red-600 dark:text-red-400 text-lg">
                    ❌ Failed to Generate Threat Model
                  </h3>
                  <p className="text-sm text-foreground mt-2">
                    <strong>Error:</strong> {result.error}
                  </p>
                  {result.cause && (
                    <p className="text-sm text-muted-foreground mt-1">
                      <strong>Cause:</strong> {result.cause}
                    </p>
                  )}
                  {result.solution && (
                    <p className="text-sm text-green-600 dark:text-green-400 mt-2">
                      <strong>Solution:</strong> {result.solution}
                    </p>
                  )}
                  <button
                    onClick={() => setResult(null)}
                    className="mt-4 px-4 py-2 bg-muted text-foreground rounded-lg text-sm"
                  >
                    Dismiss
                  </button>
                </div>
              </div>
            </motion.div>
          )}

          {result && result.success && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              className="mt-8 p-6 bg-green-500/10 border border-green-500/30 rounded-xl"
            >
              <div className="flex items-start gap-3">
                <CheckCircle2 className="w-6 h-6 text-green-500 mt-0.5" />
                <div className="flex-1">
                  <h3 className="font-semibold text-green-600 dark:text-green-400 text-lg">
                    🎉 Threat Model Generated!
                  </h3>
                  
                  {result.summary && (
                    <div className="mt-4 grid grid-cols-2 sm:grid-cols-4 gap-3">
                      <div className="p-3 bg-background/50 rounded-lg text-center">
                        <div className="text-2xl font-bold">{result.threatsCount || 0}</div>
                        <div className="text-xs text-muted-foreground">Total Threats</div>
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
                  )}

                  <p className="text-sm text-muted-foreground mt-4">
                    Your threat model has been generated using the <strong>{methodology.toUpperCase()}</strong> methodology.
                    View the detailed analysis including DFD diagrams, compliance mappings, and mitigations.
                  </p>

                  <div className="flex gap-3 mt-4">
                    <button
                      onClick={() => {
                        if (result.analysisId) {
                          window.location.href = `/review?analysis_id=${result.analysisId}`;
                        } else {
                          window.location.href = '/review';
                        }
                      }}
                      className="flex-1 px-4 py-3 bg-primary text-white rounded-xl text-sm font-medium flex items-center justify-center gap-2"
                    >
                      <Shield className="w-5 h-5" />
                      View Threat Analysis
                      <ArrowRight className="w-4 h-4" />
                    </button>
                    <button
                      onClick={() => {
                        if (result.analysisId) {
                          window.location.href = `/dfd?analysis_id=${result.analysisId}`;
                        }
                      }}
                      className="px-4 py-3 bg-purple-500/20 text-purple-600 dark:text-purple-400 rounded-xl text-sm font-medium"
                    >
                      View DFD
                    </button>
                  </div>

                  {/* Collapsible raw data */}
                  <details className="mt-4">
                    <summary className="text-xs text-muted-foreground cursor-pointer hover:text-foreground">
                      Show raw analysis context
                    </summary>
                    <div className="mt-2 p-3 bg-muted/50 rounded-lg">
                      <pre className="text-xs overflow-auto max-h-32">
                        {JSON.stringify(result.context, null, 2)}
                      </pre>
                    </div>
                  </details>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}
