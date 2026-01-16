'use client';

import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ExternalLink, Shield, Bot, Server, Globe, ChevronDown, AlertTriangle, Info } from 'lucide-react';
import { cn } from '@/lib/utils';

interface OWASPMapping {
  owasp_top_10?: string[];
  owasp_api?: string[];
  owasp_llm?: string[];
  agentic_ai?: string[];
}

interface OWASPBadgeProps {
  mappings: OWASPMapping;
  compact?: boolean;
  showDetails?: boolean;
}

// OWASP Reference data
const OWASP_REFERENCES: Record<string, { title: string; description: string; url: string; framework: string }> = {
  // OWASP Top 10 Web (2021)
  'A01:2021': { title: 'Broken Access Control', description: 'Restrictions on authenticated users are not properly enforced', url: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/', framework: 'Web' },
  'A02:2021': { title: 'Cryptographic Failures', description: 'Failures related to cryptography leading to sensitive data exposure', url: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/', framework: 'Web' },
  'A03:2021': { title: 'Injection', description: 'User-supplied data not validated, filtered, or sanitized', url: 'https://owasp.org/Top10/A03_2021-Injection/', framework: 'Web' },
  'A04:2021': { title: 'Insecure Design', description: 'Missing or ineffective security controls design', url: 'https://owasp.org/Top10/A04_2021-Insecure_Design/', framework: 'Web' },
  'A05:2021': { title: 'Security Misconfiguration', description: 'Missing security hardening or improperly configured permissions', url: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/', framework: 'Web' },
  'A06:2021': { title: 'Vulnerable Components', description: 'Using components with known vulnerabilities', url: 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/', framework: 'Web' },
  'A07:2021': { title: 'Auth Failures', description: 'Authentication and session management weaknesses', url: 'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/', framework: 'Web' },
  'A08:2021': { title: 'Integrity Failures', description: 'Code and infrastructure integrity violations', url: 'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/', framework: 'Web' },
  'A09:2021': { title: 'Logging Failures', description: 'Without logging and monitoring, breaches cannot be detected', url: 'https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/', framework: 'Web' },
  'A10:2021': { title: 'SSRF', description: 'Server-Side Request Forgery', url: 'https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/', framework: 'Web' },
  
  // OWASP API Security Top 10 (2023)
  'API1:2023': { title: 'Broken Object Level Authorization', description: 'APIs exposing endpoints without proper authorization', url: 'https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/', framework: 'API' },
  'API2:2023': { title: 'Broken Authentication', description: 'Flawed authentication mechanisms in APIs', url: 'https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/', framework: 'API' },
  'API3:2023': { title: 'Broken Property Level Auth', description: 'Improper authorization at property level', url: 'https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/', framework: 'API' },
  'API4:2023': { title: 'Unrestricted Resource Consumption', description: 'API not restricting size or number of resources', url: 'https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/', framework: 'API' },
  'API5:2023': { title: 'Broken Function Level Auth', description: 'Complex access control with unclear separation', url: 'https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/', framework: 'API' },
  'API6:2023': { title: 'Unrestricted Business Flows', description: 'Exposing business flows without controls', url: 'https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/', framework: 'API' },
  'API7:2023': { title: 'Server Side Request Forgery', description: 'API fetching remote resources without validation', url: 'https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/', framework: 'API' },
  'API8:2023': { title: 'Security Misconfiguration', description: 'Improper or insecure API configuration', url: 'https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/', framework: 'API' },
  'API9:2023': { title: 'Improper Inventory Management', description: 'Lack of proper API inventory and version management', url: 'https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/', framework: 'API' },
  'API10:2023': { title: 'Unsafe API Consumption', description: 'Vulnerabilities when consuming third-party APIs', url: 'https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/', framework: 'API' },
  
  // OWASP LLM AI Top 10 (2025)
  'LLM01:2025': { title: 'Prompt Injection', description: 'Manipulating LLM through crafted inputs', url: 'https://genai.owasp.org/', framework: 'LLM/AI' },
  'LLM02:2025': { title: 'Sensitive Info Disclosure', description: 'LLM revealing confidential data', url: 'https://genai.owasp.org/', framework: 'LLM/AI' },
  'LLM03:2025': { title: 'Supply Chain Vulnerabilities', description: 'Compromises in LLM supply chain', url: 'https://genai.owasp.org/', framework: 'LLM/AI' },
  'LLM04:2025': { title: 'Data/Model Poisoning', description: 'Tampering with training data or model', url: 'https://genai.owasp.org/', framework: 'LLM/AI' },
  'LLM05:2025': { title: 'Improper Output Handling', description: 'Failing to handle LLM outputs safely', url: 'https://genai.owasp.org/', framework: 'LLM/AI' },
  'LLM06:2025': { title: 'Excessive Agency', description: 'LLM with too much autonomy', url: 'https://genai.owasp.org/', framework: 'LLM/AI' },
  'LLM07:2025': { title: 'System Prompt Leakage', description: 'Extraction of system prompts', url: 'https://genai.owasp.org/', framework: 'LLM/AI' },
  'LLM08:2025': { title: 'Vector/Embedding Weaknesses', description: 'Vulnerabilities in vector databases', url: 'https://genai.owasp.org/', framework: 'LLM/AI' },
  'LLM09:2025': { title: 'Misinformation', description: 'LLM generating false information', url: 'https://genai.owasp.org/', framework: 'LLM/AI' },
  'LLM10:2025': { title: 'Unbounded Consumption', description: 'DoS through excessive resource use', url: 'https://genai.owasp.org/', framework: 'LLM/AI' },
  
  // Agentic AI Threats
  'AGENT01': { title: 'Uncontrolled Autonomy', description: 'AI agents executing without oversight', url: 'https://genai.owasp.org/', framework: 'Agentic AI' },
  'AGENT02': { title: 'Tool/API Abuse', description: 'AI agents misusing tools or APIs', url: 'https://genai.owasp.org/', framework: 'Agentic AI' },
  'AGENT03': { title: 'Memory Manipulation', description: 'Attacks on agent memory/context', url: 'https://genai.owasp.org/', framework: 'Agentic AI' },
  'AGENT04': { title: 'Multi-Agent Attacks', description: 'Exploiting agent communication', url: 'https://genai.owasp.org/', framework: 'Agentic AI' },
  'AGENT05': { title: 'Goal Misalignment', description: 'Agents gaming specifications', url: 'https://genai.owasp.org/', framework: 'Agentic AI' },
};

const FRAMEWORK_COLORS: Record<string, { bg: string; text: string; icon: any }> = {
  'Web': { bg: 'bg-blue-500/20', text: 'text-blue-500', icon: Globe },
  'API': { bg: 'bg-purple-500/20', text: 'text-purple-500', icon: Server },
  'LLM/AI': { bg: 'bg-amber-500/20', text: 'text-amber-500', icon: Bot },
  'Agentic AI': { bg: 'bg-red-500/20', text: 'text-red-500', icon: AlertTriangle },
};

export function OWASPBadge({ mappings, compact = false, showDetails = true }: OWASPBadgeProps) {
  const [expanded, setExpanded] = useState(false);
  
  // Collect all OWASP IDs
  const allIds = [
    ...(mappings.owasp_top_10 || []),
    ...(mappings.owasp_api || []),
    ...(mappings.owasp_llm || []),
    ...(mappings.agentic_ai || []),
  ];
  
  if (allIds.length === 0) return null;
  
  // Group by framework
  const groupedMappings = {
    'Web': mappings.owasp_top_10 || [],
    'API': mappings.owasp_api || [],
    'LLM/AI': mappings.owasp_llm || [],
    'Agentic AI': mappings.agentic_ai || [],
  };
  
  if (compact) {
    // Compact view - just badges
    return (
      <div className="flex flex-wrap gap-1">
        {allIds.slice(0, 3).map(id => {
          const ref = OWASP_REFERENCES[id];
          const colors = FRAMEWORK_COLORS[ref?.framework || 'Web'];
          return (
            <span
              key={id}
              className={cn('px-2 py-0.5 rounded text-xs font-medium', colors.bg, colors.text)}
              title={ref?.title || id}
            >
              {id}
            </span>
          );
        })}
        {allIds.length > 3 && (
          <span className="px-2 py-0.5 rounded text-xs font-medium bg-muted text-muted-foreground">
            +{allIds.length - 3}
          </span>
        )}
      </div>
    );
  }
  
  return (
    <div className="mt-4">
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex items-center gap-2 text-sm font-medium hover:text-primary transition-colors"
      >
        <Shield className="w-4 h-4" />
        OWASP Mappings ({allIds.length})
        <ChevronDown className={cn('w-4 h-4 transition-transform', expanded && 'rotate-180')} />
      </button>
      
      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="overflow-hidden"
          >
            <div className="mt-3 space-y-3">
              {Object.entries(groupedMappings).map(([framework, ids]) => {
                if (ids.length === 0) return null;
                const colors = FRAMEWORK_COLORS[framework];
                const Icon = colors.icon;
                
                return (
                  <div key={framework}>
                    <div className="flex items-center gap-2 mb-2">
                      <Icon className={cn('w-4 h-4', colors.text)} />
                      <span className={cn('text-xs font-medium', colors.text)}>
                        {framework === 'LLM/AI' ? 'OWASP LLM AI Top 10' : 
                         framework === 'Agentic AI' ? 'Agentic AI Security' :
                         framework === 'API' ? 'OWASP API Security Top 10' : 
                         'OWASP Top 10 Web'}
                      </span>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {ids.map(id => {
                        const ref = OWASP_REFERENCES[id];
                        return (
                          <a
                            key={id}
                            href={ref?.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className={cn(
                              'group flex items-center gap-1 px-2 py-1 rounded-lg text-xs font-medium transition-all hover:scale-105',
                              colors.bg, colors.text
                            )}
                            title={ref?.description}
                          >
                            {id}
                            {showDetails && ref && (
                              <span className="hidden group-hover:inline text-xs opacity-75 max-w-[150px] truncate">
                                - {ref.title}
                              </span>
                            )}
                            <ExternalLink className="w-3 h-3 opacity-50 group-hover:opacity-100" />
                          </a>
                        );
                      })}
                    </div>
                  </div>
                );
              })}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

// Inline badge for threat cards
export function OWASPInlineBadges({ mappings }: { mappings: OWASPMapping }) {
  const allIds = [
    ...(mappings.owasp_top_10 || []),
    ...(mappings.owasp_api || []),
    ...(mappings.owasp_llm || []),
    ...(mappings.agentic_ai || []),
  ];
  
  if (allIds.length === 0) return null;
  
  // Check if has AI-related mappings
  const hasAI = (mappings.owasp_llm?.length || 0) > 0 || (mappings.agentic_ai?.length || 0) > 0;
  
  return (
    <div className="flex items-center gap-1">
      {hasAI && (
        <span className="flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-amber-500/20 text-amber-500">
          <Bot className="w-3 h-3" />
          AI
        </span>
      )}
      <span className="px-2 py-0.5 rounded text-xs font-medium bg-blue-500/20 text-blue-500">
        OWASP: {allIds.length}
      </span>
    </div>
  );
}

// Summary component for showing all AI threats
export function AIThreatSummary({ 
  threats 
}: { 
  threats: Array<{ id: string; title: string; owasp_id: string; severity: string; description: string }> 
}) {
  if (!threats || threats.length === 0) return null;
  
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="p-4 rounded-2xl bg-gradient-to-br from-amber-500/10 via-red-500/5 to-purple-500/10 border border-amber-500/20"
    >
      <div className="flex items-center gap-2 mb-3">
        <Bot className="w-5 h-5 text-amber-500" />
        <h3 className="font-semibold text-amber-500">AI-Specific Security Threats</h3>
        <span className="px-2 py-0.5 rounded-full text-xs font-medium bg-amber-500/20 text-amber-500">
          {threats.length} detected
        </span>
      </div>
      <p className="text-sm text-muted-foreground mb-3">
        The following AI/LLM-specific security threats have been identified in your system:
      </p>
      <div className="space-y-2">
        {threats.map(threat => (
          <div key={threat.id} className="flex items-start gap-3 p-2 rounded-lg bg-background/50">
            <AlertTriangle className={cn(
              'w-4 h-4 mt-0.5 shrink-0',
              threat.severity === 'critical' ? 'text-red-500' :
              threat.severity === 'high' ? 'text-orange-500' : 'text-yellow-500'
            )} />
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2">
                <span className="font-medium text-sm">{threat.title}</span>
                <span className="px-1.5 py-0.5 rounded text-xs bg-amber-500/20 text-amber-500">
                  {threat.owasp_id}
                </span>
              </div>
              <p className="text-xs text-muted-foreground mt-0.5 line-clamp-2">{threat.description}</p>
            </div>
          </div>
        ))}
      </div>
    </motion.div>
  );
}
