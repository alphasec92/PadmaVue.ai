'use client';

import { motion } from 'framer-motion';
import Link from 'next/link';
import { 
  Shield, 
  Target, 
  Upload, 
  FileSearch, 
  GitBranch, 
  Lock, 
  Zap,
  ArrowRight,
  CheckCircle2,
  BarChart3,
  Code2,
  Sparkles,
  Bot,
  Settings,
  MessageSquare,
  FileText,
  Cloud
} from 'lucide-react';
import { useState } from 'react';
import { SettingsModal } from '@/components/settings-modal';

const features = [
  {
    icon: Shield,
    title: 'STRIDE Analysis',
    description: 'Systematic threat identification using Microsoft\'s proven methodology',
    gradient: 'from-blue-500 to-cyan-500',
    bgColor: 'bg-blue-500/10',
  },
  {
    icon: Target,
    title: 'PASTA Modeling',
    description: '7-stage risk-centric analysis with threat agent profiling',
    gradient: 'from-purple-500 to-pink-500',
    bgColor: 'bg-purple-500/10',
  },
  {
    icon: Lock,
    title: 'Compliance Mapping',
    description: 'Automatic mapping to NIST 800-53 and OWASP ASVS controls',
    gradient: 'from-green-500 to-emerald-500',
    bgColor: 'bg-green-500/10',
  },
  {
    icon: GitBranch,
    title: 'DFD Generation',
    description: 'AI-generated Data Flow Diagrams with threat annotations',
    gradient: 'from-orange-500 to-amber-500',
    bgColor: 'bg-orange-500/10',
  },
  {
    icon: Code2,
    title: 'DevSecOps Rules',
    description: 'Generate Checkov, tfsec, and Semgrep security rules',
    gradient: 'from-red-500 to-rose-500',
    bgColor: 'bg-red-500/10',
  },
  {
    icon: BarChart3,
    title: 'DREAD Scoring',
    description: 'Quantified risk assessment for prioritized remediation',
    gradient: 'from-indigo-500 to-violet-500',
    bgColor: 'bg-indigo-500/10',
  },
];

const steps = [
  { step: 1, title: 'Configure', desc: 'Set up your AI provider - local or cloud', icon: Settings },
  { step: 2, title: 'Input', desc: 'Upload documents or consult with AI agent', icon: Upload },
  { step: 3, title: 'Analyze', desc: 'AI performs comprehensive threat modeling', icon: Zap },
  { step: 4, title: 'Export', desc: 'Download PDF/JSON reports and rules', icon: FileText },
];

export default function HomePage() {
  const [showSettings, setShowSettings] = useState(false);

  return (
    <div className="relative">
      {/* Hero Section */}
      <section className="relative px-4 sm:px-6 lg:px-8 py-20 lg:py-32">
        <div className="mx-auto max-w-7xl">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8 }}
            className="text-center"
          >
            {/* Badge */}
            <motion.div
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: 0.2 }}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-full glass mb-8"
            >
              <Sparkles className="w-4 h-4 text-primary" />
              <span className="text-sm font-medium">AI-Powered Security Analysis</span>
            </motion.div>

            {/* Headline */}
            <h1 className="max-w-4xl mx-auto mb-6">
              <span className="block text-4xl sm:text-5xl md:text-6xl lg:text-7xl font-bold tracking-tight mb-2 bg-gradient-to-r from-blue-400 via-purple-500 to-cyan-400 bg-clip-text text-transparent drop-shadow-lg">
                Threat Modeling
              </span>
              <span className="block text-4xl sm:text-5xl md:text-6xl lg:text-7xl font-bold tracking-tight text-foreground">
                Reimagined with AI
              </span>
            </h1>

            {/* Subheadline */}
            <p className="body-lg max-w-2xl mx-auto mb-10">
              Comprehensive security analysis using STRIDE & PASTA methodologies, 
              powered by advanced AI agents with GraphRAG and compliance automation.
            </p>

            {/* CTAs */}
            <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
              <Link href="/upload">
                <motion.button
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                  className="flex items-center gap-2 px-8 py-4 rounded-2xl bg-gradient-to-r from-primary to-purple-600 text-white font-semibold shadow-xl shadow-primary/25 glow-hover"
                >
                  <Upload className="w-5 h-5" />
                  Start Security Review
                  <ArrowRight className="w-5 h-5" />
                </motion.button>
              </Link>
              
              <motion.button
                onClick={() => setShowSettings(true)}
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                className="flex items-center gap-2 px-8 py-4 rounded-2xl glass font-semibold"
              >
                <Settings className="w-5 h-5" />
                Configure AI Provider
              </motion.button>
            </div>
          </motion.div>

          {/* Methodology Cards - Consistent with Settings Modal */}
          <motion.div
            initial={{ opacity: 0, y: 40 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.4, duration: 0.8 }}
            className="mt-20 grid md:grid-cols-2 gap-6 max-w-4xl mx-auto"
          >
            {/* STRIDE Card */}
            <motion.div 
              whileHover={{ scale: 1.02 }}
              className="relative p-8 rounded-3xl border-2 border-border hover:border-blue-500/50 bg-background/50 backdrop-blur-sm transition-all overflow-hidden group"
            >
              <div className="absolute top-0 right-0 w-32 h-32 bg-gradient-to-br from-blue-500/20 to-cyan-500/20 rounded-full blur-3xl group-hover:scale-150 transition-transform" />
              <div className="relative">
                <div className="flex items-center gap-3 mb-4">
                  <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-blue-500 to-cyan-500 flex items-center justify-center">
                    <Shield className="w-6 h-6 text-white" />
                  </div>
                  <div>
                    <h3 className="text-xl font-bold">STRIDE</h3>
                    <p className="text-sm text-muted-foreground">Microsoft's methodology</p>
                  </div>
                </div>
                <p className="text-muted-foreground mb-4">
                  Systematic threat categorization for comprehensive security analysis
                </p>
                <div className="flex flex-wrap gap-1.5">
                  {['Spoofing', 'Tampering', 'Repudiation', 'Info Disclosure', 'DoS', 'Elevation'].map((cat) => (
                    <span key={cat} className="px-2.5 py-1 rounded-full bg-blue-500/10 text-blue-600 dark:text-blue-400 text-xs font-medium">
                      {cat}
                    </span>
                  ))}
                </div>
              </div>
            </motion.div>

            {/* PASTA Card */}
            <motion.div 
              whileHover={{ scale: 1.02 }}
              className="relative p-8 rounded-3xl border-2 border-border hover:border-purple-500/50 bg-background/50 backdrop-blur-sm transition-all overflow-hidden group"
            >
              <div className="absolute top-0 right-0 w-32 h-32 bg-gradient-to-br from-purple-500/20 to-pink-500/20 rounded-full blur-3xl group-hover:scale-150 transition-transform" />
              <div className="relative">
                <div className="flex items-center gap-3 mb-4">
                  <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-purple-500 to-pink-500 flex items-center justify-center">
                    <Target className="w-6 h-6 text-white" />
                  </div>
                  <div>
                    <h3 className="text-xl font-bold">PASTA</h3>
                    <p className="text-sm text-muted-foreground">Risk-centric approach</p>
                  </div>
                </div>
                <p className="text-muted-foreground mb-4">
                  7-stage process with business alignment and attack simulation
                </p>
                <div className="flex flex-wrap gap-1.5">
                  {['Objectives', 'Scope', 'Decomposition', 'Threats', 'Vulns', 'Attacks', 'Risk'].map((stage) => (
                    <span key={stage} className="px-2.5 py-1 rounded-full bg-purple-500/10 text-purple-600 dark:text-purple-400 text-xs font-medium">
                      {stage}
                    </span>
                  ))}
                </div>
              </div>
            </motion.div>
          </motion.div>
        </div>
      </section>

      {/* Security Review Agent Section */}
      <section className="relative px-4 sm:px-6 lg:px-8 py-16">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="mx-auto max-w-4xl p-8 rounded-3xl border-2 border-primary/20 bg-gradient-to-br from-primary/5 via-purple-500/5 to-pink-500/5"
        >
          <div className="flex flex-col md:flex-row items-center gap-6">
            <div className="w-20 h-20 rounded-2xl bg-gradient-to-br from-purple-500 to-blue-500 flex items-center justify-center shrink-0">
              <Bot className="w-10 h-10 text-white" />
            </div>
            <div className="flex-1 text-center md:text-left">
              <h2 className="text-2xl font-bold mb-2">Security Review Agent</h2>
              <p className="text-muted-foreground mb-4">
                No documentation? Consult our AI Security Agent. Describe your system architecture in plain English, 
                share code snippets, and receive a comprehensive threat model through intelligent conversation.
              </p>
              <Link href="/ai-architect">
                <motion.button
                  whileHover={{ scale: 1.02 }}
                  whileTap={{ scale: 0.98 }}
                  className="inline-flex items-center gap-2 px-6 py-3 rounded-xl bg-gradient-to-r from-purple-500 to-blue-500 text-white font-medium"
                >
                  <MessageSquare className="w-5 h-5" />
                  Start Consultation
                  <ArrowRight className="w-4 h-4" />
                </motion.button>
              </Link>
            </div>
          </div>
        </motion.div>
      </section>

      {/* Features Section */}
      <section className="relative px-4 sm:px-6 lg:px-8 py-20">
        <div className="mx-auto max-w-7xl">
          <motion.div
            initial={{ opacity: 0 }}
            whileInView={{ opacity: 1 }}
            viewport={{ once: true }}
            className="text-center mb-16"
          >
            <h2 className="heading-lg mb-4">Comprehensive Security Analysis</h2>
            <p className="body-lg max-w-2xl mx-auto">
              Everything you need for professional-grade threat modeling and security review
            </p>
          </motion.div>

          <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-6">
            {features.map((feature, index) => {
              const Icon = feature.icon;
              return (
                <motion.div
                  key={feature.title}
                  initial={{ opacity: 0, y: 20 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true }}
                  transition={{ delay: index * 0.1 }}
                  whileHover={{ scale: 1.02 }}
                  className="p-6 rounded-2xl border-2 border-border hover:border-primary/30 bg-background/50 backdrop-blur-sm transition-all group"
                >
                  <div className={`w-12 h-12 rounded-xl bg-gradient-to-br ${feature.gradient} flex items-center justify-center mb-4 group-hover:scale-110 transition-transform`}>
                    <Icon className="w-6 h-6 text-white" />
                  </div>
                  <h3 className="text-lg font-semibold mb-2">{feature.title}</h3>
                  <p className="text-sm text-muted-foreground">{feature.description}</p>
                </motion.div>
              );
            })}
          </div>
        </div>
      </section>

      {/* How It Works */}
      <section className="relative px-4 sm:px-6 lg:px-8 py-20">
        <div className="mx-auto max-w-7xl">
          <motion.div
            initial={{ opacity: 0 }}
            whileInView={{ opacity: 1 }}
            viewport={{ once: true }}
            className="text-center mb-16"
          >
            <h2 className="heading-lg mb-4">How It Works</h2>
            <p className="body-lg max-w-2xl mx-auto">
              From setup to actionable security insights in minutes
            </p>
          </motion.div>

          <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-6">
            {steps.map((item, index) => {
              const Icon = item.icon;
              return (
                <motion.div
                  key={item.step}
                  initial={{ opacity: 0, y: 20 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true }}
                  transition={{ delay: index * 0.15 }}
                  className="relative"
                >
                  {index < steps.length - 1 && (
                    <div className="hidden lg:block absolute top-12 left-[60%] w-[80%] h-[2px] bg-gradient-to-r from-primary/50 to-transparent" />
                  )}
                  <div className="p-6 rounded-2xl border-2 border-border bg-background/50 backdrop-blur-sm text-center">
                    <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-primary/20 to-purple-500/20 flex items-center justify-center mx-auto mb-4 relative">
                      <span className="absolute -top-2 -right-2 w-6 h-6 rounded-full bg-primary text-white text-xs font-bold flex items-center justify-center">
                        {item.step}
                      </span>
                      <Icon className="w-7 h-7 text-primary" />
                    </div>
                    <h3 className="text-lg font-semibold mb-2">{item.title}</h3>
                    <p className="text-sm text-muted-foreground">{item.desc}</p>
                  </div>
                </motion.div>
              );
            })}
          </div>
        </div>
      </section>

      {/* LLM Providers Section */}
      <section className="relative px-4 sm:px-6 lg:px-8 py-16">
        <div className="mx-auto max-w-4xl">
          <motion.div
            initial={{ opacity: 0 }}
            whileInView={{ opacity: 1 }}
            viewport={{ once: true }}
            className="text-center mb-8"
          >
            <h2 className="text-2xl font-bold mb-2">Flexible AI Provider Support</h2>
            <p className="text-muted-foreground">
              Use your preferred LLM - cloud or local, your choice
            </p>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="flex flex-wrap justify-center gap-3"
          >
            {[
              { name: 'Ollama', color: 'from-pink-500 to-rose-600' },
              { name: 'OpenRouter', color: 'from-purple-500 to-violet-600' },
              { name: 'OpenAI', color: 'from-green-500 to-emerald-600' },
              { name: 'Claude', color: 'from-orange-500 to-amber-600' },
              { name: 'Gemini', color: 'from-blue-500 to-cyan-600' },
              { name: 'LM Studio', color: 'from-indigo-500 to-purple-600' },
            ].map(provider => (
              <div 
                key={provider.name}
                className="flex items-center gap-2 px-4 py-2 rounded-xl border border-border bg-muted/50"
              >
                <div className={`w-2 h-2 rounded-full bg-gradient-to-r ${provider.color}`} />
                <span className="text-sm font-medium">{provider.name}</span>
              </div>
            ))}
          </motion.div>

          <motion.div
            initial={{ opacity: 0 }}
            whileInView={{ opacity: 1 }}
            viewport={{ once: true }}
            className="text-center mt-6"
          >
            <button 
              onClick={() => setShowSettings(true)}
              className="text-sm text-primary hover:underline inline-flex items-center gap-1"
            >
              <Settings className="w-4 h-4" />
              Configure in Settings
            </button>
          </motion.div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="relative px-4 sm:px-6 lg:px-8 py-20">
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          whileInView={{ opacity: 1, scale: 1 }}
          viewport={{ once: true }}
          className="mx-auto max-w-4xl p-12 rounded-3xl bg-gradient-to-br from-primary/10 via-purple-500/10 to-pink-500/10 border-2 border-primary/20 text-center"
        >
          <div className="w-20 h-20 rounded-2xl bg-gradient-to-br from-primary to-purple-600 flex items-center justify-center mx-auto mb-6 float">
            <Zap className="w-10 h-10 text-white" />
          </div>
          <h2 className="heading-md mb-4">Ready to Secure Your Application?</h2>
          <p className="body-lg max-w-xl mx-auto mb-8">
            Start your security review now and get actionable insights in minutes
          </p>
          <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
            <Link href="/upload">
              <motion.button
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                className="flex items-center gap-2 px-8 py-4 rounded-2xl bg-gradient-to-r from-primary to-purple-600 text-white font-semibold shadow-xl shadow-primary/25"
              >
                <Upload className="w-5 h-5" />
                Analyze Documents
              </motion.button>
            </Link>
            <Link href="/ai-architect">
              <motion.button
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                className="flex items-center gap-2 px-8 py-4 rounded-2xl glass font-semibold"
              >
                <Bot className="w-5 h-5" />
                Consult AI Agent
              </motion.button>
            </Link>
          </div>
        </motion.div>
      </section>

      {/* Footer */}
      <footer className="relative px-4 sm:px-6 lg:px-8 py-12 border-t border-border/50">
        <div className="mx-auto max-w-7xl flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-primary to-purple-600 flex items-center justify-center">
              <Shield className="w-4 h-4 text-white" />
            </div>
            <span className="font-semibold">SecurityReview.ai</span>
          </div>
          <div className="flex items-center gap-4">
            <button 
              onClick={() => setShowSettings(true)}
              className="text-sm text-muted-foreground hover:text-foreground transition-colors"
            >
              Settings
            </button>
            <Link href="/ai-architect" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
              Consult
            </Link>
            <Link href="/upload" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
              Analyze
            </Link>
          </div>
          <p className="text-sm text-muted-foreground">
            Built with ❤️ for secure software development
          </p>
        </div>
      </footer>

      {/* Settings Modal */}
      <SettingsModal isOpen={showSettings} onClose={() => setShowSettings(false)} />
    </div>
  );
}
