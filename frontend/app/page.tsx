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
    icon: Bot,
    title: 'MAESTRO Framework',
    description: 'CSA\'s Agentic AI threat modeling for LLMs and multi-agent systems',
    gradient: 'from-orange-500 to-red-500',
    bgColor: 'bg-orange-500/10',
    badge: 'NEW',
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
    gradient: 'from-amber-500 to-yellow-500',
    bgColor: 'bg-amber-500/10',
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
              <motion.span 
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.3, duration: 0.6 }}
                className="block text-4xl sm:text-5xl md:text-6xl lg:text-7xl font-bold tracking-tight mb-2 bg-gradient-to-r from-watercolor-coral via-watercolor-pink to-watercolor-blush bg-clip-text text-transparent drop-shadow-lg animate-gradient-shift bg-[length:200%_200%]"
              >
                Threat Modeling
              </motion.span>
              <motion.span 
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.5, duration: 0.6 }}
                className="block text-4xl sm:text-5xl md:text-6xl lg:text-7xl font-bold tracking-tight text-foreground"
              >
                Reimagined with AI
              </motion.span>
            </h1>

            {/* Subheadline */}
            <p className="body-lg max-w-2xl mx-auto mb-10">
              Comprehensive security analysis using STRIDE, PASTA & MAESTRO methodologies, 
              powered by advanced AI agents with GraphRAG and compliance automation.
            </p>

            {/* CTAs */}
            <motion.div 
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.7, duration: 0.6 }}
              className="flex flex-col sm:flex-row items-center justify-center gap-4"
            >
              <Link href="/upload">
                <motion.button
                  whileHover={{ scale: 1.05, boxShadow: '0 20px 40px -10px hsl(5 64% 69% / 0.4)' }}
                  whileTap={{ scale: 0.95 }}
                  className="group flex items-center gap-2 px-8 py-4 rounded-2xl bg-gradient-to-r from-watercolor-coral to-watercolor-pink text-white font-semibold shadow-xl shadow-watercolor-coral/30 relative overflow-hidden"
                >
                  <span className="absolute inset-0 bg-gradient-to-r from-watercolor-pink to-watercolor-coral opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
                  <Upload className="w-5 h-5 relative z-10 group-hover:animate-bounce-subtle" />
                  <span className="relative z-10">Start Security Review</span>
                  <ArrowRight className="w-5 h-5 relative z-10 group-hover:translate-x-1 transition-transform" />
                </motion.button>
              </Link>
              
              <motion.button
                onClick={() => setShowSettings(true)}
                whileHover={{ scale: 1.05, borderColor: 'hsl(5 64% 69% / 0.5)' }}
                whileTap={{ scale: 0.95 }}
                className="group flex items-center gap-2 px-8 py-4 rounded-2xl glass font-semibold border-2 border-transparent hover:border-watercolor-coral/30 transition-all duration-300"
              >
                <Settings className="w-5 h-5 group-hover:rotate-90 transition-transform duration-500" />
                Configure AI Provider
              </motion.button>
            </motion.div>
          </motion.div>

          {/* Methodology Cards - Consistent with Settings Modal */}
          <motion.div
            initial={{ opacity: 0, y: 40 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.4, duration: 0.8 }}
            className="mt-20 grid md:grid-cols-3 gap-5 max-w-6xl mx-auto"
          >
            {/* STRIDE Card */}
            <motion.div 
              whileHover={{ scale: 1.02 }}
              className="relative p-6 rounded-3xl border-2 border-border hover:border-blue-500/50 bg-background/50 backdrop-blur-sm transition-all overflow-hidden group"
            >
              <div className="absolute top-0 right-0 w-28 h-28 bg-gradient-to-br from-blue-500/20 to-cyan-500/20 rounded-full blur-3xl group-hover:scale-150 transition-transform" />
              <div className="relative">
                <div className="flex items-center gap-3 mb-3">
                  <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-blue-500 to-cyan-500 flex items-center justify-center">
                    <Shield className="w-5 h-5 text-white" />
                  </div>
                  <div>
                    <h3 className="text-lg font-bold">STRIDE</h3>
                    <p className="text-xs text-muted-foreground">Microsoft's methodology</p>
                  </div>
                </div>
                <p className="text-sm text-muted-foreground mb-3">
                  Systematic threat categorization for comprehensive security analysis
                </p>
                <div className="flex flex-wrap gap-1">
                  {['Spoofing', 'Tampering', 'Repudiation', 'Info Disclosure', 'DoS', 'Elevation'].map((cat) => (
                    <span key={cat} className="px-2 py-0.5 rounded-full bg-blue-500/10 text-blue-600 dark:text-blue-400 text-[10px] font-medium">
                      {cat}
                    </span>
                  ))}
                </div>
              </div>
            </motion.div>

            {/* PASTA Card */}
            <motion.div 
              whileHover={{ scale: 1.02 }}
              className="relative p-6 rounded-3xl border-2 border-border hover:border-purple-500/50 bg-background/50 backdrop-blur-sm transition-all overflow-hidden group"
            >
              <div className="absolute top-0 right-0 w-28 h-28 bg-gradient-to-br from-purple-500/20 to-pink-500/20 rounded-full blur-3xl group-hover:scale-150 transition-transform" />
              <div className="relative">
                <div className="flex items-center gap-3 mb-3">
                  <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-purple-500 to-pink-500 flex items-center justify-center">
                    <Target className="w-5 h-5 text-white" />
                  </div>
                  <div>
                    <h3 className="text-lg font-bold">PASTA</h3>
                    <p className="text-xs text-muted-foreground">Risk-centric approach</p>
                  </div>
                </div>
                <p className="text-sm text-muted-foreground mb-3">
                  7-stage process with business alignment and attack simulation
                </p>
                <div className="flex flex-wrap gap-1">
                  {['Objectives', 'Scope', 'Decomposition', 'Threats', 'Vulns', 'Attacks', 'Risk'].map((stage) => (
                    <span key={stage} className="px-2 py-0.5 rounded-full bg-purple-500/10 text-purple-600 dark:text-purple-400 text-[10px] font-medium">
                      {stage}
                    </span>
                  ))}
                </div>
              </div>
            </motion.div>

            {/* MAESTRO Card */}
            <motion.div 
              whileHover={{ scale: 1.02 }}
              className="relative p-6 rounded-3xl border-2 border-border hover:border-orange-500/50 bg-background/50 backdrop-blur-sm transition-all overflow-hidden group"
            >
              <div className="absolute top-0 right-0 w-28 h-28 bg-gradient-to-br from-orange-500/20 to-red-500/20 rounded-full blur-3xl group-hover:scale-150 transition-transform" />
              <span className="absolute top-3 right-3 px-2 py-0.5 rounded text-[9px] font-bold uppercase bg-gradient-to-r from-orange-500 to-red-500 text-white">
                Agentic AI
              </span>
              <div className="relative">
                <div className="flex items-center gap-3 mb-3">
                  <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-orange-500 to-red-500 flex items-center justify-center">
                    <Bot className="w-5 h-5 text-white" />
                  </div>
                  <div>
                    <h3 className="text-lg font-bold">MAESTRO</h3>
                    <p className="text-xs text-muted-foreground">CSA's AI framework</p>
                  </div>
                </div>
                <p className="text-sm text-muted-foreground mb-3">
                  Multi-agent threat modeling for AI-powered systems
                </p>
                <div className="flex flex-wrap gap-1">
                  {['Autonomous', 'Multi-Agent', 'Tool Abuse', 'Memory', 'Goals', 'LLM Trust'].map((cat) => (
                    <span key={cat} className="px-2 py-0.5 rounded-full bg-orange-500/10 text-orange-600 dark:text-orange-400 text-[10px] font-medium">
                      {cat}
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
          className="mx-auto max-w-4xl p-8 rounded-3xl border-2 border-watercolor-coral/20 bg-gradient-to-br from-watercolor-coral/5 via-watercolor-pink/5 to-watercolor-blush/5 relative overflow-hidden group"
        >
          {/* Animated background gradient */}
          <div className="absolute inset-0 bg-gradient-to-r from-watercolor-coral/10 via-transparent to-watercolor-blue/10 opacity-0 group-hover:opacity-100 transition-opacity duration-700" />
          
          <div className="flex flex-col md:flex-row items-center gap-6 relative z-10">
            <motion.div 
              whileHover={{ rotate: [0, -10, 10, -5, 5, 0] }}
              transition={{ duration: 0.5 }}
              className="w-20 h-20 rounded-2xl bg-gradient-to-br from-watercolor-coral to-watercolor-pink flex items-center justify-center shrink-0 shadow-lg shadow-watercolor-coral/20"
            >
              <Bot className="w-10 h-10 text-white" />
            </motion.div>
            <div className="flex-1 text-center md:text-left">
              <h2 className="text-2xl font-bold mb-2 bg-gradient-to-r from-watercolor-coral to-watercolor-blue bg-clip-text text-transparent">Security Review Agent</h2>
              <p className="text-muted-foreground mb-4">
                No documentation? Consult our AI Security Agent. Describe your system architecture in plain English, 
                share code snippets, and receive a comprehensive threat model through intelligent conversation.
              </p>
              <Link href="/ai-architect">
                <motion.button
                  whileHover={{ scale: 1.02, x: 5 }}
                  whileTap={{ scale: 0.98 }}
                  className="group/btn inline-flex items-center gap-2 px-6 py-3 rounded-xl bg-gradient-to-r from-watercolor-slate to-watercolor-blue text-white font-medium relative overflow-hidden"
                >
                  <span className="absolute inset-0 bg-gradient-to-r from-watercolor-blue to-watercolor-slate opacity-0 group-hover/btn:opacity-100 transition-opacity duration-300" />
                  <MessageSquare className="w-5 h-5 relative z-10" />
                  <span className="relative z-10">Start Consultation</span>
                  <ArrowRight className="w-4 h-4 relative z-10 group-hover/btn:translate-x-1 transition-transform" />
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
                  className="relative p-6 rounded-2xl border-2 border-border hover:border-primary/30 bg-background/50 backdrop-blur-sm transition-all group"
                >
                  {'badge' in feature && feature.badge && (
                    <span className="absolute top-3 right-3 px-2 py-0.5 rounded-full text-[10px] font-bold uppercase bg-gradient-to-r from-orange-500 to-red-500 text-white">
                      {feature.badge}
                    </span>
                  )}
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
              { name: 'Ollama', color: 'from-watercolor-coral to-watercolor-pink' },
              { name: 'OpenRouter', color: 'from-watercolor-slate to-watercolor-blue' },
              { name: 'OpenAI', color: 'from-green-500 to-emerald-600' },
              { name: 'Claude', color: 'from-watercolor-coral to-orange-500' },
              { name: 'Gemini', color: 'from-watercolor-blue to-cyan-600' },
              { name: 'LM Studio', color: 'from-watercolor-slate to-watercolor-coral' },
            ].map(provider => (
              <motion.button 
                key={provider.name}
                onClick={() => setShowSettings(true)}
                whileHover={{ scale: 1.05, y: -2 }}
                whileTap={{ scale: 0.98 }}
                className="flex items-center gap-2 px-4 py-2 rounded-xl border border-border bg-muted/50 hover:border-watercolor-coral/50 hover:bg-watercolor-coral/5 transition-colors cursor-pointer"
              >
                <div className={`w-2 h-2 rounded-full bg-gradient-to-r ${provider.color}`} />
                <span className="text-sm font-medium">{provider.name}</span>
              </motion.button>
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
          className="mx-auto max-w-4xl p-12 rounded-3xl bg-gradient-to-br from-watercolor-coral/10 via-watercolor-pink/10 to-watercolor-blush/10 border-2 border-watercolor-coral/20 text-center relative overflow-hidden"
        >
          {/* Animated orbs */}
          <div className="absolute top-0 left-0 w-64 h-64 bg-watercolor-coral/20 rounded-full blur-3xl animate-float" />
          <div className="absolute bottom-0 right-0 w-64 h-64 bg-watercolor-blue/20 rounded-full blur-3xl animate-float" style={{ animationDelay: '-3s' }} />
          
          <div className="relative z-10">
            <motion.div 
              whileHover={{ rotate: 360 }}
              transition={{ duration: 0.8 }}
              className="w-20 h-20 rounded-2xl bg-gradient-to-br from-watercolor-coral to-watercolor-pink flex items-center justify-center mx-auto mb-6 shadow-lg shadow-watercolor-coral/30"
            >
              <Zap className="w-10 h-10 text-white" />
            </motion.div>
            <h2 className="heading-md mb-4">Ready to Secure Your Application?</h2>
            <p className="body-lg max-w-xl mx-auto mb-8">
              Start your security review now and get actionable insights in minutes
            </p>
            <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
              <Link href="/upload">
                <motion.button
                  whileHover={{ scale: 1.05, boxShadow: '0 20px 40px -10px hsl(5 64% 69% / 0.4)' }}
                  whileTap={{ scale: 0.95 }}
                  className="group flex items-center gap-2 px-8 py-4 rounded-2xl bg-gradient-to-r from-watercolor-coral to-watercolor-pink text-white font-semibold shadow-xl shadow-watercolor-coral/25 relative overflow-hidden"
                >
                  <span className="absolute inset-0 bg-gradient-to-r from-watercolor-pink to-watercolor-coral opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
                  <Upload className="w-5 h-5 relative z-10" />
                  <span className="relative z-10">Analyze Documents</span>
                </motion.button>
              </Link>
              <Link href="/ai-architect">
                <motion.button
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                  className="group flex items-center gap-2 px-8 py-4 rounded-2xl glass font-semibold border-2 border-transparent hover:border-watercolor-coral/30 transition-all"
                >
                  <Bot className="w-5 h-5 group-hover:animate-wiggle" />
                  Consult AI Agent
                </motion.button>
              </Link>
            </div>
          </div>
        </motion.div>
      </section>

      {/* Footer */}
      <footer className="relative px-4 sm:px-6 lg:px-8 py-12 border-t border-border/50">
        <div className="mx-auto max-w-7xl flex flex-col sm:flex-row items-center justify-between gap-4">
          <motion.div 
            initial={{ opacity: 0, x: -20 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true }}
            className="flex items-center gap-2"
          >
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-watercolor-coral to-watercolor-pink flex items-center justify-center shadow-md shadow-watercolor-coral/20">
              <Shield className="w-4 h-4 text-white" />
            </div>
            <span className="font-semibold bg-gradient-to-r from-watercolor-coral to-watercolor-blue bg-clip-text text-transparent">PadmaVue.ai</span>
          </motion.div>
          <motion.div 
            initial={{ opacity: 0, y: 10 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="flex items-center gap-6"
          >
            <button 
              onClick={() => setShowSettings(true)}
              className="text-sm text-muted-foreground hover:text-watercolor-coral transition-colors duration-300"
            >
              Settings
            </button>
            <Link href="/ai-architect" className="text-sm text-muted-foreground hover:text-watercolor-coral transition-colors duration-300">
              Consult
            </Link>
            <Link href="/upload" className="text-sm text-muted-foreground hover:text-watercolor-coral transition-colors duration-300">
              Analyze
            </Link>
          </motion.div>
          <motion.p 
            initial={{ opacity: 0, x: 20 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true }}
            className="text-sm text-muted-foreground"
          >
            Built with <span className="text-watercolor-coral animate-pulse">❤️</span> for secure software development
          </motion.p>
        </div>
      </footer>

      {/* Settings Modal */}
      <SettingsModal isOpen={showSettings} onClose={() => setShowSettings(false)} />
    </div>
  );
}
