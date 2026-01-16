'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Shield, 
  Upload, 
  FileSearch, 
  GitBranch, 
  BarChart3, 
  Menu, 
  X,
  Sparkles,
  Settings,
  Cpu
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { ThemeToggle, ThemeToggleCompact } from './theme-toggle';
import { SettingsModal } from './settings-modal';

const navItems = [
  { href: '/', label: 'Home', icon: Shield },
  { href: '/ai-architect', label: 'Consult', icon: Sparkles },
  { href: '/upload', label: 'Analyze', icon: Upload },
  { href: '/review', label: 'Threats', icon: FileSearch },
  { href: '/dfd', label: 'Flow Map', icon: GitBranch },
];

export function Navbar() {
  const pathname = usePathname();
  const [scrolled, setScrolled] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 20);
    };
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  return (
    <>
      <motion.header
        initial={{ y: -100 }}
        animate={{ y: 0 }}
        className={cn(
          'fixed top-0 left-0 right-0 z-50 transition-all duration-500',
          scrolled 
            ? 'py-2' 
            : 'py-4'
        )}
      >
        <nav className={cn(
          'mx-auto max-w-7xl px-4 sm:px-6 lg:px-8',
          'transition-all duration-500'
        )}>
          <div className={cn(
            'flex items-center justify-between rounded-2xl px-4 py-3',
            'transition-all duration-500',
            scrolled 
              ? 'glass-solid shadow-lg' 
              : 'bg-transparent'
          )}>
            {/* Logo */}
            <Link href="/" className="flex items-center gap-3 group">
              <motion.div 
                className="relative"
                whileHover={{ rotate: 360 }}
                transition={{ duration: 0.5 }}
              >
                <div className="absolute inset-0 bg-primary/30 blur-lg rounded-full" />
                <div className="relative w-10 h-10 rounded-xl bg-gradient-to-br from-primary to-purple-600 flex items-center justify-center">
                  <Shield className="w-5 h-5 text-white" />
                </div>
              </motion.div>
              <div className="hidden sm:block">
                <h1 className="font-bold text-lg tracking-tight">
                  SecurityReview
                  <span className="text-primary">.ai</span>
                </h1>
                <p className="text-xs text-muted-foreground -mt-0.5">
                  AI-Powered Threat Analysis
                </p>
              </div>
            </Link>

            {/* Desktop Navigation */}
            <div className="hidden md:flex items-center gap-1">
              {navItems.map((item) => {
                const isActive = pathname === item.href;
                const Icon = item.icon;
                
                return (
                  <Link key={item.href} href={item.href}>
                    <motion.div
                      className={cn(
                        'relative px-4 py-2 rounded-xl flex items-center gap-2',
                        'transition-colors duration-200',
                        isActive 
                          ? 'text-primary' 
                          : 'text-muted-foreground hover:text-foreground'
                      )}
                      whileHover={{ scale: 1.05 }}
                      whileTap={{ scale: 0.95 }}
                    >
                      {isActive && (
                        <motion.div
                          layoutId="nav-active"
                          className="absolute inset-0 bg-primary/10 rounded-xl"
                          transition={{ type: 'spring', bounce: 0.25, duration: 0.4 }}
                        />
                      )}
                      <Icon className="w-4 h-4 relative z-10" />
                      <span className="text-sm font-medium relative z-10">{item.label}</span>
                    </motion.div>
                  </Link>
                );
              })}
            </div>

            {/* Right side */}
            <div className="flex items-center gap-3">
              {/* Settings Button */}
              <motion.button
                onClick={() => setSettingsOpen(true)}
                whileHover={{ scale: 1.05, rotate: 15 }}
                whileTap={{ scale: 0.95 }}
                className="p-2 rounded-xl glass hover:bg-muted/50 transition-colors"
                title="LLM Settings"
              >
                <Settings className="w-5 h-5" />
              </motion.button>
              
              <div className="hidden sm:block">
                <ThemeToggle />
              </div>
              
              <Link href="/upload">
                <motion.button
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                  className="hidden sm:flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-primary to-purple-600 text-white font-medium text-sm shadow-lg shadow-primary/25"
                >
                  <Sparkles className="w-4 h-4" />
                  Start Analysis
                </motion.button>
              </Link>

              {/* Mobile menu button */}
              <motion.button
                className="md:hidden p-2 rounded-xl glass"
                onClick={() => setMobileOpen(!mobileOpen)}
                whileTap={{ scale: 0.95 }}
              >
                <AnimatePresence mode="wait">
                  <motion.div
                    key={mobileOpen ? 'close' : 'menu'}
                    initial={{ opacity: 0, rotate: -90 }}
                    animate={{ opacity: 1, rotate: 0 }}
                    exit={{ opacity: 0, rotate: 90 }}
                    transition={{ duration: 0.2 }}
                  >
                    {mobileOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
                  </motion.div>
                </AnimatePresence>
              </motion.button>
            </div>
          </div>
        </nav>
      </motion.header>

      {/* Mobile Navigation */}
      <AnimatePresence>
        {mobileOpen && (
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="fixed inset-0 z-40 pt-24 md:hidden"
          >
            <div 
              className="absolute inset-0 bg-background/80 backdrop-blur-xl" 
              onClick={() => setMobileOpen(false)}
            />
            <motion.nav 
              className="relative mx-4 p-4 rounded-2xl glass-solid shadow-xl"
              initial={{ scale: 0.95 }}
              animate={{ scale: 1 }}
              exit={{ scale: 0.95 }}
            >
              <div className="space-y-2">
                {navItems.map((item, index) => {
                  const isActive = pathname === item.href;
                  const Icon = item.icon;
                  
                  return (
                    <motion.div
                      key={item.href}
                      initial={{ opacity: 0, x: -20 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: index * 0.05 }}
                    >
                      <Link
                        href={item.href}
                        onClick={() => setMobileOpen(false)}
                        className={cn(
                          'flex items-center gap-3 px-4 py-3 rounded-xl',
                          'transition-colors duration-200',
                          isActive 
                            ? 'bg-primary/10 text-primary' 
                            : 'hover:bg-muted'
                        )}
                      >
                        <Icon className="w-5 h-5" />
                        <span className="font-medium">{item.label}</span>
                      </Link>
                    </motion.div>
                  );
                })}
              </div>
              
              <div className="mt-4 pt-4 border-t border-border space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Theme</span>
                  <ThemeToggleCompact />
                </div>
                <button
                  onClick={() => {
                    setMobileOpen(false);
                    setSettingsOpen(true);
                  }}
                  className="w-full flex items-center gap-3 px-4 py-3 rounded-xl hover:bg-muted transition-colors"
                >
                  <Cpu className="w-5 h-5" />
                  <span className="font-medium">LLM Settings</span>
                </button>
              </div>
            </motion.nav>
          </motion.div>
        )}
      </AnimatePresence>
      
      {/* Settings Modal */}
      <SettingsModal isOpen={settingsOpen} onClose={() => setSettingsOpen(false)} />
    </>
  );
}
