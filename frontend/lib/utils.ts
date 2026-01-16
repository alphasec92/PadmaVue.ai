import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

/**
 * Merge class names with Tailwind CSS support
 * Combines clsx for conditional classes and tailwind-merge to avoid conflicts
 */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/**
 * Format a date string to a human-readable format
 */
export function formatDate(date: string | Date): string {
  const d = new Date(date);
  return d.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

/**
 * Format a risk score to a severity label
 */
export function riskToSeverity(risk: number): 'critical' | 'high' | 'medium' | 'low' {
  if (risk >= 8) return 'critical';
  if (risk >= 6) return 'high';
  if (risk >= 4) return 'medium';
  return 'low';
}

/**
 * Get color classes for a severity level
 */
export function getSeverityColors(severity: string): string {
  const colors: Record<string, string> = {
    critical: 'text-red-500 bg-red-500/10 border-red-500/30',
    high: 'text-orange-500 bg-orange-500/10 border-orange-500/30',
    medium: 'text-yellow-500 bg-yellow-500/10 border-yellow-500/30',
    low: 'text-green-500 bg-green-500/10 border-green-500/30',
  };
  return colors[severity] || colors.medium;
}

/**
 * Get STRIDE category color
 */
export function getStrideColor(category: string): string {
  const colors: Record<string, string> = {
    'Spoofing': 'stride-spoofing',
    'Tampering': 'stride-tampering',
    'Repudiation': 'stride-repudiation',
    'Information Disclosure': 'stride-disclosure',
    'Denial of Service': 'stride-dos',
    'Elevation of Privilege': 'stride-elevation',
  };
  
  // Check if category contains any of the keys
  for (const [key, value] of Object.entries(colors)) {
    if (category.includes(key)) return value;
  }
  return 'bg-muted text-muted-foreground';
}

/**
 * Truncate text to a maximum length
 */
export function truncate(text: string, maxLength: number): string {
  if (text.length <= maxLength) return text;
  return text.slice(0, maxLength - 3) + '...';
}

/**
 * Format file size to human-readable format
 */
export function formatFileSize(bytes: number): string {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

/**
 * Generate a random ID
 */
export function generateId(): string {
  return Math.random().toString(36).substring(2, 9);
}

/**
 * Delay execution for a specified time
 */
export function delay(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Debounce a function
 */
export function debounce<T extends (...args: any[]) => any>(
  func: T,
  wait: number
): (...args: Parameters<T>) => void {
  let timeout: NodeJS.Timeout | null = null;
  
  return function executedFunction(...args: Parameters<T>) {
    const later = () => {
      timeout = null;
      func(...args);
    };
    
    if (timeout) {
      clearTimeout(timeout);
    }
    timeout = setTimeout(later, wait);
  };
}
