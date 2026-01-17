import type { Metadata } from 'next';
import { Space_Grotesk, JetBrains_Mono } from 'next/font/google';
import './globals.css';
import { Providers } from './providers';
import { Navbar } from '@/components/navbar';

const spaceGrotesk = Space_Grotesk({
  subsets: ['latin'],
  variable: '--font-sans',
  display: 'swap',
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ['latin'],
  variable: '--font-mono',
  display: 'swap',
});

export const metadata: Metadata = {
  title: 'PadmaVue.ai - AI-Powered Threat Modeling',
  description: 'Advanced security analysis platform with STRIDE & PASTA threat modeling, compliance mapping, and DevSecOps rule generation.',
  keywords: ['security', 'threat modeling', 'STRIDE', 'PASTA', 'DREAD', 'compliance', 'DevSecOps'],
  authors: [{ name: 'PadmaVue.ai' }],
  openGraph: {
    title: 'PadmaVue.ai',
    description: 'AI-Powered Threat Modeling Platform',
    type: 'website',
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className={`${spaceGrotesk.variable} ${jetbrainsMono.variable} font-sans antialiased`}>
        <Providers>
          {/* Background effects */}
          <div className="fixed inset-0 -z-10 overflow-hidden">
            {/* Grid */}
            <div className="absolute inset-0 bg-grid opacity-50" />
            
            {/* Gradient orbs */}
            <div className="blur-orb blur-orb-primary w-[600px] h-[600px] -top-[300px] -left-[200px]" />
            <div className="blur-orb blur-orb-secondary w-[500px] h-[500px] top-1/2 -right-[200px]" />
            <div className="blur-orb blur-orb-primary w-[400px] h-[400px] bottom-0 left-1/3" />
            
            {/* Noise overlay */}
            <div className="absolute inset-0 noise-overlay" />
          </div>
          
          {/* Main content */}
          <Navbar />
          <main className="relative min-h-screen pt-24">
            {children}
          </main>
        </Providers>
      </body>
    </html>
  );
}
