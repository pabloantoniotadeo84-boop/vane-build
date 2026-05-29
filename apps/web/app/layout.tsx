import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'Counsel — Attestation Dashboard',
  description: 'Live attestation chain monitor',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-[#0a0c10] text-[#e6edf3]">{children}</body>
    </html>
  );
}
