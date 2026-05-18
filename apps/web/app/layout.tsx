import type { Metadata } from "next";
import { JetBrains_Mono, IBM_Plex_Mono } from "next/font/google";
import "./globals.css";
import { SiteFrame } from "@/components/site-frame";

/**
 * Aesthetic: forensic memory tool. Mono is the primary face. A second mono
 * (Plex Mono) carries any display moments — distinct cut, slightly more
 * editorial, but still mono so the whole product reads as one machine.
 */
const mono = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-mono",
  weight: ["300", "400", "500", "700"],
  display: "swap",
});

const display = IBM_Plex_Mono({
  subsets: ["latin"],
  variable: "--font-display",
  weight: ["400", "500", "600", "700"],
  style: ["normal", "italic"],
  display: "swap",
});

export const metadata: Metadata = {
  title: "cipher_audit ─ static analysis & risk register",
  description:
    "Evidence-first cybersecurity audit. Not an exploit toolkit. Read the surface, never the keys.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${mono.variable} ${display.variable}`}>
      <body className="min-h-dvh">
        <SiteFrame>{children}</SiteFrame>
      </body>
    </html>
  );
}
