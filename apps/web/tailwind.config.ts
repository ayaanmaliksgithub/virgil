import type { Config } from "tailwindcss";

/**
 * Forensic-memory aesthetic. Warm-ink background, phosphor-bone foreground.
 * Two mono faces, no serifs anywhere in the product chrome.
 */
const config: Config = {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: {
          DEFAULT: "#0B0B0A",  // CRT-deep, slightly warm
          50:  "#121211",      // surface
          100: "#171715",      // raised
          200: "#1D1C19",      // sunk
          300: "#27241F",      // hairline
          400: "#383530",      // strong border
        },
        bone: {
          DEFAULT: "#D9D3C2",  // primary text — slightly desaturated paper
          dim:     "#B4AE9F",
          mute:    "#8C8779",
          ghost:   "#5E5A52",
          fog:     "#3F3C36",
        },
        signal: {
          critical: "#E0432A",
          high:     "#D89B3A",
          medium:   "#A6995A",
          low:      "#6F8479",
          info:     "#4F6377",
          // live / cursor / active accent — a warm phosphor that won't read as "cyberpunk neon"
          live:     "#E8C26A",
          cream:    "#D9CBA4",  // legacy alias kept for unchanged components
        },
      },
      fontFamily: {
        mono:    ["var(--font-mono)", "ui-monospace", "monospace"],
        display: ["var(--font-display)", "var(--font-mono)", "ui-monospace", "monospace"],
        body:    ["var(--font-mono)", "ui-monospace", "monospace"],
      },
      letterSpacing: {
        wider2: "0.10em",
        widest2: "0.18em",
      },
      backgroundImage: {
        // Scanlines — drawn from a 3px sprite so they tile cheaply on any DPR.
        "scanlines":
          "repeating-linear-gradient(to bottom, rgba(0,0,0,0) 0, rgba(0,0,0,0) 2px, rgba(0,0,0,0.22) 2px, rgba(0,0,0,0.22) 3px)",
        // Subtle grain on top of scanlines so the screen feels analog, not pixel-perfect
        "grain":
          "url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='160' height='160'><filter id='n'><feTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='2' stitchTiles='stitch'/><feColorMatrix values='0 0 0 0 0.85 0 0 0 0 0.82 0 0 0 0 0.76 0 0 0 0.07 0'/></filter><rect width='100%' height='100%' filter='url(%23n)'/></svg>\")",
      },
      animation: {
        "cursor": "cursor 1.05s steps(2) infinite",
        "tick":   "tick 1.6s linear infinite",
        "scanjitter": "scanjitter 7s ease-in-out infinite",
      },
      keyframes: {
        cursor: { "0%,49%": { opacity: "1" }, "50%,100%": { opacity: "0" } },
        tick: {
          "0%": { transform: "translateX(0)" },
          "100%": { transform: "translateX(-100%)" },
        },
        scanjitter: {
          "0%, 100%": { transform: "translateY(0)" },
          "47%":      { transform: "translateY(0)" },
          "50%":      { transform: "translateY(1px)" },
          "53%":      { transform: "translateY(0)" },
        },
      },
    },
  },
  plugins: [],
};
export default config;
