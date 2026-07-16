/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'IBM Plex Mono', 'ui-monospace', 'SFMono-Regular', 'monospace'],
      },
      colors: {
        // Legacy aliases kept so existing components continue to work unchanged.
        primary: "#050a12",
        surface: "#101827",
        accent: "#38bdf8",
        danger: "#f43f5e",
        warning: "#f97316",
        caution: "#f59e0b",
        safe: "#22c55e",
        muted: "#94a3b8",

        // Enterprise cybersecurity design tokens.
        cyber: {
          50: "#f8fafc",
          100: "#e2e8f0",
          200: "#cbd5e1",
          300: "#94a3b8",
          400: "#64748b",
          500: "#475569",
          600: "#334155",
          700: "#223047",
          800: "#162033",
          850: "#101827",
          900: "#0b1220",
          950: "#050a12",
        },
        brand: {
          cyan: "#38bdf8",
          blue: "#2563eb",
          violet: "#8b5cf6",
          teal: "#14b8a6",
        },
        severity: {
          critical: "#f43f5e",
          high: "#f97316",
          medium: "#f59e0b",
          low: "#22c55e",
          info: "#38bdf8",
        },
      },
      boxShadow: {
        panel: "0 18px 50px -28px rgba(0, 0, 0, 0.75)",
        popover: "0 24px 70px -30px rgba(0, 0, 0, 0.85)",
        'glow-cyan': "0 0 0 1px rgba(56, 189, 248, 0.18), 0 0 32px -18px rgba(56, 189, 248, 0.9)",
        'glow-critical': "0 0 0 1px rgba(244, 63, 94, 0.2), 0 0 36px -18px rgba(244, 63, 94, 0.9)",
      },
      borderRadius: {
        '2xl': '1.25rem',
        '3xl': '1.75rem',
      },
      backgroundImage: {
        'cyber-radial': 'radial-gradient(circle at top left, rgba(56, 189, 248, 0.12), transparent 32rem), radial-gradient(circle at top right, rgba(139, 92, 246, 0.1), transparent 28rem)',
        'panel-gradient': 'linear-gradient(145deg, rgba(16, 24, 39, 0.96), rgba(11, 18, 32, 0.98))',
      },
      transitionTimingFunction: {
        enterprise: 'cubic-bezier(0.16, 1, 0.3, 1)',
      },
    },
  },
  plugins: [],
}
