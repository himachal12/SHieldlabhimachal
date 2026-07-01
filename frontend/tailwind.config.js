/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // ShieldLabs brand colors -- dark security theme
        primary: "#0f172a",      // deep navy background
        surface: "#1e293b",      // card/panel background
        accent: "#38bdf8",       // cyan accent (security tool vibe)
        danger: "#ef4444",       // red for critical
        warning: "#f59e0b",      // amber for high
        caution: "#eab308",      // yellow for medium
        safe: "#22c55e",         // green for low
        muted: "#64748b",        // gray for metadata
      }
    },
  },
  plugins: [],
}