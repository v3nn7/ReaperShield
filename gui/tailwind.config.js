/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        enterprise: {
          950: "#0b0f19", // Deep dark background
          900: "#111827", // Accent dark
          800: "#1f2937", // Card background
          700: "#374151", // Borders
          600: "#4b5563",
          100: "#f3f4f6", // Primary text
          200: "#e5e7eb", // Secondary text
        },
      },
    },
  },
  plugins: [],
}
