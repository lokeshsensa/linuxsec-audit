/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        soc: {
          bg: '#0a0d14',
          card: '#111726',
          border: '#1e293b',
          accent: '#3b82f6',
          highlight: '#1e293b',
        },
      },
    },
  },
  plugins: [],
}
