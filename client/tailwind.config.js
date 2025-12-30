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
        // Spendly Brand Colors (from logo)
        brand: {
          blue: '#2563EB',      // Deep blue from logo
          teal: '#0891B2',      // Teal from wallet
          green: '#059669',     // Green from logo text
          orange: '#F59E0B',    // Orange from coin
          gradient: {
            start: '#0891B2',   // Teal
            middle: '#059669',  // Green  
            end: '#2563EB'      // Blue
          }
        },
        
        // Primary (Blue-Green gradient style)
        primary: {
          50: '#ecfeff',
          100: '#cffafe', 
          200: '#a5f3fc',
          300: '#67e8f9',
          400: '#22d3ee',
          500: '#0891B2',      // Main brand teal
          600: '#0e7490',
          700: '#155e75',
          800: '#164e63',
          900: '#083344',
        },
        
        // Secondary (Soft green for positive)
        secondary: {
          50: '#f0fdf4',
          100: '#dcfce7',
          200: '#bbf7d0', 
          300: '#86efac',
          400: '#4ade80',
          500: '#059669',      // Brand green
          600: '#16a34a',
          700: '#15803d',
          800: '#166534',
          900: '#14532d',
        },
        
        // Accent (Orange for highlights)
        accent: {
          50: '#fffbeb',
          100: '#fef3c7',
          200: '#fde68a',
          300: '#fcd34d', 
          400: '#fbbf24',
          500: '#F59E0B',      // Brand orange
          600: '#d97706',
          700: '#b45309',
          800: '#92400e',
          900: '#78350f',
        },
        
        // Danger (Red/Orange for low balance)
        danger: {
          50: '#fef2f2',
          100: '#fee2e2',
          200: '#fecaca',
          300: '#fca5a5',
          400: '#f87171',
          500: '#ef4444',
          600: '#dc2626',
          700: '#b91c1c',
          800: '#991b1b',
          900: '#7f1d1d',
        },
        
        // Success (Green for positive actions)
        success: {
          50: '#f0fdf4',
          100: '#dcfce7', 
          200: '#bbf7d0',
          300: '#86efac',
          400: '#4ade80',
          500: '#22c55e',
          600: '#16a34a',
          700: '#15803d',
          800: '#166534',
          900: '#14532d',
        },
        
        // Warning (Yellow for alerts)
        warning: {
          50: '#fffbeb',
          100: '#fef3c7',
          200: '#fde68a',
          300: '#fcd34d',
          400: '#fbbf24', 
          500: '#f59e0b',
          600: '#d97706',
          700: '#b45309',
          800: '#92400e',
          900: '#78350f',
        }
      },
      
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        display: ['Inter', 'system-ui', 'sans-serif'],
      },
      
      backgroundImage: {
        'gradient-brand': 'linear-gradient(135deg, #0891B2 0%, #059669 50%, #2563EB 100%)',
        'gradient-card': 'linear-gradient(135deg, #f8fafc 0%, #f1f5f9 100%)',
        'gradient-dark-card': 'linear-gradient(135deg, #1e293b 0%, #0f172a 100%)',
      },
      
      boxShadow: {
        'brand': '0 4px 14px 0 rgba(8, 145, 178, 0.15)',
        'card': '0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px 0 rgba(0, 0, 0, 0.06)',
        'card-hover': '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)',
      },
      
      animation: {
        'balance-update': 'pulse 0.5s ease-in-out',
        'slide-up': 'slideUp 0.3s ease-out',
        'fade-in': 'fadeIn 0.2s ease-out',
      },
      
      keyframes: {
        slideUp: {
          '0%': { transform: 'translateY(10px)', opacity: '0' },
          '100%': { transform: 'translateY(0)', opacity: '1' },
        },
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        }
      }
    },
  },
  plugins: [],
}