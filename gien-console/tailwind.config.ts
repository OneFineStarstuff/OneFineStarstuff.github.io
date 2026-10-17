import type { Config } from "tailwindcss";

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        navy: {
          950: "#07101e",
          900: "#0b1728",
          800: "#14253b"
        },
        teal: {
          300: "#7ce9d3",
          400: "#46d3ba",
          500: "#20b59e"
        }
      },
      boxShadow: {
        panel: "0 18px 50px rgba(1, 9, 20, 0.22)"
      }
    }
  },
  plugins: []
} satisfies Config;
