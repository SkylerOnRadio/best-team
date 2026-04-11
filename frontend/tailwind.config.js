/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      boxShadow: {
        glow: "0 24px 80px rgba(15, 23, 42, 0.28)",
      },
      colors: {
        ink: {
          950: "#07111f",
          900: "#0b1726",
          800: "#12233a",
        },
      },
    },
  },
  plugins: [],
};
