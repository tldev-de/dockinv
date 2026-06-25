/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ['./templates/**/*.{html,j2}'],
  plugins: [require('daisyui')],
  daisyui: {
    themes: ['night', 'light'],
  },
}
