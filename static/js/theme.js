let themeToggle = null;
let iconSun = null;
let iconMoon = null;

const THEMES = {
  dark: 'ayu-mirage',
  light: 'base16-light'
};

function cacheElements() {
  if (!themeToggle) themeToggle = document.getElementById('theme-toggle');
  if (!iconSun) iconSun = document.getElementById('icon-sun');
  if (!iconMoon) iconMoon = document.getElementById('icon-moon');
}

/**
 * apply theme to document and update icon visibility, save preference
 * @param {string} theme - 'dark' or 'light'
 */
function setTheme(theme) {
  cacheElements();

  document.documentElement.setAttribute('data-theme', theme);

  if (theme === 'dark') {
    if (iconSun) iconSun.style.display = 'inline';
    if (iconMoon) iconMoon.style.display = 'none';
  } else {
    if (iconSun) iconSun.style.display = 'none';
    if (iconMoon) iconMoon.style.display = 'inline';
  }

  localStorage.setItem('theme', theme);

  // dispatch a custom event to notify theme change
  const event = new CustomEvent('themeChange', { detail: { theme } });
  document.dispatchEvent(event);
}

/**
 * toggle between dark and light themes
 */
function toggleTheme() {
  const currentTheme = document.documentElement.getAttribute('data-theme') || 'light';
  const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
  setTheme(newTheme);
}

/**
 * initialize toggle button listener and apply saved or default theme
 */
function initializeThemeToggle() {
  cacheElements();
  if (!themeToggle) {
    console.warn('Theme toggle button not found!');
    return;
  }

  themeToggle.addEventListener('click', toggleTheme);

  const savedTheme = localStorage.getItem('theme') || 'light';
  setTheme(savedTheme);
}

export { setTheme, toggleTheme, initializeThemeToggle, THEMES };

if (typeof module === 'undefined') {
  document.addEventListener('DOMContentLoaded', () => initializeThemeToggle());
}