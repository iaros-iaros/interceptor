// Shared by the app and the docs page so a theme choice carries across both.
// Before an explicit choice is made we follow the OS setting.

const KEY = "interceptor-theme";

function apply(theme) {
  document.documentElement.dataset.theme = theme;
}

export function initTheme() {
  const stored = localStorage.getItem(KEY);
  if (stored === "light" || stored === "dark") return apply(stored);
  apply(matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
}

export function currentTheme() {
  return document.documentElement.dataset.theme === "light" ? "light" : "dark";
}

export function toggleTheme() {
  const next = currentTheme() === "light" ? "dark" : "light";
  localStorage.setItem(KEY, next);
  apply(next);
  return next;
}

initTheme();
