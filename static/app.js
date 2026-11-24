/* ==============================================================================
 * CyberDesk Client-Side UI Helpers
 * Used by: ALL environments (executed in the user's browser)
 *
 * Loaded via: templates/base.html -> <script src="/static/app.js" defer></script>
 *
 * Why `defer` matters:
 *   Because the <script> tag is in <head>, `defer` tells the browser to download
 *   this file in parallel with HTML parsing and execute it ONLY AFTER the DOM
 *   is completely built—so `document.querySelectorAll(...)` finds every element
 *   without needing a `DOMContentLoaded` wrapper.
 *
 * Why there is no inline JavaScript in HTML templates:
 *   app.py enforces `Content-Security-Policy: script-src 'self'`, which blocks
 *   inline `onclick` / `onsubmit` attributes. Instead, HTML elements declare
 *   intent via `data-*` attributes and CSS classes, and this file attaches
 *   event listeners cleanly.
 * ============================================================================== */

// Enable JavaScript strict mode: catches silent bugs (like accidental global
// variables) and enforces cleaner runtime behavior.
'use strict';

// ------------------------------------------------------------------------------
// 1. DESTRUCTIVE ACTION CONFIRMATIONS (e.g., Delete Report / Delete Comment)
// ------------------------------------------------------------------------------
// Targets any <form data-confirm="Usunąć zgłoszenie?"> in templates/report.html.
// When the user clicks the submit button, this intercepts the `submit` event:
//   - Shows the browser's native confirmation dialog with the message from
//     `form.dataset.confirm`.
//   - If the user clicks "Cancel", `event.preventDefault()` cancels the HTTP
//     POST request before it ever leaves the browser.
document.querySelectorAll('[data-confirm]').forEach(form => {
  form.addEventListener('submit', event => {
    if (!window.confirm(form.dataset.confirm)) event.preventDefault();
  });
});

// ------------------------------------------------------------------------------
// 2. FLASH NOTIFICATION DISMISSAL
// ------------------------------------------------------------------------------
// Targets the "×" close button inside Flask flash banners in templates/base.html
// (`<div class="flash">...<button class="dismiss-flash">×</button></div>`).
// Clicking the button walks up the DOM to the nearest `.flash` container and
// removes it safely (`?.` prevents a TypeError if no `.flash` ancestor exists).
document.querySelectorAll('.dismiss-flash').forEach(button => {
  button.addEventListener('click', () => button.closest('.flash')?.remove());
});

// ------------------------------------------------------------------------------
// 3. PASSWORD VISIBILITY TOGGLE (Login & Registration Forms)
// ------------------------------------------------------------------------------
// Targets the eye-icon button next to the password input in templates/auth.html:
//   <button type="button" class="password-toggle" data-target="password">
// Clicking toggles the linked <input> between `type="password"` (masked) and
// `type="text"` (visible), and updates ARIA attributes (`aria-label` and
// `aria-pressed`) so screen readers announce the current state accurately.
document.querySelectorAll('.password-toggle').forEach(button => {
  button.addEventListener('click', () => {
    const field = document.getElementById(button.dataset.target);
    if (!field) return; // Null-safety guard if data-target ID is missing/mismatched
    const show = field.type === 'password';
    field.type = show ? 'text' : 'password';
    button.setAttribute('aria-label', show ? 'Ukryj hasło' : 'Pokaż hasło');
    button.setAttribute('aria-pressed', String(show));
  });
});

















