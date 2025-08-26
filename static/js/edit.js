import { THEMES, initializeThemeToggle } from './theme.js';

let editorContent;
let editorCSS;

/**
 * apply theme to CodeMirror editors
 * @param {string} theme - 'dark' or 'light'
 */
function applyEditorTheme(theme) {
  const editorTheme = THEMES[theme] || THEMES.light;
  if (editorContent) {
    editorContent.setOption('theme', editorTheme);
  }
  if (editorCSS) {
    editorCSS.setOption('theme', editorTheme);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  const preview = document.querySelector('#edit-preview');
  const fullPreviewIframe = document.querySelector('#full-preview-iframe');
  if (!preview || !fullPreviewIframe) return;

  const savedTheme = localStorage.getItem('theme') || 'light';
  const initialTheme = THEMES[savedTheme] || THEMES.light;

  // initialize CodeMirror editors
  editorContent = CodeMirror.fromTextArea(document.getElementById('edit-textarea'), {
    lineNumbers: true,
    mode: 'htmlmixed',
    theme: initialTheme,
    indentUnit: 2,
    tabSize: 2,
    lineWrapping: true,
    scrollbarStyle: 'null',
    matchBrackets: true,
    autoRefresh: true,
  });

  editorCSS = CodeMirror.fromTextArea(document.getElementById('edit-cssarea'), {
    lineNumbers: true,
    mode: 'css',
    theme: initialTheme,
    indentUnit: 2,
    tabSize: 2,
    lineWrapping: true,
    scrollbarStyle: 'null',
    matchBrackets: true,
    autoRefresh: true,
  });

  // initialize theme toggle (site-wide)
  initializeThemeToggle();

  // listen for theme changes to update editors
  document.addEventListener('themeChange', (event) => {
    applyEditorTheme(event.detail.theme);
  });

  // tab switching
  const tabButtons = document.querySelectorAll('.tab-button');
  const tabContents = document.querySelectorAll('.tab-content');

  tabButtons.forEach((button) => {
    button.addEventListener('click', () => {
      const targetTab = button.dataset.tab;

      tabButtons.forEach((btn) => btn.classList.remove('tab-button--active'));
      button.classList.add('tab-button--active');

      tabContents.forEach((content) => {
        content.style.display = content.id === `${targetTab}-tab` ? 'block' : 'none';
      });

      if (targetTab === 'full-preview') {
        updateFullPreviewIframe();
      }
    });
  });

  // initial tab setup
  document.querySelector('.tab-button--active').click();

  // live preview update function
  function updateLivePreview() {
    if (!editorContent || !editorCSS) return;

    const html = editorContent.getValue();
    const css = `<style>${editorCSS.getValue()}</style>`;
    const preview = document.querySelector('#edit-preview');
    if (preview) {
      preview.innerHTML = css + html;
    }
  }

  // full preview iframe update
  function updateFullPreviewIframe() {
    if (!editorContent || !editorCSS) return;

    const iframe = document.querySelector('#full-preview-iframe');
    if (!iframe) return;

    const doc = iframe.contentDocument || iframe.contentWindow.document;
    const html = editorContent.getValue();
    const css = editorCSS.getValue();

    const parentStyles = Array.from(document.querySelectorAll('link[rel="stylesheet"]'))
      .map((link) => `<link rel="stylesheet" href="${link.href}">`)
      .join('\n');

    const themeScript = `
      <script>
        (function() {
          try {
            var theme = localStorage.getItem('theme') || 'light';
            document.documentElement.setAttribute('data-theme', theme);
          } catch(e) {}
        })();
      </script>
    `;

    const combinedCSS = `
      ${parentStyles}
      <style>${css}</style>
    `;

    doc.open();
    doc.write(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        ${themeScript}
        ${combinedCSS}
      </head>
      <body>
        <div class="text-container container-base">
          ${html}
        </div>
        <script>
          window.onload = function() {
            const content = document.querySelector('.text-container');
            const height = content.scrollHeight;
            window.parent.postMessage({ iframeHeight: height }, '*');
          };
        </script>
      </body>
      </html>
    `);
    doc.close();
  }

  // listen for height messages from the iframe
  window.addEventListener('message', (event) => {
    if (event.data.iframeHeight) {
      const iframe = document.querySelector('#full-preview-iframe');
      if (iframe) {
        iframe.style.height = `${event.data.iframeHeight}px`;
      }
    }
  });

  // attach change listeners to CodeMirror editors
  if (editorContent && editorCSS) {
    editorContent.on('change', updateLivePreview);
    editorCSS.on('change', updateLivePreview);
    updateLivePreview(); // initial render
  }

  // toggle meta inputs
  document.getElementById('toggle-meta').addEventListener('click', function () {
    const metaSection = document.getElementById('meta-section');
    if (metaSection.style.display === 'none') {
      metaSection.style.display = 'block';
      this.textContent = '-';
    } else {
      metaSection.style.display = 'none';
      this.textContent = '+';
    }
  });
});