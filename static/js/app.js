/**
 * ForenScan — Frontend JS
 * Drag-drop upload, hash copy, spinner guards, accessibility
 */

// ── Drag-drop ────────────────────────────────────────────────────────
const dropZone = document.getElementById('dropZone');
const fileInput = document.getElementById('fileInput');

if (dropZone && fileInput) {
  ['dragenter', 'dragover'].forEach(evt => {
    dropZone.addEventListener(evt, e => {
      e.preventDefault();
      dropZone.classList.add('dragover');
    });
  });

  ['dragleave', 'drop'].forEach(evt => {
    dropZone.addEventListener(evt, e => {
      e.preventDefault();
      dropZone.classList.remove('dragover');
    });
  });

  dropZone.addEventListener('drop', e => {
    const files = e.dataTransfer.files;
    if (files.length > 0) {
      fileInput.files = files;
      onFileSelected(fileInput);
    }
  });
}

function onFileSelected(input) {
  const label = document.getElementById('dropFileName');
  if (!label) return;
  if (input.files && input.files.length > 0) {
    const f = input.files[0];
    label.textContent = f.name + ' — ' + formatBytes(f.size);
    label.style.display = 'block';
  }
}

function formatBytes(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1048576).toFixed(1) + ' MB';
}

// ── Upload form spinner guard ────────────────────────────────────────
const uploadForm = document.getElementById('uploadForm');
if (uploadForm) {
  uploadForm.addEventListener('submit', function (e) {
    const file = fileInput && fileInput.files && fileInput.files.length > 0;
    if (!file) {
      e.preventDefault();
      showInlineError(uploadForm, 'Please select a file before scanning.');
      return;
    }
    const btn = document.getElementById('scanBtn');
    const spinner = document.getElementById('scanSpinner');
    if (btn) btn.style.display = 'none';
    if (spinner) spinner.style.display = 'inline-flex';
  });
}

// ── Directory form spinner guard — Bug 11 fix ────────────────────────
const dirForm = document.getElementById('dirForm');
if (dirForm) {
  dirForm.addEventListener('submit', function (e) {
    const dirpath = this.querySelector('[name="dirpath"]');
    if (!dirpath || !dirpath.value.trim()) {
      e.preventDefault();
      showInlineError(dirForm, 'Please enter a directory path.');
      return;
    }
    const btn = document.getElementById('dirScanBtn');
    const spinner = document.getElementById('dirSpinner');
    if (btn) btn.style.display = 'none';
    if (spinner) spinner.style.display = 'inline-flex';
  });
}

function showInlineError(form, msg) {
  // Remove any existing inline error
  const existing = form.querySelector('.inline-error');
  if (existing) existing.remove();
  const div = document.createElement('div');
  div.className = 'flash flash-error inline-error mt-2';
  div.style.marginTop = '0.5rem';
  div.innerHTML = '<i class="bi bi-exclamation-triangle"></i> ' + msg;
  form.appendChild(div);
  setTimeout(() => div.remove(), 4000);
}

// ── Hash box — click to copy ─────────────────────────────────────────
document.querySelectorAll('.hash-box').forEach(el => {
  el.title = 'Click to copy';
  el.addEventListener('click', () => {
    const text = el.textContent.trim();
    if (!text || text === '—') return;
    navigator.clipboard.writeText(text).then(() => {
      const orig = el.style.borderColor;
      el.style.borderColor = 'var(--risk-low)';
      el.style.boxShadow = '0 0 6px rgba(46,213,115,0.2)';
      setTimeout(() => {
        el.style.borderColor = orig;
        el.style.boxShadow = '';
      }, 800);
    }).catch(() => {
      // Fallback for older browsers
      const sel = window.getSelection();
      const range = document.createRange();
      range.selectNodeContents(el);
      sel.removeAllRanges();
      sel.addRange(range);
    });
  });
});

// ── Collapse icon rotation (Bootstrap collapse events) ───────────────
document.querySelectorAll('[data-bs-toggle="collapse"]').forEach(trigger => {
  const targetId = trigger.getAttribute('data-bs-target');
  const target = document.querySelector(targetId);
  if (!target) return;

  target.addEventListener('show.bs.collapse', () => {
    trigger.setAttribute('aria-expanded', 'true');
  });
  target.addEventListener('hide.bs.collapse', () => {
    trigger.setAttribute('aria-expanded', 'false');
  });
});

// ── Auto-dismiss flash messages after 6s ────────────────────────────
document.querySelectorAll('.flash').forEach(el => {
  setTimeout(() => {
    el.style.transition = 'opacity 0.4s';
    el.style.opacity = '0';
    setTimeout(() => el.remove(), 400);
  }, 6000);
});