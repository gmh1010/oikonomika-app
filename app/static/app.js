// Oikonomika page behaviour. Loaded as a static file so the Content-Security-Policy can forbid inline scripts.
(function () {
  'use strict';

  // Category <select>s inside [data-kind-form] only show categories of the chosen kind (expense/income).
  document.querySelectorAll('[data-kind-form]').forEach(function (form) {
    var sel = form.querySelector('select[name=category_id]');
    if (!sel) return;
    function apply() {
      var k = (form.querySelector('input[name=kind]:checked') || {}).value;
      if (!k) return;
      form.dataset.kind = k;
      var first = null;
      sel.querySelectorAll('option').forEach(function (o) {
        var ok = o.dataset.kind === k;
        o.hidden = !ok; o.disabled = !ok;
        if (ok && !first) first = o;
      });
      if (sel.selectedOptions[0] && sel.selectedOptions[0].disabled && first) sel.value = first.value;
    }
    form.querySelectorAll('input[name=kind]').forEach(function (r) { r.addEventListener('change', apply); });
    apply();
  });

  // Forms with data-confirm ask before submitting.
  document.querySelectorAll('form[data-confirm]').forEach(function (f) {
    f.addEventListener('submit', function (e) { if (!window.confirm(f.dataset.confirm)) e.preventDefault(); });
  });

  // Emoji palette on the categories page: opens under whichever emoji box was focused.
  var picker = document.getElementById('picker');
  if (picker) {
    var target = null;
    var close = function () {
      picker.hidden = true;
      if (target) target.classList.remove('target');
      target = null;
    };
    document.querySelectorAll('.icon-in').forEach(function (i) {
      i.addEventListener('focus', function () {
        if (target) target.classList.remove('target');
        target = i; i.classList.add('target');
        (i.closest('[data-picker-anchor]') || i.form).after(picker);
        picker.hidden = false;
      });
    });
    picker.addEventListener('mousedown', function (e) { e.preventDefault(); });
    picker.querySelectorAll('[data-emoji]').forEach(function (b) {
      b.addEventListener('click', function () {
        if (!target) return;
        target.value = b.dataset.emoji;
        var save = target.form.querySelector('button');
        close();
        if (save) save.focus();
      });
    });
    document.addEventListener('mousedown', function (e) {
      if (!picker.hidden && !picker.contains(e.target) && !e.target.classList.contains('icon-in')) close();
    });
    document.addEventListener('keydown', function (e) { if (e.key === 'Escape') close(); });
  }

  // Scan page: file list, drag & drop, busy button. File names are shown as text, never as HTML.
  var input = document.getElementById('files');
  var drop = document.getElementById('drop');
  if (input && drop) {
    var text = document.getElementById('droptext');
    var form = document.getElementById('scanform');
    var go = document.getElementById('go');
    input.addEventListener('change', function () {
      if (!input.files.length) return;
      text.textContent = '';
      var head = document.createElement('b');
      head.textContent = input.files.length + ' αρχείο/α:';
      text.appendChild(head);
      Array.prototype.forEach.call(input.files, function (f) {
        text.appendChild(document.createElement('br'));
        var s = document.createElement('small');
        s.textContent = f.name;
        text.appendChild(s);
      });
    });
    ['dragover', 'dragenter'].forEach(function (ev) {
      drop.addEventListener(ev, function (e) { e.preventDefault(); drop.classList.add('ring-2', 'ring-primary'); });
    });
    ['dragleave', 'drop'].forEach(function (ev) {
      drop.addEventListener(ev, function () { drop.classList.remove('ring-2', 'ring-primary'); });
    });
    drop.addEventListener('drop', function (e) {
      e.preventDefault(); input.files = e.dataTransfer.files; input.dispatchEvent(new Event('change'));
    });
    form.addEventListener('submit', function () { go.disabled = true; go.textContent = 'Διαβάζω… (5–20″ ανά αρχείο)'; });
  }

  // Add-transaction sheet: bottom sheet on mobile, modal on desktop (native <dialog>).
  var sheet = document.getElementById('add-sheet');
  if (sheet && sheet.showModal) {
    document.querySelectorAll('[data-open-sheet]').forEach(function (b) {
      b.addEventListener('click', function () {
        sheet.showModal();
        var amt = sheet.querySelector('input[name=amount]');
        if (amt) amt.focus();
      });
    });
    sheet.querySelectorAll('[data-close-sheet]').forEach(function (b) {
      b.addEventListener('click', function () { sheet.close(); });
    });
    sheet.addEventListener('click', function (e) { if (e.target === sheet) sheet.close(); });   // backdrop
  }

  // "Σήμερα / Χθες" chips fill the nearest date input.
  document.querySelectorAll('[data-date-chip]').forEach(function (chip) {
    chip.addEventListener('click', function () {
      var input = chip.parentElement.querySelector('[data-date-input]');
      if (!input) return;
      var d = new Date();
      d.setDate(d.getDate() + parseInt(chip.dataset.dateChip, 10));
      var p = function (n) { return (n < 10 ? '0' : '') + n; };
      input.value = d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate());
    });
  });

  // Copy buttons: data-copy="#element-id" copies that element's text.
  document.querySelectorAll('[data-copy]').forEach(function (b) {
    b.addEventListener('click', function () {
      var el = document.querySelector(b.dataset.copy);
      if (!el || !navigator.clipboard) return;
      navigator.clipboard.writeText(el.innerText.trim()).then(function () {
        var old = b.dataset.label || b.textContent;
        b.dataset.label = old;
        b.textContent = 'Αντιγράφηκε ✓';
        setTimeout(function () { b.textContent = old; }, 1800);
      });
    });
  });

  // Download recovery codes as a .txt file (generated in the browser; codes are never stored in plain text).
  document.querySelectorAll('[data-download]').forEach(function (b) {
    b.addEventListener('click', function () {
      var el = document.querySelector(b.dataset.download);
      if (!el) return;
      var text = 'Οικονομικά — κωδικοί ανάκτησης 2FA\n(ο καθένας δουλεύει μία φορά)\n\n' + el.innerText.trim() + '\n';
      var a = document.createElement('a');
      a.href = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
      a.download = 'oikonomika-recovery-codes.txt';
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
    });
  });

  // A checkbox that must be ticked before a button/link is enabled (e.g. "Τα αποθήκευσα").
  document.querySelectorAll('[data-gate]').forEach(function (box) {
    var target = document.querySelector(box.dataset.gate);
    if (!target) return;
    var sync = function () {
      target.classList.toggle('pointer-events-none', !box.checked);
      target.classList.toggle('opacity-50', !box.checked);
      target.setAttribute('aria-disabled', box.checked ? 'false' : 'true');
    };
    box.addEventListener('change', sync);
    sync();
  });

  // One-time-code fields: keep digits only.
  document.querySelectorAll('input[data-otp]').forEach(function (i) {
    i.addEventListener('input', function () { i.value = i.value.replace(/\D/g, '').slice(0, 6); });
  });

  // Scan page camera button (mobile): taking a photo submits right away.
  document.querySelectorAll('input[data-camera]').forEach(function (cam) {
    cam.addEventListener('change', function () {
      if (!cam.files.length) return;
      var main = document.getElementById('files');
      if (main) main.required = false;
      var go = document.getElementById('go');
      if (go) { go.disabled = true; go.textContent = 'Διαβάζω…'; }
      cam.form.submit();
    });
  });
})();
