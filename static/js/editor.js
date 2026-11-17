(function () {
  'use strict';

  var layout = document.querySelector('.editor-layout');
  var reportId = layout.dataset.reportId;
  var saveState = document.getElementById('save-state');
  var findingsBox = document.getElementById('findings');
  var toolbar = document.getElementById('toolbar');
  var imageInput = document.getElementById('image-input');
  var SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

  // ------------------------------------------------------------ saving
  var pending = new Map();   // url -> {url, data}
  var timer = null;
  var inflight = 0;

  function setState(state, text) {
    saveState.dataset.state = state;
    saveState.textContent = text;
  }

  function endpointFor(el) {
    var scope = el.closest('[data-scope]');
    if (!scope) return null;
    if (scope.dataset.scope === 'finding') {
      return { key: '/api/findings/' + scope.dataset.id, url: '/api/findings/' + scope.dataset.id };
    }
    return { key: '/api/reports/' + reportId, url: '/api/reports/' + reportId };
  }

  function valueOf(el) {
    return el.isContentEditable ? el.innerHTML : el.value;
  }

  function queue(el, delay) {
    var ep = endpointFor(el);
    if (!ep || !el.dataset.field) return;
    var entry = pending.get(ep.key) || { url: ep.url, data: {} };
    entry.data[el.dataset.field] = valueOf(el);
    pending.set(ep.key, entry);
    setState('dirty', 'Есть изменения…');
    clearTimeout(timer);
    timer = setTimeout(flush, delay == null ? 700 : delay);
  }

  function flush() {
    clearTimeout(timer);
    if (!pending.size) return Promise.resolve();
    var batch = Array.from(pending.values());
    pending.clear();
    setState('saving', 'Сохранение…');
    inflight++;
    return Promise.all(batch.map(function (b) {
      return fetch(b.url, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(b.data)
      }).then(function (r) { if (!r.ok) throw new Error(r.status); });
    })).then(function () {
      inflight--;
      if (!pending.size && !inflight) {
        var t = new Date();
        setState('saved', 'Сохранено в ' + t.toLocaleTimeString().slice(0, 5));
      }
    }).catch(function () {
      inflight--;
      batch.forEach(function (b) {   // keep the data so the next attempt retries it
        var key = b.url;
        var e = pending.get(key) || { url: b.url, data: {} };
        Object.keys(b.data).forEach(function (k) { if (!(k in e.data)) e.data[k] = b.data[k]; });
        pending.set(key, e);
      });
      setState('error', 'Ошибка сохранения — повтор…');
      timer = setTimeout(flush, 3000);
    });
  }

  window.addEventListener('beforeunload', function (e) {
    if (pending.size || inflight) { flush(); e.preventDefault(); e.returnValue = ''; }
  });

  // ------------------------------------------------------------ field events
  document.addEventListener('input', function (e) {
    var el = e.target;
    if (!el.dataset || !el.dataset.field) return;
    if (el.dataset.field === 'cvss_score') syncSeverityFromScore(el);
    if (el.dataset.field === 'cvss_vector') syncScoreFromVector(el);
    if (el.dataset.field === 'title' && el.closest('.finding')) updateOutlineTitle(el.closest('.finding'));
    queue(el);
    if (el.isContentEditable) updateWordCount();
  });

  document.addEventListener('change', function (e) {
    var el = e.target;
    if (!el.dataset || !el.dataset.field || el.tagName !== 'SELECT') return;
    queue(el, 0);
    if (el.dataset.field === 'severity') applySeverity(el.closest('.finding'), el.value, true);
    if (el.dataset.field === 'classification') el.style.setProperty('--class-color', window.CLASS_COLORS[el.value]);
    if (el.dataset.reload) flush().then(function () { location.reload(); });
  });

  // ------------------------------------------------------------ severity / CVSS
  function scoreToSeverity(score) {
    if (score >= 9) return 'critical';
    if (score >= 7) return 'high';
    if (score >= 4) return 'medium';
    if (score > 0) return 'low';
    return 'info';
  }

  function syncSeverityFromScore(input) {
    var v = parseFloat(String(input.value).replace(',', '.'));
    if (isNaN(v) || v < 0 || v > 10) { input.classList.toggle('invalid', input.value.trim() !== ''); return; }
    input.classList.remove('invalid');
    var card = input.closest('.finding');
    var sel = card.querySelector('[data-field="severity"]');
    var sev = scoreToSeverity(v);
    if (sel.value !== sev) {
      sel.value = sev;
      queue(sel);
      applySeverity(card, sev, true);
    }
  }

  // A complete vector typed or pasted by hand also updates the score.
  function syncScoreFromVector(input) {
    var s = window.CVSS.score(window.CVSS.parse(input.value));
    var scoreInput = input.closest('.finding').querySelector('[data-field="cvss_score"]');
    if (s === null || scoreInput.value === s.toFixed(1)) return;
    scoreInput.value = s.toFixed(1);
    queue(scoreInput);
    syncSeverityFromScore(scoreInput);
  }

  function applySeverity(card, sev, refresh) {
    SEVERITIES.forEach(function (s) {
      card.classList.remove('sevborder-' + s);
      card.querySelector('.sev-select').classList.remove('sev-' + s);
    });
    card.classList.add('sevborder-' + sev);
    card.querySelector('.sev-select').classList.add('sev-' + sev);
    if (refresh) flush().then(refreshSummary);
  }

  // Re-number and re-order findings exactly as the final report will.
  function refreshSummary() {
    return fetch('/api/reports/' + reportId + '/summary').then(function (r) { return r.json(); }).then(function (s) {
      var outline = document.getElementById('outline-findings');
      outline.innerHTML = '';
      s.findings.forEach(function (f) {
        var card = document.getElementById('finding-' + f.id);
        if (card) {
          card.querySelector('.finding-code').textContent = f.code;
          findingsBox.appendChild(card);
        }
        var a = document.createElement('a');
        a.href = '#finding-' + f.id;
        a.className = 'outline-sub';
        a.dataset.id = f.id;
        a.innerHTML = '<i class="dot sev-' + f.severity + '"></i><span class="code"></span><span class="t"></span>';
        a.querySelector('.code').textContent = f.code;
        a.querySelector('.t').textContent = card ? card.querySelector('.finding-title').value : f.title;
        outline.appendChild(a);
      });
      SEVERITIES.forEach(function (sv) {
        var b = document.querySelector('#stat-list [data-sev="' + sv + '"]');
        if (b) b.textContent = s.counts[sv];
      });
      renderSevbar(s.counts);
      document.getElementById('findings-empty').hidden = s.findings.length > 0;
    });
  }

  function renderSevbar(counts) {
    var bar = document.getElementById('side-sevbar');
    var total = SEVERITIES.reduce(function (n, s) { return n + counts[s]; }, 0);
    bar.innerHTML = '';
    if (!total) { bar.innerHTML = '<span class="sev-none"></span>'; return; }
    SEVERITIES.forEach(function (s) {
      if (!counts[s]) return;
      var span = document.createElement('span');
      span.className = 'sev-' + s;
      span.style.flex = counts[s];
      span.title = window.SEV_LABELS[s] + ': ' + counts[s];
      bar.appendChild(span);
    });
  }

  function updateOutlineTitle(card) {
    var link = document.querySelector('#outline-findings [data-id="' + card.dataset.id + '"] .t');
    if (link) link.textContent = card.querySelector('.finding-title').value;
  }

  // ------------------------------------------------------------ add / delete / collapse findings
  function addFinding(e, templateId) {
    if (e && e.preventDefault) e.preventDefault();
    return flush().then(function () {
      return fetch('/api/reports/' + reportId + '/findings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(templateId ? { template_id: templateId } : {})
      });
    }).then(function (r) { return r.json(); }).then(function (res) {
      var tmp = document.createElement('div');
      tmp.innerHTML = res.html;
      var card = tmp.firstElementChild;
      findingsBox.appendChild(card);
      return refreshSummary().then(function () {
        card.scrollIntoView({ behavior: 'smooth', block: 'start' });
        var title = card.querySelector('.finding-title');
        title.focus();
        title.select();
      });
    });
  }
  ['add-finding', 'add-finding-side', 'add-finding-empty'].forEach(function (id) {
    var b = document.getElementById(id);
    if (b) b.addEventListener('click', addFinding);
  });

  findingsBox.addEventListener('click', function (e) {
    var card = e.target.closest('.finding');
    if (!card) return;
    if (e.target.closest('.finding-delete')) {
      var name = card.querySelector('.finding-title').value || card.querySelector('.finding-code').textContent;
      if (!confirm('Удалить уязвимость «' + name + '»?')) return;
      flush().then(function () {
        return fetch('/api/findings/' + card.dataset.id, { method: 'DELETE' });
      }).then(function () { card.remove(); refreshSummary(); });
    } else if (e.target.closest('.finding-collapse')) {
      card.classList.toggle('collapsed');
    } else if (e.target.closest('.finding-to-lib')) {
      saveToLibrary(card);
    } else if (e.target.closest('.calc-btn')) {
      e.preventDefault();
      openCalculator(card);
    }
  });

  // ------------------------------------------------------------ modal & toast
  var modal = document.getElementById('modal');
  var modalBody = document.getElementById('modal-body');
  var modalFoot = document.getElementById('modal-foot');

  function openModal(title, body, buttons, wide) {
    document.getElementById('modal-title').textContent = title;
    modalBody.innerHTML = '';
    modalBody.appendChild(body);
    modalFoot.innerHTML = '';
    (buttons || []).forEach(function (b) {
      var btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'btn' + (b.primary ? ' btn-primary' : '');
      btn.textContent = b.label;
      btn.addEventListener('click', function () { if (b.onClick() !== false) modal.close(); });
      modalFoot.appendChild(btn);
      b.el = btn;
    });
    modalFoot.hidden = !buttons || !buttons.length;
    modal.classList.toggle('wide', !!wide);
    modal.showModal();
  }
  modal.addEventListener('click', function (e) { if (e.target === modal) modal.close(); });

  var toastTimer;
  function toast(text, isError) {
    var t = document.getElementById('toast');
    t.textContent = text;
    t.classList.toggle('error', !!isError);
    t.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { t.hidden = true; }, 3200);
  }

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }

  // ------------------------------------------------------------ vulnerability library
  document.querySelectorAll('[data-open-library]').forEach(function (b) {
    b.addEventListener('click', function (e) { e.preventDefault(); openLibrary(); });
  });

  function openLibrary() {
    var body = el('div', 'lib-picker');
    var search = el('input', 'lib-picker-search');
    search.type = 'search';
    search.placeholder = 'Поиск: SQL, XSS, TLS…';
    var list = el('div', 'lib-picker-list', 'Загрузка…');
    var manage = el('a', 'small', 'Управление библиотекой →');
    manage.href = '/library?lang=' + window.REPORT_LANG;
    manage.target = '_blank';
    body.appendChild(search);
    body.appendChild(list);
    body.appendChild(manage);
    openModal('Добавить уязвимость из библиотеки', body, [], true);
    setTimeout(function () { search.focus(); }, 30);

    fetch('/api/library?lang=' + window.REPORT_LANG).then(function (r) { return r.json(); }).then(function (items) {
      function render() {
        var q = search.value.trim().toLowerCase();
        list.innerHTML = '';
        var shown = items.filter(function (t) { return t.title.toLowerCase().indexOf(q) >= 0; });
        if (!shown.length) { list.appendChild(el('div', 'muted lib-empty', 'Ничего не найдено')); return; }
        shown.forEach(function (t) {
          var row = el('button', 'lib-row');
          row.type = 'button';
          row.appendChild(el('span', 'badge sev-' + t.severity, window.SEV_LABELS[t.severity]));
          row.appendChild(el('span', 'lib-row-title', t.title));
          row.appendChild(el('span', 'mono muted', t.cvss_score || '—'));
          row.addEventListener('click', function () {
            modal.close();
            addFinding(null, t.id).then(function () { toast('Добавлено: ' + t.title); });
          });
          list.appendChild(row);
        });
      }
      search.addEventListener('input', render);
      search.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') { e.preventDefault(); var first = list.querySelector('.lib-row'); if (first) first.click(); }
      });
      render();
    });
  }

  function saveToLibrary(card) {
    flush().then(function () {
      return fetch('/api/findings/' + card.dataset.id + '/to-library', { method: 'POST' });
    }).then(function (r) { return r.json(); }).then(function (res) {
      toast(res.status === 'updated' ? 'Шаблон в библиотеке обновлён' : 'Сохранено в библиотеку');
    }).catch(function () { toast('Не удалось сохранить в библиотеку', true); });
  }

  // ------------------------------------------------------------ CVSS calculator
  function openCalculator(card) {
    var vecInput = card.querySelector('[data-field="cvss_vector"]');
    var scoreInput = card.querySelector('[data-field="cvss_score"]');
    var m = window.CVSS.parse(vecInput.value);
    var metrics = window.CVSS.METRICS[window.REPORT_LANG] || window.CVSS.METRICS.ru;

    var body = el('div', 'calc');
    var result = el('div', 'calc-result');
    var big = el('div', 'calc-score');
    var badge = el('span', 'badge');
    var vec = el('div', 'mono small muted calc-vector');
    var left = el('div');
    left.appendChild(badge);
    left.appendChild(vec);
    result.appendChild(big);
    result.appendChild(left);

    var grid = el('div', 'calc-grid');
    metrics.forEach(function (def) {
      var group = el('div', 'calc-group');
      var head = el('div', 'calc-name', def.name);
      head.appendChild(el('span', 'muted small', ' · ' + def.hint));
      group.appendChild(head);
      var seg = el('div', 'calc-options');
      def.options.forEach(function (o) {
        var b = el('button', 'calc-opt');
        b.type = 'button';
        b.dataset.key = def.key;
        b.dataset.val = o[0];
        b.appendChild(el('b', null, o[1]));
        if (o[2]) b.title = o[2];
        b.addEventListener('click', function () { m[def.key] = o[0]; update(); });
        seg.appendChild(b);
      });
      group.appendChild(seg);
      var hint = el('div', 'calc-hint muted small');
      group.appendChild(hint);
      grid.appendChild(group);
    });
    body.appendChild(result);
    body.appendChild(grid);

    var apply = { label: 'Применить', primary: true, onClick: function () {
      var s = window.CVSS.score(m);
      if (s === null) return false;
      vecInput.value = window.CVSS.build(m);
      scoreInput.value = s.toFixed(1);
      queue(vecInput);
      syncSeverityFromScore(scoreInput);
      queue(scoreInput);
      toast('CVSS ' + s.toFixed(1) + ' — ' + window.SEV_LABELS[window.CVSS.severity(s)]);
    } };

    function update() {
      grid.querySelectorAll('.calc-opt').forEach(function (b) {
        b.classList.toggle('on', m[b.dataset.key] === b.dataset.val);
      });
      grid.querySelectorAll('.calc-group').forEach(function (g, i) {
        var def = metrics[i];
        var opt = def.options.filter(function (o) { return o[0] === m[def.key]; })[0];
        g.querySelector('.calc-hint').textContent = opt ? opt[2] : '';
      });
      var s = window.CVSS.score(m);
      if (s === null) {
        big.textContent = '—';
        big.className = 'calc-score';
        badge.className = 'badge sev-info';
        badge.textContent = 'Выберите все параметры';
        vec.textContent = '';
        if (apply.el) apply.el.disabled = true;
      } else {
        var sev = window.CVSS.severity(s);
        big.textContent = s.toFixed(1);
        big.className = 'calc-score sev-text-' + sev;
        badge.className = 'badge sev-' + sev;
        badge.textContent = window.SEV_LABELS[sev];
        vec.textContent = window.CVSS.build(m);
        if (apply.el) apply.el.disabled = false;
      }
    }

    openModal('Калькулятор CVSS 3.1', body, [{ label: 'Отмена', onClick: function () {} }, apply], true);
    update();
  }

  // ------------------------------------------------------------ screenshot annotation
  var imgEditBtn = el('button', 'img-edit-btn');
  imgEditBtn.type = 'button';
  imgEditBtn.innerHTML = '<svg viewBox="0 0 24 24" width="15" height="15"><path fill="currentColor" d="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zM20.71 7.04a1 1 0 0 0 0-1.41l-2.34-2.34a1 1 0 0 0-1.41 0l-1.83 1.83 3.75 3.75 1.83-1.83z"/></svg> Рисовать';
  imgEditBtn.hidden = true;
  document.body.appendChild(imgEditBtn);
  var hoveredImg = null;

  function placeImgButton(img) {
    var r = img.getBoundingClientRect();
    imgEditBtn.style.top = (r.top + 8) + 'px';
    imgEditBtn.style.left = (r.right - imgEditBtn.offsetWidth - 8) + 'px';
  }
  document.addEventListener('mouseover', function (e) {
    var img = e.target.closest && e.target.closest('.rich img');
    if (img && !modal.open) { hoveredImg = img; imgEditBtn.hidden = false; placeImgButton(img); }
    else if (!e.target.closest || !e.target.closest('.img-edit-btn')) { imgEditBtn.hidden = true; }
  });
  document.getElementById('canvas').addEventListener('scroll', function () { imgEditBtn.hidden = true; });
  imgEditBtn.addEventListener('click', function () {
    imgEditBtn.hidden = true;
    if (hoveredImg) openAnnotator(hoveredImg);
  });

  var ANN_COLORS = ['#E5484D', '#F5C518', '#21A038', '#2F80ED', '#111111', '#FFFFFF'];
  var ANN_TOOLS = [
    ['arrow', 'Стрелка', 'M4 20 18.6 5.4M18.6 5.4H11M18.6 5.4V13'],
    ['rect', 'Рамка', 'M4 5h16v14H4z'],
    ['pen', 'Карандаш', 'M4 18c3-6 6 2 9-4s4-8 7-8'],
    ['marker', 'Маркер', 'M4 9h16v6H4z'],
    ['text', 'Текст', 'M5 5h14M12 5v14'],
    ['blur', 'Скрыть данные', 'M4 4h4v4H4zM12 4h4v4h-4zM8 8h4v4H8zM16 8h4v4h-4zM4 12h4v4H4zM12 12h4v4h-4zM8 16h4v4H8zM16 16h4v4h-4z']
  ];

  function openAnnotator(img) {
    var base = new Image();
    base.onload = function () { buildAnnotator(img, base); };
    base.onerror = function () { toast('Не удалось открыть изображение', true); };
    base.src = img.src;
  }

  function buildAnnotator(img, base) {
    var W = base.naturalWidth, H = base.naturalHeight;
    var state = { tool: 'arrow', color: ANN_COLORS[0], size: 2, shapes: [], drawing: null };
    var unit = Math.max(2, Math.round(Math.max(W, H) / 400));

    var body = el('div', 'ann');
    var bar = el('div', 'ann-bar');
    var toolGroup = el('div', 'ann-group');
    ANN_TOOLS.forEach(function (t) {
      var b = el('button', 'ann-tool');
      b.type = 'button';
      b.dataset.tool = t[0];
      b.title = t[1];
      b.innerHTML = '<svg viewBox="0 0 24 24" width="18" height="18"><path d="' + t[2] + '" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg><span>' + t[1] + '</span>';
      b.addEventListener('click', function () { state.tool = t[0]; sync(); });
      toolGroup.appendChild(b);
    });
    var colorGroup = el('div', 'ann-group');
    ANN_COLORS.forEach(function (c) {
      var b = el('button', 'ann-color');
      b.type = 'button';
      b.dataset.color = c;
      b.style.background = c;
      b.title = c;
      b.addEventListener('click', function () { state.color = c; sync(); });
      colorGroup.appendChild(b);
    });
    var sizeGroup = el('div', 'ann-group');
    [1, 2, 3].forEach(function (s) {
      var b = el('button', 'ann-size');
      b.type = 'button';
      b.dataset.size = s;
      b.title = ['Тонко', 'Средне', 'Толсто'][s - 1];
      b.innerHTML = '<i style="height:' + (s * 2 + 1) + 'px"></i>';
      b.addEventListener('click', function () { state.size = s; sync(); });
      sizeGroup.appendChild(b);
    });
    var histGroup = el('div', 'ann-group');
    var undoBtn = el('button', 'btn btn-sm', 'Отменить');
    undoBtn.type = 'button';
    undoBtn.addEventListener('click', function () { state.shapes.pop(); render(); });
    var clearBtn = el('button', 'btn btn-sm', 'Очистить');
    clearBtn.type = 'button';
    clearBtn.addEventListener('click', function () { state.shapes = []; render(); });
    histGroup.appendChild(undoBtn);
    histGroup.appendChild(clearBtn);
    [toolGroup, colorGroup, sizeGroup, histGroup].forEach(function (g) { bar.appendChild(g); });

    var stage = el('div', 'ann-stage');
    var canvas = document.createElement('canvas');
    canvas.width = W;
    canvas.height = H;
    stage.appendChild(canvas);
    body.appendChild(bar);
    body.appendChild(stage);
    body.appendChild(el('div', 'muted small ann-hint',
      '«Скрыть данные» пикселизирует область — используйте для паролей, токенов, ФИО и номеров карт. Ctrl/⌘+Z — отменить.'));
    var ctx = canvas.getContext('2d');

    function sync() {
      bar.querySelectorAll('.ann-tool').forEach(function (b) { b.classList.toggle('on', b.dataset.tool === state.tool); });
      bar.querySelectorAll('.ann-color').forEach(function (b) { b.classList.toggle('on', b.dataset.color === state.color); });
      bar.querySelectorAll('.ann-size').forEach(function (b) { b.classList.toggle('on', +b.dataset.size === state.size); });
      canvas.style.cursor = state.tool === 'text' ? 'text' : 'crosshair';
    }

    function norm(s) {
      return { x: Math.min(s.x1, s.x2), y: Math.min(s.y1, s.y2), w: Math.abs(s.x2 - s.x1), h: Math.abs(s.y2 - s.y1) };
    }

    function drawShape(s) {
      var lw = unit * s.size;
      ctx.save();
      ctx.strokeStyle = ctx.fillStyle = s.color;
      ctx.lineWidth = lw;
      ctx.lineCap = ctx.lineJoin = 'round';
      if (s.type === 'rect') {
        var r = norm(s);
        ctx.strokeRect(r.x, r.y, r.w, r.h);
      } else if (s.type === 'marker') {
        var m = norm(s);
        ctx.globalAlpha = 0.35;
        ctx.fillRect(m.x, m.y, m.w, m.h);
      } else if (s.type === 'arrow') {
        var ang = Math.atan2(s.y2 - s.y1, s.x2 - s.x1), head = lw * 4;
        ctx.beginPath();
        ctx.moveTo(s.x1, s.y1);
        ctx.lineTo(s.x2 - Math.cos(ang) * head * 0.6, s.y2 - Math.sin(ang) * head * 0.6);
        ctx.stroke();
        ctx.beginPath();
        ctx.moveTo(s.x2, s.y2);
        ctx.lineTo(s.x2 - head * Math.cos(ang - 0.45), s.y2 - head * Math.sin(ang - 0.45));
        ctx.lineTo(s.x2 - head * Math.cos(ang + 0.45), s.y2 - head * Math.sin(ang + 0.45));
        ctx.closePath();
        ctx.fill();
      } else if (s.type === 'pen') {
        ctx.beginPath();
        s.points.forEach(function (p, i) { if (i) ctx.lineTo(p[0], p[1]); else ctx.moveTo(p[0], p[1]); });
        ctx.stroke();
      } else if (s.type === 'text') {
        var fs = Math.max(14, unit * 7) * (0.7 + s.size * 0.3);
        ctx.font = '600 ' + fs + 'px -apple-system, "Segoe UI", Arial, sans-serif';
        ctx.textBaseline = 'top';
        ctx.lineWidth = Math.max(2, fs / 6);
        ctx.strokeStyle = s.color === '#FFFFFF' ? '#111111' : '#FFFFFF';
        ctx.strokeText(s.text, s.x1, s.y1);
        ctx.fillText(s.text, s.x1, s.y1);
      } else if (s.type === 'blur') {
        var b = norm(s);
        if (b.w >= 2 && b.h >= 2) {
          var block = Math.max(12, Math.round(Math.max(W, H) / 60));  // coarse enough to be unreadable
          var tw = Math.max(1, Math.round(b.w / block)), th = Math.max(1, Math.round(b.h / block));
          var tmp = document.createElement('canvas');
          tmp.width = tw;
          tmp.height = th;
          tmp.getContext('2d').drawImage(canvas, b.x, b.y, b.w, b.h, 0, 0, tw, th);
          ctx.imageSmoothingEnabled = false;
          ctx.drawImage(tmp, 0, 0, tw, th, b.x, b.y, b.w, b.h);
        }
      }
      ctx.restore();
    }

    function render() {
      ctx.clearRect(0, 0, W, H);
      ctx.drawImage(base, 0, 0);
      state.shapes.forEach(drawShape);
      if (state.drawing) drawShape(state.drawing);
    }

    function pos(e) {
      var r = canvas.getBoundingClientRect();
      return [(e.clientX - r.left) * W / r.width, (e.clientY - r.top) * H / r.height];
    }

    canvas.addEventListener('pointerdown', function (e) {
      e.preventDefault();
      var p = pos(e);
      if (state.tool === 'text') {
        var text = prompt('Текст надписи:');
        if (text) { state.shapes.push({ type: 'text', color: state.color, size: state.size, x1: p[0], y1: p[1], text: text }); render(); }
        return;
      }
      canvas.setPointerCapture(e.pointerId);
      state.drawing = { type: state.tool, color: state.color, size: state.size, x1: p[0], y1: p[1], x2: p[0], y2: p[1], points: [p] };
    });
    canvas.addEventListener('pointermove', function (e) {
      if (!state.drawing) return;
      var p = pos(e);
      state.drawing.x2 = p[0];
      state.drawing.y2 = p[1];
      if (state.drawing.type === 'pen') state.drawing.points.push(p);
      render();
    });
    function finish() {
      var d = state.drawing;
      state.drawing = null;
      if (d && (d.type === 'pen' ? d.points.length > 1 : Math.abs(d.x2 - d.x1) + Math.abs(d.y2 - d.y1) > 4)) state.shapes.push(d);
      render();
    }
    canvas.addEventListener('pointerup', finish);
    canvas.addEventListener('pointercancel', finish);

    function onKey(e) {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'z' && modal.open) {
        e.preventDefault();
        e.stopPropagation();
        state.shapes.pop();
        render();
      }
    }
    document.addEventListener('keydown', onKey, true);
    modal.addEventListener('close', function cleanup() {
      document.removeEventListener('keydown', onKey, true);
      modal.removeEventListener('close', cleanup);
      modal.classList.remove('xl');
    });

    var save = { label: 'Сохранить', primary: true, onClick: function () {
      if (!state.shapes.length) return true;
      save.el.disabled = true;
      save.el.textContent = 'Сохранение…';
      canvas.toBlob(function (blob) {
        var form = new FormData();
        form.append('file', new File([blob], 'annotated.png', { type: 'image/png' }));
        fetch('/api/uploads', { method: 'POST', body: form })
          .then(function (r) { return r.json(); })
          .then(function (res) {
            if (!res.ok) throw new Error(res.error);
            img.setAttribute('src', res.url);
            queue(img.closest('.rich'), 0);
            modal.close();
            toast('Изображение сохранено');
          })
          .catch(function (err) {
            save.el.disabled = false;
            save.el.textContent = 'Сохранить';
            toast(err.message || 'Не удалось сохранить', true);
          });
      }, 'image/png');
      return false;  // close only after the upload finished
    } };

    openModal('Редактирование изображения', body, [{ label: 'Отмена', onClick: function () {} }, save], true);
    modal.classList.add('xl');
    sync();
    render();
  }

  // Export links: save first so the file contains the latest edits.
  document.querySelectorAll('[data-export]').forEach(function (a) {
    a.addEventListener('click', function (e) {
      if (!pending.size && !inflight) return;
      e.preventDefault();
      flush().then(function () { location.href = a.href; });
    });
  });

  // ------------------------------------------------------------ rich text toolbar
  var activeEditor = null;
  var savedRange = null;

  document.addEventListener('focusin', function (e) {
    if (e.target.isContentEditable && e.target.classList.contains('rich')) {
      activeEditor = e.target;
      toolbar.classList.add('active');
    }
  });
  document.addEventListener('selectionchange', function () {
    var sel = document.getSelection();
    if (!sel.rangeCount || !activeEditor) return;
    var r = sel.getRangeAt(0);
    if (activeEditor.contains(r.commonAncestorContainer)) {
      savedRange = r.cloneRange();
      updateToolbarState();
    }
  });

  function restoreSelection() {
    if (!activeEditor) return false;
    activeEditor.focus();
    if (savedRange) {
      var sel = document.getSelection();
      sel.removeAllRanges();
      sel.addRange(savedRange);
    }
    return true;
  }

  function updateToolbarState() {
    ['bold', 'italic', 'underline', 'strikeThrough', 'insertUnorderedList', 'insertOrderedList'].forEach(function (c) {
      var b = toolbar.querySelector('[data-cmd="' + c + '"]');
      try { b.classList.toggle('on', document.queryCommandState(c)); } catch (e) { /* ignore */ }
    });
    var block = (document.queryCommandValue('formatBlock') || 'p').toLowerCase();
    var select = toolbar.querySelector('select[data-cmd="formatBlock"]');
    select.value = ['h3', 'h4', 'pre', 'blockquote'].indexOf(block) >= 0 ? block : 'p';
  }

  toolbar.addEventListener('mousedown', function (e) {
    if (e.target.closest('button')) e.preventDefault();   // keep focus in editor
  });

  toolbar.addEventListener('click', function (e) {
    var btn = e.target.closest('button[data-cmd]');
    if (!btn || !restoreSelection()) return;
    run(btn.dataset.cmd);
  });

  // Ready-made callout blocks ("Обратите внимание", "Внимание", ...).
  toolbar.querySelector('select[data-cmd="callout"]').addEventListener('change', function (e) {
    var type = e.target.value;
    e.target.value = '';
    if (!type || !restoreSelection()) return;
    var sel = document.getSelection();
    var selected = sel.toString();
    if (selected) document.execCommand('delete');  // selected text moves into the block
    var box = document.createElement('div');
    box.className = 'callout callout-' + type;
    box.innerHTML = '<p><strong>' + escapeHtml(window.CALLOUT_LABELS[type]) + '</strong></p><p>' +
      (selected ? escapeHtml(selected) : '<br>') + '</p>';
    insertBlock(box);
    placeCaret(box.lastChild);
    changed();
  });

  // Insert a block element after the paragraph that holds the caret (or in place of an empty one).
  // execCommand('insertHTML') would merge the block's first line into the current paragraph.
  function insertBlock(node) {
    var ed = activeEditor;
    var n = document.getSelection().anchorNode;
    if (n && ed.contains(n) && n !== ed) {
      while (n.parentNode !== ed) n = n.parentNode;
    } else {
      n = null;
    }
    var empty = n && n.nodeType === 1 && /^(P|DIV)$/.test(n.tagName) && !n.textContent.trim() &&
      !n.querySelector('img, figure, table');
    if (empty) ed.replaceChild(node, n);
    else if (n) ed.insertBefore(node, n.nextSibling);
    else ed.appendChild(node);
    if (!node.nextSibling) {
      var after = document.createElement('p');
      after.innerHTML = '<br>';
      ed.appendChild(after);
    }
  }

  function placeCaret(target, selectAll) {
    var range = document.createRange();
    range.selectNodeContents(target);
    if (!selectAll) range.collapse(false);
    var sel = document.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
  }

  toolbar.querySelector('select[data-cmd="formatBlock"]').addEventListener('change', function (e) {
    if (!restoreSelection()) return;
    document.execCommand('formatBlock', false, '<' + e.target.value + '>');
    changed();
  });

  function changed() {
    if (activeEditor) { queue(activeEditor); updateWordCount(); updateToolbarState(); }
  }

  function run(cmd) {
    switch (cmd) {
      case 'link':
        var url = prompt('Адрес ссылки (URL):', 'https://');
        if (url) document.execCommand('createLink', false, url);
        break;
      case 'image':
        imageInput.click();
        return;
      case 'table':
        document.execCommand('insertHTML', false,
          '<table><thead><tr><th>Параметр</th><th>Значение</th></tr></thead>' +
          '<tbody><tr><td>&nbsp;</td><td>&nbsp;</td></tr><tr><td>&nbsp;</td><td>&nbsp;</td></tr></tbody></table><p><br></p>');
        break;
      case 'code':
        var sel = document.getSelection();
        var text = sel.toString();
        if (text) document.execCommand('insertHTML', false, '<code>' + escapeHtml(text) + '</code>&#8203;');
        break;
      default:
        document.execCommand(cmd, false, null);
    }
    changed();
  }

  function escapeHtml(s) {
    return s.replace(/[&<>"]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; });
  }

  // ------------------------------------------------------------ images (button + paste + drop)
  // Screenshots are uploaded as files and inserted as numbered figures with a caption.
  function insertImageFile(file) {
    if (!file || !/^image\//.test(file.type)) return;
    var form = new FormData();
    form.append('file', file);
    setState('saving', 'Загрузка изображения…');
    fetch('/api/uploads', { method: 'POST', body: form })
      .then(function (r) { return r.json().then(function (j) { if (!r.ok) throw new Error(j.error); return j; }); })
      .then(function (res) {
        restoreSelection();
        var fig = document.createElement('figure');
        fig.innerHTML = '<img src="' + res.url + '" alt=""><figcaption>' + escapeHtml(window.CAPTION_PH) + '</figcaption>';
        insertBlock(fig);
        placeCaret(fig.querySelector('figcaption'), true);  // type the description right away
        changed();
      })
      .catch(function (err) {
        setState('error', 'Ошибка загрузки');
        toast(err.message || 'Не удалось загрузить изображение', true);
      });
  }


  imageInput.addEventListener('change', function () {
    insertImageFile(imageInput.files[0]);
    imageInput.value = '';
  });

  document.addEventListener('paste', function (e) {
    var ed = e.target.closest && e.target.closest('.rich');
    if (!ed) return;
    var items = Array.from(e.clipboardData.items || []);
    var img = items.find(function (i) { return i.kind === 'file' && /^image\//.test(i.type); });
    e.preventDefault();
    if (img) { insertImageFile(img.getAsFile()); return; }
    // Paste as plain text so every report keeps the same formatting.
    var text = e.clipboardData.getData('text/plain');
    var inPre = document.getSelection().anchorNode;
    inPre = inPre && (inPre.nodeType === 1 ? inPre : inPre.parentElement).closest('pre');
    if (inPre) {
      document.execCommand('insertText', false, text);
    } else {
      var html = text.split(/\r?\n/).map(escapeHtml).join('<br>');
      document.execCommand('insertHTML', false, html);
    }
    changed();
  });

  document.addEventListener('drop', function (e) {
    var ed = e.target.closest && e.target.closest('.rich');
    if (!ed || !e.dataTransfer.files.length) return;
    e.preventDefault();
    ed.focus();
    activeEditor = ed;
    insertImageFile(e.dataTransfer.files[0]);
  });

  // ------------------------------------------------------------ keyboard shortcuts
  document.addEventListener('keydown', function (e) {
    var mod = e.metaKey || e.ctrlKey;
    if (!mod) return;
    var k = e.key.toLowerCase();
    if (k === 's') { e.preventDefault(); flush(); }
    else if (k === 'k' && activeEditor && activeEditor.contains(document.activeElement)) { e.preventDefault(); run('link'); }
    else if (k === 'e' && activeEditor && activeEditor.contains(document.activeElement)) { e.preventDefault(); run('code'); }
    else if (k === 'p' && !e.shiftKey) { e.preventDefault(); flush().then(function () { window.open(document.getElementById('preview-btn').href, '_blank'); }); }
  });

  // Make sure the preview opens with everything saved.
  document.getElementById('preview-btn').addEventListener('click', function (e) {
    if (!pending.size) return;
    e.preventDefault();
    var href = this.href;
    flush().then(function () { window.open(href, '_blank'); });
  });

  // ------------------------------------------------------------ word count & outline highlight
  function updateWordCount() {
    var text = Array.from(document.querySelectorAll('.rich')).map(function (r) { return r.innerText; }).join(' ');
    var n = (text.match(/[\p{L}\p{N}]+/gu) || []).length;
    document.getElementById('wordcount').textContent = n + ' слов · ' + document.querySelectorAll('.finding').length + ' уязв.';
  }

  var canvas = document.getElementById('canvas');
  var outlineLinks = Array.from(document.querySelectorAll('#outline .outline-item'));
  var io = new IntersectionObserver(function (entries) {
    entries.forEach(function (en) {
      if (!en.isIntersecting) return;
      outlineLinks.forEach(function (a) { a.classList.toggle('current', a.getAttribute('href') === '#' + en.target.id); });
    });
  }, { root: canvas, rootMargin: '-20% 0px -70% 0px' });
  document.querySelectorAll('.doc-section').forEach(function (s) { io.observe(s); });

  updateWordCount();
  refreshSummary();
})();
