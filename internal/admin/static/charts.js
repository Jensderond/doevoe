// doevoe admin dashboard charts — dependency-free ES module.
//
// Reads the JSON embedded by the dashboard handler in #dashboard-data and
// renders three SVG charts (daily volume, volume by domain, top failure
// reasons) with real axes, gridlines and hover tooltips. All colors are the
// CSS custom properties from doevoe.css (var(--green) etc.), so the charts
// follow the light/dark theme automatically — no hardcoded hex anywhere.
//
// Loaded once from layout.html (outside #shell); htmx boosted navigation
// swaps #shell, so re-rendering is driven by the htmx:afterSettle event.

const NS = 'http://www.w3.org/2000/svg';

function svgEl(name, attrs = {}) {
  const e = document.createElementNS(NS, name);
  for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
  return e;
}

function line(x1, y1, x2, y2, attrs = {}) {
  return svgEl('line', { x1, y1, x2, y2, stroke: 'var(--line)', ...attrs });
}

function text(str, x, y, opts = {}) {
  const t = svgEl('text', {
    x, y,
    'text-anchor': opts.anchor || 'start',
    fill: opts.fill || 'var(--muted)',
    'font-size': opts.size || 10,
    'font-family': 'var(--font-mono)',
  });
  t.textContent = str;
  return t;
}

// ---- nice-number axis ticks ------------------------------------------------

function niceStep(rough) {
  const pow = Math.pow(10, Math.floor(Math.log10(rough)));
  const f = rough / pow;
  const nf = f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10;
  return nf * pow;
}

// Integer "nice" ticks from 0 up to a rounded-up top >= max.
function ticksFor(max, count = 4) {
  if (max <= 0) max = 1;
  let step = niceStep(max / count);
  if (step < 1) step = 1;
  const top = Math.ceil(max / step) * step;
  const ticks = [];
  for (let v = 0; v <= top; v += step) ticks.push(v);
  return { top, ticks };
}

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
  'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

function fmtDate(iso) { // "2026-07-05" → "Jul 5"
  const [, m, d] = iso.split('-');
  return `${MONTHS[+m - 1]} ${+d}`;
}

// Approximate monospace glyph width at a given font-size (used for label
// column sizing and ellipsizing; SVG has no CSS text-overflow).
function charW(size) { return size * 0.62; }

function ellipsize(s, maxPx, size) {
  const max = Math.max(3, Math.floor(maxPx / charW(size)));
  return s.length <= max ? s : s.slice(0, max - 1) + '…';
}

// ---- shared tooltip ----------------------------------------------------------

let tipEl = null;

function tip() {
  if (!tipEl || !tipEl.isConnected) {
    tipEl = document.createElement('div');
    tipEl.className = 'chart-tip';
    tipEl.hidden = true;
    document.body.appendChild(tipEl); // outside #shell: survives htmx swaps
  }
  return tipEl;
}

function moveTip(evt) {
  const t = tip();
  const pad = 12;
  let x = evt.pageX + pad;
  let y = evt.pageY + pad;
  if (x + t.offsetWidth > window.scrollX + document.documentElement.clientWidth - 6) {
    x = evt.pageX - t.offsetWidth - pad;
  }
  if (y + t.offsetHeight > window.scrollY + document.documentElement.clientHeight - 6) {
    y = evt.pageY - t.offsetHeight - pad;
  }
  t.style.left = x + 'px';
  t.style.top = y + 'px';
}

function showTip(evt, str) {
  const t = tip();
  t.textContent = str;
  t.hidden = false;
  moveTip(evt);
}

function hideTip() { if (tipEl) tipEl.hidden = true; }

function hover(el, str, highlight) {
  el.addEventListener('pointerenter', (e) => {
    if (highlight) highlight(true);
    showTip(e, str);
  });
  el.addEventListener('pointermove', moveTip);
  el.addEventListener('pointerleave', () => {
    if (highlight) highlight(false);
    hideTip();
  });
}

// ---- bar shapes (rounded on the data end only, square at the baseline) ------

function topRoundedRect(x, y, w, h, r) {
  r = Math.min(r, w / 2, h);
  return `M${x},${y + h} L${x},${y + r} Q${x},${y} ${x + r},${y}` +
    ` L${x + w - r},${y} Q${x + w},${y} ${x + w},${y + r} L${x + w},${y + h} Z`;
}

function rightRoundedRect(x, y, w, h, r) {
  r = Math.min(r, h / 2, w);
  return `M${x},${y} L${x + w - r},${y} Q${x + w},${y} ${x + w},${y + r}` +
    ` L${x + w},${y + h - r} Q${x + w},${y + h} ${x + w - r},${y + h} L${x},${y + h} Z`;
}

function bar(d, fill) {
  return svgEl('path', { d, fill });
}

function empty(box) {
  const p = document.createElement('p');
  p.className = 'empty';
  p.textContent = 'No data for this range.';
  box.replaceChildren(p);
}

function chartWidth(box) {
  return Math.max(box.clientWidth || 640, 280);
}

// ---- volume over time (stacked columns) --------------------------------------

function drawVolume(box, daily) {
  if (!box) return;
  const totSent = daily.reduce((s, d) => s + d.sent, 0);
  const totFailed = daily.reduce((s, d) => s + d.failed, 0);
  if (!daily.length || totSent + totFailed === 0) return empty(box);

  const width = chartWidth(box);
  const height = 220;
  const maxDay = Math.max(...daily.map((d) => d.sent + d.failed));
  const { top, ticks } = ticksFor(maxDay);

  const mLeft = Math.ceil(String(top).length * charW(10)) + 12;
  const mRight = 20; // room for the newest date label, which is always drawn
  const mTop = 8;
  const mBottom = 24;
  const plotW = width - mLeft - mRight;
  const plotH = height - mTop - mBottom;
  const baseY = mTop + plotH;

  const svg = svgEl('svg', {
    viewBox: `0 0 ${width} ${height}`,
    height,
    role: 'img',
    'aria-label': `Daily email volume over ${daily.length} days: ` +
      `${totSent} sent, ${totFailed} failed.`,
  });

  // Y axis: gridlines + labels.
  for (const v of ticks) {
    const y = baseY - (v / top) * plotH;
    if (v > 0) svg.append(line(mLeft, y, mLeft + plotW, y));
    svg.append(text(String(v), mLeft - 6, y + 3, { anchor: 'end' }));
  }
  // Baseline slightly stronger than the grid.
  svg.append(line(mLeft, baseY, mLeft + plotW, baseY,
    { stroke: 'var(--muted)', 'stroke-opacity': 0.55 }));

  const n = daily.length;
  const band = plotW / n;
  const barW = Math.min(band * 0.72, 22);
  const labelStep = Math.ceil(n / 7); // ~7 date labels, never one per day

  daily.forEach((d, i) => {
    const cx = mLeft + band * i + band / 2;

    // X axis: thinned date ticks, anchored so the newest day is labeled.
    if ((n - 1 - i) % labelStep === 0) {
      svg.append(line(cx, baseY, cx, baseY + 4, { stroke: 'var(--muted)', 'stroke-opacity': 0.55 }));
      svg.append(text(fmtDate(d.date), cx, baseY + 16, { anchor: 'middle' }));
    }

    const x = cx - barW / 2;
    const sentH = (d.sent / top) * plotH;
    const failH = (d.failed / top) * plotH;
    const gap = d.sent > 0 && d.failed > 0 ? 1.5 : 0; // spacer between segments
    const marks = [];
    if (d.sent > 0) {
      marks.push(bar(
        d.failed > 0
          ? `M${x},${baseY} L${x},${baseY - sentH} L${x + barW},${baseY - sentH} L${x + barW},${baseY} Z`
          : topRoundedRect(x, baseY - sentH, barW, sentH, 2),
        'var(--green)'));
    }
    if (d.failed > 0) {
      marks.push(bar(topRoundedRect(x, baseY - sentH - gap - failH, barW, failH, 2), 'var(--red)'));
    }
    svg.append(...marks);

    // Full-height hit area: hoverable even on empty/short days.
    const hit = svgEl('rect', {
      x: mLeft + band * i, y: mTop, width: band, height: plotH,
      fill: 'var(--ink)', 'fill-opacity': 0,
    });
    hover(hit, `${fmtDate(d.date)} — ${d.sent} sent, ${d.failed} failed`,
      (on) => hit.setAttribute('fill-opacity', on ? 0.05 : 0));
    svg.append(hit);
  });

  box.replaceChildren(svg);
}

// ---- horizontal bars (domains, failure reasons) -------------------------------

function drawHBars(box, rows, ariaLabel) {
  if (!box) return;
  if (!rows.length || rows.every((r) => r.value === 0)) return empty(box);

  const width = chartWidth(box);
  const rowH = 28;
  const mTop = 4;
  const mBottom = 22;
  const height = mTop + rows.length * rowH + mBottom;
  const maxV = Math.max(...rows.map((r) => r.value));
  const { top, ticks } = ticksFor(maxV);

  const labelSize = 11;
  const labelW = Math.min(Math.round(width * 0.32), 180);
  const mLeft = labelW + 10;
  const mRight = Math.ceil(String(maxV).length * charW(10)) + 14;
  const plotW = width - mLeft - mRight;
  const plotBottom = mTop + rows.length * rowH;

  const svg = svgEl('svg', {
    viewBox: `0 0 ${width} ${height}`,
    height,
    role: 'img',
    'aria-label': ariaLabel,
  });

  // X axis: vertical gridlines + value labels.
  for (const v of ticks) {
    const x = mLeft + (v / top) * plotW;
    if (v > 0) svg.append(line(x, mTop, x, plotBottom));
    svg.append(text(String(v), x, height - 7, { anchor: 'middle' }));
  }
  // Zero-baseline slightly stronger than the grid.
  svg.append(line(mLeft, mTop, mLeft, plotBottom,
    { stroke: 'var(--muted)', 'stroke-opacity': 0.55 }));

  rows.forEach((r, i) => {
    const yMid = mTop + rowH * i + rowH / 2;

    const lbl = text(ellipsize(r.label, labelW, labelSize), labelW, yMid + 3.5,
      { anchor: 'end', fill: 'var(--ink)', size: labelSize });
    const full = svgEl('title');
    full.textContent = r.label;
    lbl.append(full);
    svg.append(lbl);

    const barLen = Math.max((r.value / top) * plotW, r.value > 0 ? 1 : 0);
    const mark = bar(rightRoundedRect(mLeft, yMid - 6, barLen, 12, 2), 'var(--blue)');
    svg.append(mark);
    svg.append(text(String(r.value), mLeft + barLen + 6, yMid + 3.5, {}));

    const hit = svgEl('rect', {
      x: 0, y: mTop + rowH * i, width, height: rowH,
      fill: 'var(--ink)', 'fill-opacity': 0,
    });
    hover(hit, r.tip, (on) => hit.setAttribute('fill-opacity', on ? 0.05 : 0));
    svg.append(hit);
  });

  box.replaceChildren(svg);
}

// ---- entry point ----------------------------------------------------------------

function render() {
  const src = document.getElementById('dashboard-data');
  if (!src) return; // not the dashboard page
  let data;
  try {
    data = JSON.parse(src.textContent);
  } catch {
    return;
  }

  drawVolume(document.getElementById('chart-volume'), data.daily || []);

  drawHBars(
    document.getElementById('chart-domains'),
    (data.domains || []).map((d) => ({
      label: d.name,
      value: d.sent + d.failed,
      tip: `${d.name} — ${d.sent + d.failed} total (${d.sent} sent, ${d.failed} failed)`,
    })),
    'Email volume by domain, horizontal bar chart.');

  drawHBars(
    document.getElementById('chart-reasons'),
    (data.reasons || []).map((r) => ({
      label: r.reason,
      value: r.count,
      tip: `${r.reason} — ${r.count}`,
    })),
    'Top failure reasons, horizontal bar chart.');
}

render();
// htmx boosted navigation (incl. the 7/30/90 range toggle) swaps #shell.
document.body.addEventListener('htmx:afterSettle', () => {
  hideTip();
  render();
});
let resizeTimer;
window.addEventListener('resize', () => {
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(render, 120);
});
