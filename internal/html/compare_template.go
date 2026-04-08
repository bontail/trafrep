package html

const compareTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Compare</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
  font-family: Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  background: #f3f4f6;
  color: #111827;
  overflow: hidden;
  height: 100vh;
}

:root {
  --panel-bg: rgba(255, 255, 255, 0.94);
  --border: #d1d5db;
  --muted: #6b7280;
  --text-soft: #374151;
  --row-even: #ffffff;
  --row-odd: #f8fafc;
  --left-grad-start: #dbeafe;
  --left-grad-end: #bfdbfe;
  --right-grad-start: #dcfce7;
  --right-grad-end: #bbf7d0;
}

#scroll-outer { overflow: auto; height: 100vh; }

#header {
  position: sticky;
  top: 0;
  z-index: 10;
  background: var(--panel-bg);
  backdrop-filter: blur(8px);
  border-bottom: 1px solid var(--border);
  padding: 10px 16px 8px;
  box-shadow: 0 2px 10px rgba(15, 23, 42, 0.06);
}

#header .names {
  display: flex;
  align-items: stretch;
  gap: 0;
}
#header .name-index-spacer {
  width: 48px;
  min-width: 48px;
  padding-right: 6px;
}
#header .name-card {
  flex: 0 0 auto;
  display: flex;
  align-items: baseline;
  gap: 6px;
  min-width: 0;
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 6px 8px;
}
#header .name-gap {
  width: 6px;
  min-width: 6px;
  border-left: 2px solid var(--border);
}
#header .name-card.left { background: linear-gradient(90deg, var(--left-grad-start), var(--left-grad-end)); }
#header .name-card.right { background: linear-gradient(90deg, var(--right-grad-start), var(--right-grad-end)); }
#header .name-label {
  font-size: 11px;
  color: var(--muted);
  text-transform: uppercase;
  letter-spacing: 0.05em;
  white-space: nowrap;
}
#header .name-value {
  font-size: 13px;
  font-weight: 600;
  color: #111827;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

#header .streams-row {
  display: flex;
  margin-top: 8px;
}
#header .index-col-head {
  width: 48px;
  min-width: 48px;
  text-align: right;
  color: var(--muted);
  font-size: 10px;
  font-weight: 600;
  padding-right: 6px;
  line-height: 28px;
}
#header .half {
  display: flex;
  flex: 0 0 auto;
}
#header .half + .half {
  border-left: 2px solid var(--border);
  padding-left: 6px;
}
#header .stream-col {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 0 6px;
  border-radius: 6px;
  transition: background 0.12s ease;
}
#header .stream-col.is-hovered { background: rgba(79, 70, 229, 0.12); }
#header .stream-col + .stream-col { border-left: 1px solid #e5e7eb; }
#header .stream-col.hidden-stream {
  display: none;
}
#header .stream-col .stream-name { font-size: 11px; font-weight: 700; color: var(--text-soft); }
#header .stream-col .sub-labels { display: flex; gap: 4px; font-size: 10px; color: var(--muted); }
#header .stream-col .sub-labels span { width: 220px; text-align: center; }

.controls-bar {
  display: flex;
  flex-direction: column;
  gap: 8px;
  margin-top: 8px;
  align-items: flex-start;
}
.stream-controls,
.aux-controls {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}
.toggle-group {
  display: flex;
  align-items: center;
  gap: 4px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: #fff;
  padding: 4px 6px;
}
.toggle-group .label { font-size: 11px; font-weight: 600; color: var(--text-soft); margin-right: 2px; }
.toggle-group .visible-count { font-size: 10px; color: var(--muted); margin-right: 4px; }

.toggle-btn,
.action-btn {
  font-size: 10px;
  cursor: pointer;
  border: 1px solid var(--border);
  border-radius: 999px;
  background: #fff;
  padding: 2px 7px;
  color: var(--text-soft);
}
.filter-input {
  font-size: 11px;
  padding: 2px 6px;
  border: 1px solid var(--border);
  border-radius: 6px;
  min-width: 190px;
  color: #111827;
}
.toggle-btn:hover,
.action-btn:hover { background: #f3f4f6; }
.toggle-btn.is-hidden {
  background: #e5e7eb;
  color: #9ca3af;
  text-decoration: line-through;
}

.legend {
  display: flex;
  gap: 12px;
  align-items: center;
  margin-top: 7px;
  font-size: 11px;
  color: var(--muted);
  flex-wrap: wrap;
}
.aux-controls .legend {
  margin-top: 0;
}
.legend .swatch {
  display: inline-block;
  width: 10px;
  height: 10px;
  border-radius: 2px;
  margin-right: 3px;
  vertical-align: middle;
}
.swatch-client { background: #3b82f6; }
.swatch-server { background: #22c55e; }
.swatch-client-delta { background: #ef4444; }
.swatch-server-delta { background: #eab308; }

#content-area { position: relative; }
#scroll-spacer { width: 1px; }
#viewport { position: absolute; top: 0; left: 0; right: 0; }

.row {
  position: absolute;
  left: 0;
  display: flex;
  height: 24px;
  border-bottom: 1px solid #f1f5f9;
}
.row.odd { background: var(--row-odd); }
.row.even { background: var(--row-even); }
.row:hover { background: #eef2ff; }

.row-index {
  width: 48px;
  min-width: 48px;
  text-align: right;
  padding-right: 6px;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 10px;
  color: var(--muted);
  line-height: 24px;
  position: sticky;
  left: 0;
  z-index: 2;
  background: inherit;
}

.half-row { display: flex; }
.half-row + .half-row {
  border-left: 2px solid var(--border);
  padding-left: 6px;
}
.stream-cell {
  display: flex;
  gap: 4px;
  padding: 0 6px;
}
.stream-cell.is-hovered { background: rgba(79, 70, 229, 0.1); }
.stream-cell + .stream-cell { border-left: 1px solid #e5e7eb; }
.stream-cell.hidden-stream {
  display: none;
}

.msg-box {
  width: 220px;
  height: 24px;
  border-radius: 4px;
  color: #fff;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 10px;
  line-height: 24px;
  padding: 0 5px;
  overflow: hidden;
  white-space: nowrap;
  text-overflow: ellipsis;
}
.msg-box.filtered-out { opacity: 0.25; }
.empty-box { width: 220px; height: 24px; }

body.is-dense .row { height: 21px; }
body.is-dense .row-index { line-height: 21px; }
body.is-dense .msg-box {
  width: 170px;
  height: 20px;
  line-height: 20px;
  font-size: 9px;
}
body.is-dense .empty-box { width: 170px; height: 20px; }
body.is-dense #header .stream-col .sub-labels span { width: 170px; }

.client { background: #3b82f6; }
.server { background: #22c55e; }
.client-delta { background: #ef4444; }
.server-delta {
  background: #eab308;
  color: #111827;
}
.diverged {
  outline: 2px solid #f97316;
  outline-offset: -2px;
  opacity: 0.86;
}

.diverge-row {
  position: absolute;
  left: 0;
  right: 0;
  height: 0;
  border-top: 2px dashed #f97316;
  z-index: 5;
  pointer-events: none;
}
.diverge-label {
  position: absolute;
  right: 4px;
  top: -14px;
  font-size: 9px;
  color: #f97316;
  background: #f9fafb;
  padding: 0 3px;
  border-radius: 2px;
  white-space: nowrap;
  pointer-events: none;
}

@media (max-width: 1200px) {
  #header { padding: 8px 10px 6px; }
  .toggle-group .visible-count,
  .legend { font-size: 10px; }
}
#header .half-left { order: 0; }
#header .half-right { order: 1; }
.half-row.left-lane { order: 0; }
.half-row.right-lane { order: 1; }
</style>
</head>
<body>
<div id="scroll-outer">
  <div id="header"></div>
  <div id="content-area">
    <div id="scroll-spacer"></div>
    <div id="viewport"></div>
  </div>
</div>

<script>
const DATA = /*__DATA__*/null;
let SUB_COL_W = 220;
const SUB_COL_GAP = 4;
const STREAM_PAD = 12;
const INDEX_COL_W = 48;
let ROW_HEIGHT = 25;
const OVERSCAN = 10;
let TRUNCATE_LEN = 28;

let uiDensity = 'comfortable';
let typeFilter = '';
let hoveredStream = -1;

// Visibility state: true = visible
const leftVisible = DATA.left.map(() => false);
const rightVisible = DATA.right.map(() => false);

// Precompute relative times and deltas
const leftRelMs = [];
const rightRelMs = [];
const deltas = [];
const leftTypeNamesLower = DATA.left.map((s) => s.map((m) => m.typeName.toLowerCase()));
const rightTypeNamesLower = DATA.right.map((s) => s.map((m) => m.typeName.toLowerCase()));

let leftBase = Infinity, rightBase = Infinity;
DATA.left.forEach(s => s.forEach(m => { if (m.relMs < leftBase) leftBase = m.relMs; }));
DATA.right.forEach(s => s.forEach(m => { if (m.relMs < rightBase) rightBase = m.relMs; }));
if (!isFinite(leftBase)) leftBase = 0;
if (!isFinite(rightBase)) rightBase = 0;

DATA.left.forEach(s => {
  leftRelMs.push(s.map(m => m.relMs - leftBase));
});
DATA.right.forEach(s => {
  rightRelMs.push(s.map(m => m.relMs - rightBase));
});

const minStreams = Math.min(DATA.left.length, DATA.right.length);
DATA.right.forEach((s, si) => {
  const streamDeltas = [];
  s.forEach((m, mi) => {
    if (si < minStreams && mi < DATA.left[si].length) {
      const leftRel = DATA.left[si][mi].relMs - leftBase;
      const rightRel = m.relMs - rightBase;
      const d = rightRel - leftRel;
      if (Math.abs(d) > DATA.deltaShowThreshMs) {
        streamDeltas.push({hasDelta: true, deltaMs: d, isServer: m.isServer});
      } else {
        streamDeltas.push({hasDelta: false});
      }
    } else {
      streamDeltas.push({hasDelta: false});
    }
  });
  deltas.push(streamDeltas);
});

// Max rows
let maxRows = 0;
DATA.left.forEach(s => { if (s.length > maxRows) maxRows = s.length; });
DATA.right.forEach(s => { if (s.length > maxRows) maxRows = s.length; });

// Build header
const headerEl = document.getElementById('header');
const namesDiv = document.createElement('div');
namesDiv.className = 'names';

const nameIndexSpacer = document.createElement('div');
nameIndexSpacer.className = 'name-index-spacer';

const leftNameCard = document.createElement('div');
leftNameCard.className = 'name-card left';
leftNameCard.innerHTML = '<span class="name-label">Left</span><span class="name-value">' + esc(DATA.leftName) + '</span>';

const nameGap = document.createElement('div');
nameGap.className = 'name-gap';

const rightNameCard = document.createElement('div');
rightNameCard.className = 'name-card right';
rightNameCard.innerHTML = '<span class="name-label">Right</span><span class="name-value">' + esc(DATA.rightName) + '</span>';

namesDiv.appendChild(nameIndexSpacer);
namesDiv.appendChild(leftNameCard);
namesDiv.appendChild(nameGap);
namesDiv.appendChild(rightNameCard);
headerEl.appendChild(namesDiv);

const streamsRow = document.createElement('div');
streamsRow.className = 'streams-row';

const leftHeaderCols = [];
const rightHeaderCols = [];

function buildHalfHeader(streams, colsArr, side) {
  const half = document.createElement('div');
  half.className = 'half half-' + side;
  for (let i = 0; i < streams.length; i++) {
    const col = document.createElement('div');
    col.className = 'stream-col';
    col.dataset.side = side;
    col.dataset.stream = String(i);
    col.innerHTML = '<span class="stream-name">Stream ' + (i + 1) + '</span>' +
      '<div class="sub-labels"><span>client</span><span>server</span></div>';
    half.appendChild(col);
    colsArr.push(col);
  }
  return half;
}

const indexHead = document.createElement('div');
indexHead.className = 'index-col-head';
indexHead.textContent = '#';
streamsRow.appendChild(indexHead);
streamsRow.appendChild(buildHalfHeader(DATA.left, leftHeaderCols, 'left'));
streamsRow.appendChild(buildHalfHeader(DATA.right, rightHeaderCols, 'right'));
headerEl.appendChild(streamsRow);

// Toggle buttons bar
const controlsBar = document.createElement('div');
controlsBar.className = 'controls-bar';
const streamControls = document.createElement('div');
streamControls.className = 'stream-controls';
const auxControls = document.createElement('div');
auxControls.className = 'aux-controls';

function countVisible(visArr) {
  let n = 0;
  for (let i = 0; i < visArr.length; i++) if (visArr[i]) n++;
  return n;
}

function addToggleButtons(label, count, visArr, headerCols) {
  const group = document.createElement('div');
  group.className = 'toggle-group';

  const lbl = document.createElement('span');
  lbl.className = 'label';
  lbl.textContent = label;
  group.appendChild(lbl);

  const stat = document.createElement('span');
  stat.className = 'visible-count';
  group.appendChild(stat);

  const buttons = [];

  function refreshGroup() {
    stat.textContent = countVisible(visArr) + '/' + count;
  }

  function setAll(visible) {
    for (let i = 0; i < count; i++) {
      visArr[i] = visible;
      buttons[i].classList.toggle('is-hidden', !visible);
      headerCols[i].classList.toggle('hidden-stream', !visible);
    }
    refreshGroup();
    updateLayout();
    forceRender();
  }

  const showAllBtn = document.createElement('button');
  showAllBtn.className = 'action-btn';
  showAllBtn.textContent = 'all';
  showAllBtn.title = 'Show all streams';
  showAllBtn.addEventListener('click', () => setAll(true));
  group.appendChild(showAllBtn);

  const hideAllBtn = document.createElement('button');
  hideAllBtn.className = 'action-btn';
  hideAllBtn.textContent = 'none';
  hideAllBtn.title = 'Hide all streams';
  hideAllBtn.addEventListener('click', () => setAll(false));
  group.appendChild(hideAllBtn);

  for (let i = 0; i < count; i++) {
    const btn = document.createElement('button');
    btn.className = 'toggle-btn';
    btn.textContent = 'S' + (i + 1);
    btn.title = 'Toggle Stream ' + (i + 1);
    btn.classList.toggle('is-hidden', !visArr[i]);
    headerCols[i].classList.toggle('hidden-stream', !visArr[i]);
    btn.addEventListener('click', () => {
      visArr[i] = !visArr[i];
      btn.classList.toggle('is-hidden', !visArr[i]);
      headerCols[i].classList.toggle('hidden-stream', !visArr[i]);
      refreshGroup();
      updateLayout();
      forceRender();
    });
    buttons.push(btn);
    group.appendChild(btn);
  }

  refreshGroup();
  streamControls.appendChild(group);
}

addToggleButtons('Left', DATA.left.length, leftVisible, leftHeaderCols);
addToggleButtons('Right', DATA.right.length, rightVisible, rightHeaderCols);

const densityGroup = document.createElement('div');
densityGroup.className = 'toggle-group';
densityGroup.innerHTML = '<span class="label">Density</span>';
const comfyBtn = document.createElement('button');
comfyBtn.className = 'action-btn';
comfyBtn.textContent = 'comfortable';
const denseBtn = document.createElement('button');
denseBtn.className = 'action-btn';
denseBtn.textContent = 'dense';
densityGroup.appendChild(comfyBtn);
densityGroup.appendChild(denseBtn);
auxControls.appendChild(densityGroup);

const filterGroup = document.createElement('div');
filterGroup.className = 'toggle-group';
const filterLabel = document.createElement('span');
filterLabel.className = 'label';
filterLabel.textContent = 'Filter';
const filterInput = document.createElement('input');
filterInput.className = 'filter-input';
filterInput.placeholder = 'typeName contains...';
const clearFilterBtn = document.createElement('button');
clearFilterBtn.className = 'action-btn';
clearFilterBtn.textContent = 'clear';
filterGroup.appendChild(filterLabel);
filterGroup.appendChild(filterInput);
filterGroup.appendChild(clearFilterBtn);
auxControls.appendChild(filterGroup);

const legend = document.createElement('div');
legend.className = 'legend';
legend.innerHTML = '<span><span class="swatch swatch-client"></span>client</span>' +
  '<span><span class="swatch swatch-server"></span>server</span>' +
  '<span><span class="swatch swatch-client-delta"></span>client delta</span>' +
  '<span><span class="swatch swatch-server-delta"></span>server delta</span>' +
  '<span><span class="swatch" style="background:#f97316;opacity:.75"></span>diverged</span>';
auxControls.appendChild(legend);

controlsBar.appendChild(streamControls);
controlsBar.appendChild(auxControls);
headerEl.appendChild(controlsBar);

// Layout
const spacer = document.getElementById('scroll-spacer');
spacer.style.height = (maxRows * ROW_HEIGHT) + 'px';

const viewport = document.getElementById('viewport');
const container = document.getElementById('scroll-outer');

function currentStreamW() {
  return SUB_COL_W * 2 + SUB_COL_GAP + STREAM_PAD;
}

function halfW(count) {
  return count > 0 ? count * currentStreamW() : 0;
}

function updateLayout() {
  const leftCount = countVisible(leftVisible);
  const rightCount = countVisible(rightVisible);
  const hasLeft = leftCount > 0;
  const hasRight = rightCount > 0;
  const midGap = hasLeft && hasRight ? 6 : 0;
  const leftW = halfW(leftCount);
  const rightW = halfW(rightCount);
  const w = 20 + INDEX_COL_W + leftW + midGap + rightW + 20;

  namesDiv.style.display = hasLeft || hasRight ? 'flex' : 'none';
  nameIndexSpacer.style.display = hasLeft || hasRight ? 'block' : 'none';
  leftNameCard.style.display = hasLeft ? 'flex' : 'none';
  rightNameCard.style.display = hasRight ? 'flex' : 'none';

  leftNameCard.style.width = leftW + 'px';
  rightNameCard.style.width = rightW + 'px';
  nameGap.style.display = midGap > 0 ? 'block' : 'none';

  viewport.style.minWidth = w + 'px';
  spacer.style.minWidth = w + 'px';
  headerEl.style.minWidth = w + 'px';
}
updateLayout();

function updateDensityButtons() {
  comfyBtn.classList.toggle('is-hidden', uiDensity !== 'comfortable');
  denseBtn.classList.toggle('is-hidden', uiDensity !== 'dense');
}

function applyDensity(nextDensity) {
  uiDensity = nextDensity;
  if (uiDensity === 'dense') {
    SUB_COL_W = 170;
    ROW_HEIGHT = 21;
    TRUNCATE_LEN = 20;
    document.body.classList.add('is-dense');
  } else {
    SUB_COL_W = 220;
    ROW_HEIGHT = 25;
    TRUNCATE_LEN = 28;
    document.body.classList.remove('is-dense');
  }
  spacer.style.height = (maxRows * ROW_HEIGHT) + 'px';
  updateDensityButtons();
  updateLayout();
  forceRender();
  renderDivergeLines();
}

function setHoveredStream(next) {
  if (hoveredStream === next) return;
  hoveredStream = next;
  leftHeaderCols.forEach((col, i) => col.classList.toggle('is-hovered', i === hoveredStream));
  rightHeaderCols.forEach((col, i) => col.classList.toggle('is-hovered', i === hoveredStream));
  document.querySelectorAll('.stream-cell').forEach((cell) => {
    cell.classList.toggle('is-hovered', Number(cell.dataset.stream) === hoveredStream);
  });
}

comfyBtn.addEventListener('click', () => applyDensity('comfortable'));
denseBtn.addEventListener('click', () => applyDensity('dense'));

filterInput.addEventListener('input', () => {
  typeFilter = filterInput.value.trim().toLowerCase();
  forceRender();
});
clearFilterBtn.addEventListener('click', () => {
  filterInput.value = '';
  typeFilter = '';
  forceRender();
});

headerEl.addEventListener('mouseover', (e) => {
  const col = e.target.closest('.stream-col');
  if (!col) return;
  setHoveredStream(Number(col.dataset.stream));
});
headerEl.addEventListener('mouseleave', () => setHoveredStream(-1));
viewport.addEventListener('mouseover', (e) => {
  const cell = e.target.closest('.stream-cell');
  if (!cell) return;
  setHoveredStream(Number(cell.dataset.stream));
});
viewport.addEventListener('mouseleave', () => setHoveredStream(-1));

let lastStart = -1, lastEnd = -1;

function forceRender() {
  lastStart = -1;
  lastEnd = -1;
  render();
}

function render() {
  const headerH = headerEl.offsetHeight;
  const scrollTop = Math.max(0, container.scrollTop - headerH);
  const viewH = container.clientHeight;
  let start = Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN;
  let end = Math.ceil((scrollTop + viewH) / ROW_HEIGHT) + OVERSCAN;
  if (start < 0) start = 0;
  if (end > maxRows) end = maxRows;

  if (start === lastStart && end === lastEnd) return;
  lastStart = start;
  lastEnd = end;

  const frag = document.createDocumentFragment();
  for (let row = start; row < end; row++) {
    const rowEl = document.createElement('div');
    rowEl.className = 'row ' + (row % 2 === 0 ? 'even' : 'odd');
    rowEl.style.top = (row * ROW_HEIGHT) + 'px';

    const rowIndex = document.createElement('div');
    rowIndex.className = 'row-index';
    rowIndex.textContent = String(row + 1);
    rowEl.appendChild(rowIndex);

    // Left half
    const leftHalf = document.createElement('div');
    leftHalf.className = 'half-row left-lane';
    for (let si = 0; si < DATA.left.length; si++) {
      if (!leftVisible[si]) continue;
      const cell = document.createElement('div');
      cell.className = 'stream-cell';
      cell.dataset.stream = String(si);
      if (si === hoveredStream) cell.classList.add('is-hovered');
      const msgs = DATA.left[si];
      if (row < msgs.length) {
        const m = msgs[row];
        const relMs = leftRelMs[si][row];
        const low = leftTypeNamesLower[si][row];
        cell.appendChild(makeBox(m, relMs, null, false, si, row, low));
      } else {
        cell.innerHTML = '<div class="empty-box"></div><div class="empty-box"></div>';
      }
      leftHalf.appendChild(cell);
    }
    rowEl.appendChild(leftHalf);

    // Right half
    const rightHalf = document.createElement('div');
    rightHalf.className = 'half-row right-lane';
    for (let si = 0; si < DATA.right.length; si++) {
      if (!rightVisible[si]) continue;
      const cell = document.createElement('div');
      cell.className = 'stream-cell';
      cell.dataset.stream = String(si);
      if (si === hoveredStream) cell.classList.add('is-hovered');
      const msgs = DATA.right[si];
      if (row < msgs.length) {
        const m = msgs[row];
        const relMs = rightRelMs[si][row];
        const di = deltas[si][row];
        const low = rightTypeNamesLower[si][row];
        cell.appendChild(makeBox(m, relMs, di, true, si, row, low));
      } else {
        cell.innerHTML = '<div class="empty-box"></div><div class="empty-box"></div>';
      }
      rightHalf.appendChild(cell);
    }
    rowEl.appendChild(rightHalf);

    frag.appendChild(rowEl);
  }
  viewport.innerHTML = '';
  viewport.appendChild(frag);
}

function makeBox(m, relMs, di, isRight, si, row, typeNameLower) {
  const clientBox = document.createElement('div');
  const serverBox = document.createElement('div');

  const activeBox = m.isServer ? serverBox : clientBox;
  const inactiveBox = m.isServer ? clientBox : serverBox;

  inactiveBox.className = 'empty-box';

  let cls = m.isServer ? 'server' : 'client';
  if (isRight && di && di.hasDelta && Math.abs(di.deltaMs) > DATA.deltaColorThreshMs) {
    cls = m.isServer ? 'server-delta' : 'client-delta';
  }

  const streamRanges = DATA.divergeRanges ? DATA.divergeRanges[si] : null;
  const isDiverged = streamRanges && streamRanges.some(([start, end]) =>
    row >= start && (end < 0 || row < end)
  );

  activeBox.className = 'msg-box ' + cls + (isDiverged ? ' diverged' : '');
  if (typeFilter && !typeNameLower.includes(typeFilter)) {
    activeBox.classList.add('filtered-out');
  }

  let text = formatRelTime(relMs);
  if (isRight && di && di.hasDelta) {
    text += '(' + formatDelta(di.deltaMs) + ')';
  }
  text += ' ' + truncate(m.typeName, TRUNCATE_LEN);
  activeBox.textContent = text;

  const side = isRight ? 'right' : 'left';
  const fullDelta = isRight && di && di.hasDelta ? ' delta=' + formatDelta(di.deltaMs) : '';
  activeBox.title = side + ' S' + (si + 1) + ' row ' + (row + 1) + '\n' +
    't=' + formatRelTime(relMs) + fullDelta + '\n' + m.typeName + (isDiverged ? '\nDIVERGED' : '');

  const wrapper = document.createDocumentFragment();
  wrapper.appendChild(clientBox);
  wrapper.appendChild(serverBox);
  return wrapper;
}

function formatRelTime(ms) {
  if (ms < 0) ms = 0;
  const totalMs = Math.floor(ms);
  if (totalMs < 1000) return totalMs + 'ms';
  const sec = Math.floor(totalMs / 1000);
  const rem = totalMs % 1000;
  const pad = String(rem).padStart(3, '0');
  if (sec < 60) return sec + '.' + pad;
  const min = Math.floor(sec / 60);
  const s = sec % 60;
  return min + 'm' + s + '.' + pad;
}

function formatDelta(ms) {
  if (ms === 0) return '0ms';
  const sign = ms > 0 ? '+' : '';
  const abs = Math.abs(ms);
  if (abs >= 1000) return sign + (ms / 1000).toFixed(1) + 's';
  if (abs >= 1) return sign + ms.toFixed(1) + 'ms';
  return sign + Math.round(ms * 1000) + 'us';
}

function truncate(s, n) {
  if (s.length <= n) return s;
  return s.substring(0, n - 1) + '\u2026';
}

function esc(s) {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

// Diverge lines — static, rendered once
function renderDivergeLines() {
  document.querySelectorAll('.diverge-row').forEach(e => e.remove());
  if (!DATA.divergeRanges) return;

  function makeLine(rowIdx, label) {
    const el = document.createElement('div');
    el.className = 'diverge-row';
    el.style.top = (rowIdx * ROW_HEIGHT - 2) + 'px';
    if (label) {
      const lbl = document.createElement('div');
      lbl.className = 'diverge-label';
      lbl.textContent = label;
      el.appendChild(lbl);
    }
    viewport.appendChild(el);
  }

  // Collect start/end rows across all streams, merge labels for same row
  const startMap = new Map(); // rowIdx -> Set of stream nums
  const endMap   = new Map();

  DATA.divergeRanges.forEach((ranges, si) => {
    ranges.forEach(([start, end]) => {
      if (!startMap.has(start)) startMap.set(start, new Set());
      startMap.get(start).add(si + 1);
      if (end >= 0) {
        if (!endMap.has(end)) endMap.set(end, new Set());
        endMap.get(end).add(si + 1);
      }
    });
  });

  startMap.forEach((streams, rowIdx) => {
    makeLine(rowIdx, 'diverge start S' + [...streams].join(',S'));
  });
  endMap.forEach((streams, rowIdx) => {
    makeLine(rowIdx, 'diverge end S' + [...streams].join(',S'));
  });
}

container.addEventListener('scroll', render);
window.addEventListener('resize', forceRender);
updateDensityButtons();
render();
renderDivergeLines();
</script>
</body>
</html>`
