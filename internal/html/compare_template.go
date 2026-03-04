package html

const compareTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Compare</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: sans-serif; background: #fafafa; overflow: hidden; height: 100vh; }

#scroll-outer { overflow: auto; height: 100vh; }

#header {
  position: sticky; top: 0; z-index: 10; background: #fafafa;
  border-bottom: 1px solid #ccc; padding: 8px 20px;
}
#header .names {
  display: flex; justify-content: space-around; font-size: 14px; font-weight: bold; color: #333;
}
#header .streams-row {
  display: flex; margin-top: 4px;
}
#header .half {
  display: flex; flex: 1;
}
#header .half + .half {
  border-left: 2px solid #ccc;
  padding-left: 6px;
}
#header .stream-col {
  display: flex; flex-direction: column; align-items: center;
  padding: 0 6px;
}
#header .stream-col + .stream-col {
  border-left: 1px solid #ddd;
}
#header .stream-col.hidden-stream { display: none; }
#header .stream-col .stream-name { font-size: 11px; font-weight: bold; color: #555; }
#header .stream-col .sub-labels { display: flex; gap: 4px; font-size: 10px; color: #888; }
#header .stream-col .sub-labels span { width: 200px; text-align: center; }

.toggle-btn {
  font-size: 10px; cursor: pointer; border: 1px solid #ccc; border-radius: 3px;
  background: #fff; padding: 1px 6px; margin-top: 2px; color: #555;
}
.toggle-btn:hover { background: #eee; }
.toggle-btn.is-hidden { background: #ddd; color: #999; }

.toggles-bar {
  display: flex; gap: 4px; margin-top: 4px; flex-wrap: wrap; align-items: center;
  font-size: 10px; color: #888;
}
.toggles-bar .label { margin-right: 2px; }

.legend {
  display: flex; gap: 16px; align-items: center; margin-top: 4px; font-size: 11px; color: #888;
}
.legend .swatch {
  display: inline-block; width: 10px; height: 10px; border-radius: 2px; margin-right: 3px; vertical-align: middle;
}
.swatch-client { background: #3b82f6; }
.swatch-server { background: #22c55e; }
.swatch-client-delta { background: #ef4444; }
.swatch-server-delta { background: #eab308; }

#content-area { position: relative; }
#scroll-spacer { width: 1px; }
#viewport { position: absolute; top: 0; left: 0; right: 0; }

.row {
  position: absolute; left: 0; display: flex; height: 22px;
}
.half-row {
  display: flex;
}
.half-row + .half-row {
  border-left: 2px solid #ccc;
  padding-left: 6px;
}
.stream-cell {
  display: flex; gap: 4px; padding: 0 6px;
}
.stream-cell + .stream-cell {
  border-left: 1px solid #ddd;
}
.stream-cell.hidden-stream { display: none; }
.msg-box {
  width: 200px; height: 22px; border-radius: 3px; color: #fff;
  font-family: monospace; font-size: 10px; line-height: 22px;
  padding: 0 3px; overflow: hidden; white-space: nowrap; text-overflow: ellipsis;
}
.empty-box { width: 200px; height: 22px; }

.client { background: #3b82f6; }
.server { background: #22c55e; }
.client-delta { background: #ef4444; }
.server-delta { background: #eab308; }
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
const SUB_COL_W = 200;
const SUB_COL_GAP = 4;
const STREAM_PAD = 12;
const ROW_HEIGHT = 25;
const OVERSCAN = 10;
const TRUNCATE_LEN = 18;

// Visibility state: true = visible
const leftVisible = DATA.left.map(() => true);
const rightVisible = DATA.right.map(() => true);

// Precompute relative times and deltas
const leftRelMs = [];
const rightRelMs = [];
const deltas = [];

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
namesDiv.innerHTML = '<span>' + esc(DATA.leftName) + '</span><span>' + esc(DATA.rightName) + '</span>';
headerEl.appendChild(namesDiv);

const streamsRow = document.createElement('div');
streamsRow.className = 'streams-row';

const leftHeaderCols = [];
const rightHeaderCols = [];

function buildHalfHeader(streams, colsArr) {
  const half = document.createElement('div');
  half.className = 'half';
  for (let i = 0; i < streams.length; i++) {
    const col = document.createElement('div');
    col.className = 'stream-col';
    col.innerHTML = '<span class="stream-name">Stream ' + (i+1) + '</span>' +
      '<div class="sub-labels"><span>client</span><span>server</span></div>';
    half.appendChild(col);
    colsArr.push(col);
  }
  return half;
}
streamsRow.appendChild(buildHalfHeader(DATA.left, leftHeaderCols));
streamsRow.appendChild(buildHalfHeader(DATA.right, rightHeaderCols));
headerEl.appendChild(streamsRow);

// Toggle buttons bar
const togglesBar = document.createElement('div');
togglesBar.className = 'toggles-bar';

function addToggleButtons(label, count, visArr, headerCols) {
  const lbl = document.createElement('span');
  lbl.className = 'label';
  lbl.textContent = label + ':';
  togglesBar.appendChild(lbl);
  for (let i = 0; i < count; i++) {
    const btn = document.createElement('button');
    btn.className = 'toggle-btn';
    btn.textContent = 'S' + (i + 1);
    btn.title = 'Toggle Stream ' + (i + 1);
    btn.addEventListener('click', () => {
      visArr[i] = !visArr[i];
      btn.classList.toggle('is-hidden', !visArr[i]);
      headerCols[i].classList.toggle('hidden-stream', !visArr[i]);
      updateLayout();
      forceRender();
    });
    togglesBar.appendChild(btn);
  }
}
addToggleButtons('Left', DATA.left.length, leftVisible, leftHeaderCols);
addToggleButtons('Right', DATA.right.length, rightVisible, rightHeaderCols);
headerEl.appendChild(togglesBar);

const legend = document.createElement('div');
legend.className = 'legend';
legend.innerHTML = '<span><span class="swatch swatch-client"></span>client</span>' +
  '<span><span class="swatch swatch-server"></span>server</span>' +
  '<span><span class="swatch swatch-client-delta"></span>client delta</span>' +
  '<span><span class="swatch swatch-server-delta"></span>server delta</span>';
headerEl.appendChild(legend);

// Layout
const spacer = document.getElementById('scroll-spacer');
spacer.style.height = (maxRows * ROW_HEIGHT) + 'px';

const viewport = document.getElementById('viewport');
const container = document.getElementById('scroll-outer');

const streamW = SUB_COL_W * 2 + SUB_COL_GAP + STREAM_PAD; // content + padding (6+6)
function halfW(count, visArr) {
  let n = 0;
  for (let i = 0; i < count; i++) if (visArr[i]) n++;
  return n > 0 ? n * streamW : 0;
}

function updateLayout() {
  const w = 20 + halfW(DATA.left.length, leftVisible) + 6 + halfW(DATA.right.length, rightVisible) + 20;
  viewport.style.minWidth = w + 'px';
  spacer.style.minWidth = w + 'px';
  headerEl.style.minWidth = w + 'px';
}
updateLayout();

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
    rowEl.className = 'row';
    rowEl.style.top = (row * ROW_HEIGHT) + 'px';

    // Left half
    const leftHalf = document.createElement('div');
    leftHalf.className = 'half-row';
    for (let si = 0; si < DATA.left.length; si++) {
      if (!leftVisible[si]) continue;
      const cell = document.createElement('div');
      cell.className = 'stream-cell';
      const msgs = DATA.left[si];
      if (row < msgs.length) {
        const m = msgs[row];
        const relMs = leftRelMs[si][row];
        cell.appendChild(makeBox(m, relMs, null, false));
      } else {
        cell.innerHTML = '<div class="empty-box"></div><div class="empty-box"></div>';
      }
      leftHalf.appendChild(cell);
    }
    rowEl.appendChild(leftHalf);

    // Right half
    const rightHalf = document.createElement('div');
    rightHalf.className = 'half-row';
    for (let si = 0; si < DATA.right.length; si++) {
      if (!rightVisible[si]) continue;
      const cell = document.createElement('div');
      cell.className = 'stream-cell';
      const msgs = DATA.right[si];
      if (row < msgs.length) {
        const m = msgs[row];
        const relMs = rightRelMs[si][row];
        const di = deltas[si][row];
        cell.appendChild(makeBox(m, relMs, di, true));
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

function makeBox(m, relMs, di, isRight) {
  const clientBox = document.createElement('div');
  const serverBox = document.createElement('div');

  const activeBox = m.isServer ? serverBox : clientBox;
  const inactiveBox = m.isServer ? clientBox : serverBox;

  inactiveBox.className = 'empty-box';

  let cls = m.isServer ? 'server' : 'client';
  if (isRight && di && di.hasDelta && Math.abs(di.deltaMs) > DATA.deltaColorThreshMs) {
    cls = m.isServer ? 'server-delta' : 'client-delta';
  }
  activeBox.className = 'msg-box ' + cls;

  let text = formatRelTime(relMs);
  if (isRight && di && di.hasDelta) {
    text += '(' + formatDelta(di.deltaMs) + ')';
  }
  text += ' ' + truncate(m.typeName, TRUNCATE_LEN);
  activeBox.textContent = text;

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

container.addEventListener('scroll', render);
window.addEventListener('resize', forceRender);
render();
</script>
</body>
</html>`
