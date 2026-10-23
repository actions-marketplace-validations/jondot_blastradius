// Shared pixel kit: palette, a 3x5 font, bug and machine sprites, and icons for the page.
(() => {
  const P = {
    sky0:'#0b0a1c', sky1:'#14122a', sky2:'#221c44', ink:'#08070f', m0:'#2e2a5c', m1:'#58509e', m2:'#8f86d6',
    coin:'#ffcc33', hot:'#ff4d6d', org:'#ff9a3c', cool:'#59e3ff', go:'#5dff9d', white:'#f4f0ff'
  };
  const SEV = {critical:P.hot, high:P.org, medium:P.coin, low:P.cool};

  const F = {A:'010101111101101',B:'110101110101110',C:'011100100100011',D:'110101101101110',E:'111100110100111',F:'111100110100100',
    G:'011100101101011',H:'101101111101101',I:'111010010010111',J:'001001001101010',K:'101101110101101',L:'100100100100111',
    M:'101111111101101',N:'110101101101101',O:'010101101101010',P:'110101110100100',Q:'010101101110011',R:'110101110101101',
    S:'011100010001110',T:'111010010010010',U:'101101101101111',V:'101101101101010',W:'101101111111101',X:'101101010101101',
    Y:'101101010010010',Z:'111001010100111','0':'111101101101111','1':'010110010010111','2':'110001010100111','3':'110001010001110',
    '4':'101101111001001','5':'111100110001110','6':'011100111101111','7':'111001010010010','8':'111101111101111','9':'111101111001110',
    '-':'000000111000000','_':'000000000000111','*':'000101010101000','.':'000000000000010',':':'000010000010000','/':'001001010100100',
    '!':'010010010000010','>':'100010001010100','@':'111101111100011','+':'000010111010000','(':'010100100100010',')':'010001001001010'};
  const width = s => Math.max(0, String(s).length * 4 - 1);
  function text(x, s, px, py, col, center) {
    s = String(s).toUpperCase(); if (center) px -= width(s) / 2; px = Math.round(px); py = Math.round(py);
    for (const [c, d] of [[P.ink, 1], [col, 0]]) {
      x.fillStyle = c;
      for (let k = 0; k < s.length; k++) { const g = F[s[k]]; if (!g) continue;
        for (let i = 0; i < 15; i++) if (g[i] === '1') x.fillRect(px + k * 4 + i % 3 + d, py + (i / 3 | 0) + d, 1, 1); }
    }
  }

  const BUG = [
    ['.l....l.', '..l..l..', '.bbbbbb.', 'bbwbbwbb', 'bbbbbbbb', 'lbbddbbl', '.bbbbbb.', 'l.l..l.l'],
    ['..l..l..', '.l....l.', '.bbbbbb.', 'bbwbbwbb', 'bbbbbbbb', 'lbbddbbl', '.bbbbbb.', '.l.ll.l.']];
  function bug(x, px, py, col, frame) {
    px = Math.round(px); py = Math.round(py);
    const map = {b:col, l:P.ink, w:P.white, d:'rgba(0,0,0,.35)'};
    BUG[frame & 1].forEach((r, j) => { for (let i = 0; i < 8; i++) { const c = map[r[i]]; if (c) { x.fillStyle = c; x.fillRect(px + i, py + j, 1, 1); } } });
  }

  // A machine is 22x20, centred on cx with its base on gy.
  function machine(x, kind, cx, gy, t, sick, fix, label) {
    const bx = Math.round(cx) - 11, by = gy - 20;
    const body = sick ? '#3a1630' : P.m0, edge = sick ? P.hot : P.m1, hi = sick ? '#ff8aa0' : P.m2;
    x.fillStyle = P.ink; x.fillRect(bx - 1, by - 1, 24, 22);
    x.fillStyle = body; x.fillRect(bx, by, 22, 20);
    x.fillStyle = edge; x.fillRect(bx, by, 22, 1); x.fillRect(bx, by, 1, 20);
    x.fillStyle = hi;
    const c = bx + 11, m = by + 10;
    if (kind === 'repo') { x.fillRect(c - 5, m - 5, 4, 2); x.fillRect(c - 5, m - 3, 11, 8); x.fillStyle = body; x.fillRect(c - 1, m - 1, 1, 5); x.fillRect(c + 2, m - 1, 1, 2); x.fillRect(c, m + 1, 2, 1); }
    if (kind === 'ci') { for (let a = 0; a < 8; a++) x.fillRect(c + Math.round(Math.cos(a * .785 + t) * 5) - 1, m + Math.round(Math.sin(a * .785 + t) * 5) - 1, 2, 2); x.fillRect(c - 2, m - 2, 4, 4); }
    if (kind === 'images') { for (let j = 0; j < 3; j++) x.fillRect(c - 6 + j, m + 3 - j * 4, 11, 3); }
    if (kind === 'laptop') { x.fillRect(c - 6, m - 5, 12, 8); x.fillStyle = sick ? P.hot : P.cool; x.fillRect(c - 5, m - 4, 10, 6); x.fillStyle = hi; x.fillRect(c - 8, m + 3, 16, 2); }
    if (kind === 'cache') { x.fillRect(c - 5, m - 5, 10, 11); x.fillStyle = body; x.fillRect(c - 5, m - 2, 10, 1); x.fillRect(c - 5, m + 2, 10, 1); }
    if (kind === 'keys') { x.fillRect(c - 6, m - 6, 12, 12); x.fillStyle = body; x.fillRect(c - 2, m - 2, 4, 4); x.fillStyle = hi; x.fillRect(c - 1, m - 1, 2, 2); }
    if (kind === 'certs') { x.fillRect(c - 6, m - 5, 12, 9); x.fillStyle = body; x.fillRect(c - 4, m - 3, 8, 1); x.fillRect(c - 4, m - 1, 6, 1); x.fillStyle = P.coin; x.fillRect(c + 2, m + 2, 4, 4); x.fillRect(c + 3, m + 6, 1, 2); }
    if (sick) {
      for (let i = 0; i < 6; i++) { x.fillStyle = Math.random() < .5 ? P.hot : P.go; x.fillRect(bx + (Math.random() * 20 | 0), by + (Math.random() * 18 | 0), 1 + (Math.random() * 3 | 0), 1); }
      if ((t * 4 | 0) % 2) { x.fillStyle = P.hot; x.fillRect(c - 3, by - 10, 7, 7); text(x, '!', c - 1, by - 9, P.white); }
    }
    if (fix > 0) { const sy = by + 20 - Math.round((1 - fix) * 22); x.fillStyle = P.cool; x.fillRect(bx - 2, sy, 26, 1); x.globalAlpha = .35; x.fillRect(bx - 2, sy + 1, 26, 2); x.globalAlpha = 1; }
    if (label) text(x, label, c, gy + 6, sick ? P.hot : P.m2, true);
  }

  // <img data-px="repo|ci|...|bug-critical|net"> becomes a crisp pixel icon.
  function icons(root) {
    for (const img of (root || document).querySelectorAll('img[data-px]')) {
      const k = img.dataset.px, cv = document.createElement('canvas'); cv.width = 26; cv.height = 24;
      const x = cv.getContext('2d');
      if (k.startsWith('bug')) bug(x, 9, 8, SEV[k.split('-')[1]] || P.coin, 0);
      else if (k === 'net') { x.fillStyle = P.go; for (let a = 0; a < 6.283; a += .2) x.fillRect(Math.round(13 + Math.cos(a) * 8), Math.round(12 + Math.sin(a) * 8), 1, 1);
        for (let a = 0; a < 6.283; a += .785) x.fillRect(Math.round(13 + Math.cos(a) * 4), Math.round(12 + Math.sin(a) * 4), 1, 1); x.fillRect(13, 12, 1, 1); }
      else if (k === 'fix') { machine(x, 'repo', 13, 22, 0, false, .5); }
      else if (k === 'found') { machine(x, 'ci', 13, 22, .3, true, 0); }
      else machine(x, k, 13, 22, .3, false, 0);
      img.src = cv.toDataURL(); img.width = img.width || 52; img.style.imageRendering = 'pixelated';
    }
  }

  window.PX = {P, SEV, text, width, bug, machine, icons};
  if (document.readyState !== 'loading') icons(); else document.addEventListener('DOMContentLoaded', () => icons());
})();
