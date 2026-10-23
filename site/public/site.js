// Shared page behaviour: copy buttons on code blocks.
// A block whose lines start with "$ " copies only those commands (with their "\\" continuation lines), without the prompt or trailing "# comments".
(() => {
  function commands(pre) {
    const lines = pre.innerText.split('\n');
    const cmds = [];
    let cont = false;
    for (const l of lines) {
      if (l.startsWith('$ ')) { cmds.push(l.slice(2).replace(/\s+#\s.*$/, '').trimEnd()); cont = cmds[cmds.length - 1].endsWith('\\'); }
      else if (cont) { cmds.push(l.trimEnd()); cont = l.trimEnd().endsWith('\\'); }
    }
    return cmds.length ? cmds.join('\n') : pre.innerText.trim();
  }
  window.brCopyText = commands;
  document.addEventListener('click', async e => {
    const btn = e.target.closest('.copy'); if (!btn) return;
    const pre = btn.closest('.code')?.querySelector('pre'); if (!pre) return;
    const label = btn.textContent;
    try { await navigator.clipboard.writeText(commands(pre)); btn.textContent = 'Copied'; }
    catch { const r = document.createRange(); r.selectNodeContents(pre); const s = getSelection(); s.removeAllRanges(); s.addRange(r); btn.textContent = 'Selected'; }
    setTimeout(() => btn.textContent = label, 1500);
  });
})();

// Game windows below the fold pop in when they scroll into view.
(() => {
  if (matchMedia('(prefers-reduced-motion: reduce)').matches || !('IntersectionObserver' in window)) return;
  const io = new IntersectionObserver(es => es.forEach(e => { if (e.isIntersecting) { e.target.classList.add('in'); io.unobserve(e.target); } }), {rootMargin:'0px 0px -6% 0px'});
  document.querySelectorAll('.win').forEach(w => { if (w.getBoundingClientRect().top > innerHeight) { w.classList.add('wait'); io.observe(w); } });
})();
