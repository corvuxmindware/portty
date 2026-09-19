// Portty local proof client. Loaded as an external module so the page can run
// under a strict CSP (script-src 'self'); no inline script is required.
//
// The per-startup capability token arrives in the URL query (?token=…) - the
// host prints the full URL to the owner's terminal. The token is NOT embedded in
// the served page, so another local process that fetches `/` cannot learn it.
// We read it, then strip it from the address bar so it doesn't linger in history
// or a screenshot.
(() => {
  const params = new URLSearchParams(location.search);
  const token = params.get("token") || "";
  if (token) {
    try { history.replaceState(null, "", location.pathname); } catch { /* ignore */ }
  }

  const term = new Terminal({ cursorBlink: true, fontFamily: "monospace", fontSize: 13 });
  const fit = new FitAddon.FitAddon();
  term.loadAddon(fit);
  term.open(document.getElementById("term"));
  fit.fit();

  let sessions = [];          // [{id,title,kind,has_activity}]
  let activeId = null;

  const scheme = location.protocol === "https:" ? "wss://" : "ws://";
  const wsHost = scheme + location.host + "/ws?token=" + encodeURIComponent(token);
  const ws = new WebSocket(wsHost);
  ws.binaryType = "arraybuffer";
  const status = document.getElementById("status");
  const decoder = new TextDecoder();

  function send(obj) { if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj)); }

  function renderTabs() {
    const el = document.getElementById("tabs");
    el.innerHTML = "";
    for (const s of sessions) {
      const tab = document.createElement("span");
      tab.className = "tab" + (s.id === activeId ? " active" : "") + (s.has_activity ? " has-activity" : "");
      const dot = document.createElement("span"); dot.className = "dot";
      const t = document.createElement("span"); t.className = "t"; t.textContent = s.title || ("#" + s.id);
      const x = document.createElement("span"); x.className = "x"; x.title = "kill"; x.textContent = "✕";
      tab.append(dot, t, x);
      t.onclick = () => attach(s.id);
      x.onclick = (e) => { e.stopPropagation(); send({ cmd: "kill", id: s.id }); };
      el.appendChild(tab);
    }
  }

  function attach(id) {
    activeId = id;
    const s = sessions.find(x => x.id === id);
    if (s) s.has_activity = false;
    term.reset();             // clear view; server resends scrollback for this session
    send({ cmd: "resize", id, cols: term.cols, rows: term.rows });
    send({ cmd: "attach", id });
    renderTabs();
    status.textContent = `attached to #${id}`;
  }

  function upsertSession(info) {
    const i = sessions.findIndex(s => s.id === info.id);
    if (i >= 0) sessions[i] = info; else sessions.push(info);
  }
  function removeSession(id) {
    sessions = sessions.filter(s => s.id !== id);
    if (activeId === id) {
      activeId = null;
      term.reset();
      status.textContent = "session closed";
    }
    renderTabs();
  }

  ws.onopen = () => { status.textContent = "connected"; };
  ws.onclose = () => { status.textContent = "disconnected - restart the host"; };
  ws.onerror = () => { status.textContent = "socket error"; };

  ws.onmessage = (ev) => {
    // Terminal output arrives as a binary frame: [8-byte LE session id][raw bytes].
    // Everything else is JSON text. Keeping output binary means the host stays a
    // literal byte pipe (no UTF-8 lossy round-trip).
    if (ev.data instanceof ArrayBuffer) {
      const buf = new Uint8Array(ev.data);
      if (buf.length < 8) return;
      const view = new DataView(ev.data);
      const id = Number(view.getBigUint64(0, true));
      if (id === activeId) term.write(buf.subarray(8));
      return;
    }
    let m; try { m = JSON.parse(ev.data); } catch { return; }
    switch (m.type) {
      case "list":
        sessions = m.sessions || [];
        if (!activeId && sessions.length) attach(sessions[0].id);
        else renderTabs();
        break;
      case "added":
        upsertSession(m.info);
        renderTabs();
        break;
      case "removed":
        removeSession(m.id);
        renderTabs();
        break;
      case "activity": {
        const s = sessions.find(x => x.id === m.id);
        if (s) { s.has_activity = true; renderTabs(); }
        break;
      }
      case "reset":
        // Host is about to resend scrollback (lag recovery) - clear first so it
        // doesn't render on top of existing output.
        if (m.id === activeId) term.reset();
        break;
    }
  };

  // Keystrokes → host input.
  term.onData((data) => { if (activeId != null) send({ cmd: "input", id: activeId, data }); });

  // Keep the PTY size in sync with the terminal viewport.
  term.onResize(({ cols, rows }) => {
    if (activeId != null) send({ cmd: "resize", id: activeId, cols, rows });
  });
  window.addEventListener("resize", () => fit.fit());

  document.getElementById("newbtn").onclick = () => send({ cmd: "new", title: "session " + (sessions.length + 1) });
})();
