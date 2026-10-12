// Shared admin UI helpers: the body viewer (request detail page and live
// stream cards), formatting, and the request detail page wiring.
(() => {
  "use strict";
  const PREVIEW_BYTES = 256 * 1024;
  /** Most the viewer will load into the page; Download has no cap. */
  const VIEW_LIMIT = 5 * 1024 * 1024;
  const HEXDUMP_LIMIT = 64 * 1024;

  function el(tag, cls, text) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text != null) node.textContent = text;
    return node;
  }

  function button(label, cls, onClick) {
    const b = el("button", cls || "secondary small", label);
    b.type = "button";
    if (onClick) b.addEventListener("click", onClick);
    return b;
  }

  function humanBytes(bytes) {
    const units = ["B", "KiB", "MiB", "GiB", "TiB"];
    let value = bytes, unit = 0;
    while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit++; }
    return unit === 0 ? `${bytes} B` : `${value.toFixed(1)} ${units[unit]}`;
  }

  function fmtTime(iso) {
    const d = new Date(iso);
    if (isNaN(d)) return iso || "";
    const pad = (n, w = 2) => String(n).padStart(w, "0");
    const time = `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`;
    return d.toDateString() === new Date().toDateString()
      ? time
      : `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${time}`;
  }

  function methodChip(method) {
    const m = String(method || "?");
    const cls = { GET: "get", POST: "post", PUT: "put", PATCH: "put", DELETE: "delete" }[m] || "other";
    return el("span", "method " + cls, m);
  }

  function statusPill(body) {
    body = body || {};
    if (body.limit_exceeded) return el("span", "pill warn", "⚠ limit exceeded");
    if (!body.complete) return el("span", "pill bad", "✗ incomplete");
    return el("span", "pill ok", "✓ complete");
  }

  function looksBinary(bytes) {
    if (bytes.length === 0) return false;
    let control = 0;
    for (const b of bytes) {
      if (b === 0) return true;
      if (b < 0x09 || (b > 0x0d && b < 0x20)) control++;
    }
    return control / bytes.length > 0.1;
  }

  function looksLikeForm(text) {
    const fields = text.trim().split("&");
    return text.trim() !== "" && fields.every((f) => /^[^=\s]+=[^\s]*$/.test(f));
  }

  function hexdump(bytes) {
    const lines = [];
    for (let off = 0; off < bytes.length; off += 16) {
      const row = bytes.subarray(off, off + 16);
      let hex = "", ascii = "";
      for (let i = 0; i < 16; i++) {
        if (i < row.length) {
          hex += row[i].toString(16).padStart(2, "0") + " ";
          ascii += row[i] >= 0x20 && row[i] < 0x7f ? String.fromCharCode(row[i]) : ".";
        } else {
          hex += "   ";
        }
        if (i === 7) hex += " ";
      }
      lines.push(off.toString(16).padStart(8, "0") + "  " + hex + " " + ascii);
    }
    return lines.join("\n");
  }

  /** `{ kind, text, raw }`: how to show a body, and its text for copying. */
  function renderBody(bytes, contentType) {
    if (looksBinary(bytes.subarray(0, 4096))) {
      let text = hexdump(bytes.subarray(0, HEXDUMP_LIMIT));
      if (bytes.length > HEXDUMP_LIMIT) text += `\n… ${humanBytes(bytes.length - HEXDUMP_LIMIT)} more`;
      return { kind: "Binary", text, raw: null };
    }
    const raw = new TextDecoder().decode(bytes);
    const trimmed = raw.trimStart();
    if (/json/i.test(contentType) || trimmed.startsWith("{") || trimmed.startsWith("[")) {
      try { return { kind: "JSON", text: JSON.stringify(JSON.parse(raw), null, 2), raw }; } catch (_) {}
    }
    // curl -d/--data-binary labels any body as a form, so only treat it as one
    // when every field really is key=value.
    if (/x-www-form-urlencoded/i.test(contentType) && looksLikeForm(raw)) {
      const lines = [];
      for (const [k, v] of new URLSearchParams(raw)) lines.push(`${k} = ${v}`);
      return { kind: "Form", text: lines.join("\n"), raw };
    }
    return { kind: "Text", text: raw, raw };
  }

  function bytesToB64(bytes) {
    let bin = "";
    for (let i = 0; i < bytes.length; i += 0x8000) {
      bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    }
    return btoa(bin);
  }

  async function copyText(text, btn) {
    const label = btn.textContent;
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
      } else {
        // The Clipboard API needs https; plain-http deployments use the legacy path.
        const ta = el("textarea");
        ta.value = text;
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.append(ta);
        ta.select();
        const ok = document.execCommand("copy");
        ta.remove();
        if (!ok) throw new Error("copy failed");
      }
      btn.textContent = "Copied";
    } catch (_) {
      btn.textContent = "Copy failed";
    }
    setTimeout(() => { btn.textContent = label; }, 1200);
  }

  /** GET a stored body; `headers` carries the stream token where needed. */
  async function fetchBytes(url, limit, headers) {
    const res = await fetch(url + (limit != null ? "?limit=" + limit : ""), { headers: headers || {}, cache: "no-store" });
    if (!res.ok) {
      throw new Error(res.status === 404
        ? "The body is no longer stored (expired or cleaned up)."
        : res.status === 401
          ? "Not authorised to fetch the body."
          : `Fetching the body failed (HTTP ${res.status}).`);
    }
    return new Uint8Array(await res.arrayBuffer());
  }

  /**
   * Fills `container` with a body viewer for request `meta`. The first
   * PREVIEW_BYTES are fetched straight away and "Load all" fetches up to
   * VIEW_LIMIT. Download is a plain link, so the browser streams the whole
   * body to disk without holding it in the page. `token` is the stream token
   * for stream-view cards; admin pages use the session cookie instead.
   */
  function bodyViewer(container, meta, bodyUrl, token) {
    const body = meta.body || {};
    const size = body.original_size || 0;
    const headers = token ? { Authorization: "Bearer " + token } : {};
    container.replaceChildren();

    if (body.limit_exceeded) {
      container.append(el("p", "viewer-note", "The body exceeded max_body_size; only the part received before the cutoff was stored."));
    } else if (!body.complete) {
      container.append(el("p", "viewer-note", "The body is incomplete: the client disconnected mid-body. This is what was stored."));
    }
    if (!bodyUrl) {
      container.append(el("p", "muted", size === 0 ? "Empty body." : "No body was stored for this request (metadata_only mode)."));
      return;
    }
    if (size === 0 && body.complete) {
      container.append(el("p", "muted", "Empty body."));
      return;
    }

    const head = el("div", "viewer-head");
    const kind = el("span", "tag");
    kind.hidden = true;
    const tools = el("span", "tools");
    head.append(kind, el("span", "muted", body.content_type || "no content type"), tools);
    const info = el("p", "muted", "Loading body\u2026");
    const pre = el("pre");
    pre.hidden = true;
    container.append(head, info, pre);

    let loaded = null;
    const fail = (err) => {
      info.hidden = false;
      info.className = "error";
      info.textContent = err.message;
    };
    const loadMore = button(size > VIEW_LIMIT ? `Load first ${humanBytes(VIEW_LIMIT)}` : "Load all", "secondary small", () => {
      loadMore.disabled = true;
      loadMore.textContent = "Loading\u2026";
      fetchBytes(bodyUrl, VIEW_LIMIT, headers).then((b) => render(b, VIEW_LIMIT), fail);
    });
    // Fewer bytes than asked for means the whole stored body is here.
    const render = (bytes, requested) => {
      const view = renderBody(bytes, body.content_type || "");
      loaded = { bytes, view };
      kind.textContent = view.kind;
      kind.hidden = false;
      pre.textContent = view.text;
      pre.hidden = false;
      if (bytes.length < requested) {
        info.hidden = true;
        return;
      }
      info.className = "viewer-partial";
      const shown = `Showing the first ${humanBytes(bytes.length)} of ${humanBytes(size)}.`;
      if (requested < VIEW_LIMIT) {
        info.replaceChildren(shown, loadMore);
      } else {
        info.replaceChildren(`${shown} Use Download for the full body.`);
      }
    };

    const ct = body.content_type || "";
    const ext = /json/i.test(ct) ? ".json" : /^text\//i.test(ct) || /x-www-form-urlencoded|xml/i.test(ct) ? ".txt" : ".bin";
    const download = el("a", "button secondary small", "Download");
    download.href = bodyUrl + "?download=1" + (token ? "&token=" + encodeURIComponent(token) : "");
    download.download = (meta.id || "body") + ext;
    tools.append(
      button("Copy", "secondary small", (e) => {
        if (!loaded) return;
        copyText(loaded.view.kind === "Binary" ? bytesToB64(loaded.bytes) : loaded.view.raw, e.currentTarget);
      }),
      download,
    );
    fetchBytes(bodyUrl, PREVIEW_BYTES, headers).then((b) => render(b, PREVIEW_BYTES), fail);
  }

  function headersTable(headers) {
    const table = el("table", "kv");
    const tbody = el("tbody");
    for (const name of Object.keys(headers || {}).sort()) {
      const values = Array.isArray(headers[name]) ? headers[name] : [headers[name]];
      for (const value of values) {
        const tr = el("tr");
        tr.append(el("td", null, name), el("td", null, String(value)));
        tbody.append(tr);
      }
    }
    if (!tbody.childElementCount) {
      const tr = el("tr");
      const td = el("td", "empty", "No headers.");
      td.colSpan = 2;
      tr.append(td);
      tbody.append(tr);
    }
    table.append(tbody);
    return table;
  }

  // ---------- Copy as cURL ----------

  const SKIP_HEADERS = new Set(["host", "content-length", "connection", "transfer-encoding", "accept-encoding", "expect"]);

  function shellQuote(s) {
    return "'" + String(s).replace(/'/g, "'\\''") + "'";
  }

  /** curl for a stored body over the token-protected stream API. */
  function bodyCurl(streamBodyPath, token) {
    const auth = token ? ` -H ${shellQuote("X-Stream-Token: " + token)}` : "";
    return `curl -s${auth} ${shellQuote(location.origin + streamBodyPath)}`;
  }

  /** A labelled, copyable command. `code` is returned for later updates. */
  function codeBlock(label, text) {
    const wrap = el("div", "codeblock");
    const head = el("div", "codeblock-head");
    const code = el("code", null, text);
    const pre = el("pre");
    pre.append(code);
    head.append(
      el("span", null, label),
      button("Copy", "secondary small", (e) => copyText(code.textContent, e.currentTarget)),
    );
    wrap.append(head, pre);
    wrap.code = code;
    return wrap;
  }

  async function curlCommand(meta, bodyUrl) {
    const headers = meta.headers || {};
    const first = (name) => {
      const v = headers[name];
      return Array.isArray(v) ? v[0] : v;
    };
    const proto = first("x-forwarded-proto") || location.protocol.replace(":", "");
    const host = first("x-forwarded-host") || first("host") || location.host;
    const url = `${proto}://${host}${meta.path}${meta.query ? "?" + meta.query : ""}`;
    const lines = [`curl -X ${meta.method} ${shellQuote(url)}`];
    for (const name of Object.keys(headers).sort()) {
      if (SKIP_HEADERS.has(name) || name.startsWith("x-forwarded-")) continue;
      const values = Array.isArray(headers[name]) ? headers[name] : [headers[name]];
      for (const v of values) lines.push(`  -H ${shellQuote(`${name}: ${v}`)}`);
    }
    const size = (meta.body && meta.body.original_size) || 0;
    if (bodyUrl && size > 0) {
      const bytes = await fetchBytes(bodyUrl, 64 * 1024 + 1);
      if (bytes.length <= 64 * 1024 && !looksBinary(bytes)) {
        lines.push(`  --data-binary ${shellQuote(new TextDecoder().decode(bytes))}`);
      } else {
        lines.push(`  --data-binary @${meta.id}.body   # download the body first`);
      }
    }
    return lines.join(" \\\n");
  }

  // ---------- request detail page ----------

  function initDetail() {
    const dataEl = document.getElementById("req-data");
    if (!dataEl) return;
    const { meta, bodyUrl, streamBodyUrl, streamToken } = JSON.parse(dataEl.textContent);

    const tabs = document.querySelectorAll(".tabs [data-tab]");
    const select = (name) => {
      for (const t of tabs) {
        const on = t.dataset.tab === name;
        t.setAttribute("aria-selected", String(on));
        document.getElementById("tab-" + t.dataset.tab).hidden = !on;
      }
      if (history.replaceState) history.replaceState(null, "", "#" + name);
    };
    for (const t of tabs) t.addEventListener("click", () => select(t.dataset.tab));
    const initial = location.hash.slice(1);
    select([...tabs].some((t) => t.dataset.tab === initial) ? initial : "body");

    const bodyTab = document.getElementById("tab-body");
    bodyViewer(bodyTab, meta, bodyUrl);
    if (streamBodyUrl) {
      bodyTab.append(codeBlock("Fetch this body from a terminal", bodyCurl(streamBodyUrl, streamToken)));
    }

    const curl = document.getElementById("copy-curl");
    if (curl) {
      curl.addEventListener("click", async () => {
        try {
          await copyText(await curlCommand(meta, bodyUrl), curl);
        } catch (err) {
          curl.textContent = "Copy failed";
        }
      });
    }
  }

  // Result rows navigate on click, keeping links and text selection usable.
  function initResults() {
    for (const row of document.querySelectorAll("tr[data-href]")) {
      row.addEventListener("click", (e) => {
        if (e.target.closest("a") || String(window.getSelection())) return;
        location.href = row.dataset.href;
      });
    }
  }

  // Column chart tooltips: one floating box, filled with textContent, shown on
  // hover and keyboard focus. The same numbers are in the chart's table view.
  function initChart() {
    const cols = document.querySelectorAll(".col[data-value]");
    if (!cols.length) return;
    const tip = el("div", "chart-tip");
    tip.hidden = true;
    document.body.append(tip);
    const show = (col) => {
      const strong = el("strong", null, col.dataset.value);
      tip.replaceChildren(strong, el("span", null, col.dataset.title));
      if (col.dataset.detail) tip.append(el("div", null, col.dataset.detail));
      const box = col.getBoundingClientRect();
      const bar = col.firstElementChild.getBoundingClientRect();
      const half = tip.offsetWidth / 2 || 80;
      const x = Math.min(Math.max(box.left + box.width / 2, half + 8), window.innerWidth - half - 8);
      tip.style.left = x + "px";
      tip.style.top = Math.min(bar.top, box.bottom - 4) + "px";
      tip.hidden = false;
    };
    const hide = () => { tip.hidden = true; };
    for (const col of cols) {
      col.addEventListener("pointerenter", () => show(col));
      col.addEventListener("focus", () => show(col));
      col.addEventListener("pointerleave", hide);
      col.addEventListener("blur", hide);
    }
    window.addEventListener("scroll", hide, { passive: true });
  }

  window.WH = {
    el, button, humanBytes, fmtTime, methodChip, statusPill, bodyViewer, headersTable, copyText,
    codeBlock, bodyCurl,
  };
  document.addEventListener("DOMContentLoaded", () => {
    initDetail();
    initResults();
    initChart();
  });
})();
