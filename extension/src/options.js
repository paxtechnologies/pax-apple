// SPDX-License-Identifier: GPL-3.0-only
// Allow-list editor (options page and toolbar popup).
(function () {
  "use strict";
  const Core = globalThis.PaxBlurCore;
  const $ = (id) => document.getElementById(id);

  function load() {
    return new Promise((resolve) => chrome.storage.local.get({ allowlist: [] },
      (v) => resolve(Core.parseAllowlist((v && v.allowlist) || []))));
  }
  function save(list) {
    return new Promise((resolve) => chrome.storage.local.set({ allowlist: Core.parseAllowlist(list) }, resolve));
  }

  async function render() {
    const list = await load();
    const ul = $("list");
    ul.textContent = "";
    if (!list.length) {
      const li = document.createElement("li");
      li.textContent = "None yet.";
      ul.appendChild(li);
    }
    for (const d of list) {
      const li = document.createElement("li");
      const span = document.createElement("span");
      span.textContent = d;
      const btn = document.createElement("button");
      btn.textContent = "Remove";
      btn.addEventListener("click", async () => { await save(list.filter((x) => x !== d)); render(); });
      li.append(span, btn);
      ul.appendChild(li);
    }
  }

  async function add(raw) {
    const d = Core.normalizeDomain(raw);
    if (!d) { $("msg").textContent = "That doesn't look like a site name."; return; }
    const list = await load();
    if (!list.includes(d)) list.push(d);
    await save(list);
    $("msg").textContent = `Added ${d}. Reload its tabs to see the change.`;
    render();
  }

  $("add").addEventListener("submit", (e) => { e.preventDefault(); add($("domain").value); $("domain").value = ""; });

  // In the toolbar popup, offer the current tab's site.
  if (chrome.tabs && chrome.tabs.query) {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const url = tabs && tabs[0] && tabs[0].url;
      const host = url && /^https?:/.test(url) ? Core.normalizeDomain(url) : null;
      if (host) {
        $("currentHost").textContent = host;
        $("current").hidden = false;
        $("allowCurrent").addEventListener("click", () => add(host));
      }
    });
  }
  render();
})();
