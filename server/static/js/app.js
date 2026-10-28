// All page behaviour lives in this external file so the app can run under a
// strict Content-Security-Policy (script-src 'self', no inline handlers).
(function () {
  "use strict";

  // Click-to-sort on every table header. Idempotent: tables are only wired once
  // (the hosts table gets re-wired after an htmx swap, see below).
  function initTableSort(root) {
    (root || document).querySelectorAll("table").forEach(function (table) {
      if (table.dataset.sortInit) return;
      table.dataset.sortInit = "1";
      const headers = table.querySelectorAll("th");
      const sortDirection = {};
      headers.forEach((th, idx) => {
        th.style.cursor = "pointer";
        th.addEventListener("click", function () {
          const tbody = table.querySelector("tbody");
          if (!tbody) return;
          const rows = Array.from(tbody.rows);
          sortDirection[idx] = sortDirection[idx] === "asc" ? "desc" : "asc";
          const dir = sortDirection[idx];
          // A cell may carry an explicit data-sort-value (e.g. a composite weight
          // for the multi-number Trivy column); fall back to its visible text.
          const cellValue = (cell) =>
            cell && cell.dataset.sortValue !== undefined ? cell.dataset.sortValue : (cell?.textContent.trim() ?? "");
          rows.sort((a, b) => {
            const aText = cellValue(a.cells[idx]);
            const bText = cellValue(b.cells[idx]);
            const aNum = parseFloat(aText.replace(/[^0-9.\-]/g, ""));
            const bNum = parseFloat(bText.replace(/[^0-9.\-]/g, ""));
            if (!isNaN(aNum) && !isNaN(bNum)) {
              return dir === "asc" ? aNum - bNum : bNum - aNum;
            }
            return dir === "asc" ? aText.localeCompare(bText) : bText.localeCompare(aText);
          });
          const fragment = document.createDocumentFragment();
          rows.forEach((row) => fragment.appendChild(row));
          tbody.appendChild(fragment);
        });
      });
    });
  }

  // Live table filter driven by data-* attributes on the search input.
  function initFilter() {
    const input = document.getElementById("filter");
    if (!input || input.dataset.filterInit) return;
    input.dataset.filterInit = "1";
    input.addEventListener("input", function () {
      const table = document.getElementById(input.getAttribute("data-filter-target"));
      if (!table) return;
      const cols = (input.getAttribute("data-filter-cols") || "")
        .split(",").map((c) => parseInt(c, 10)).filter((c) => !isNaN(c));
      const needle = input.value.toLowerCase();
      table.querySelectorAll("tbody tr").forEach(function (row) {
        const cells = row.getElementsByTagName("td");
        let match = false;
        for (const idx of cols) {
          if (cells[idx] && cells[idx].textContent.toLowerCase().includes(needle)) {
            match = true;
            break;
          }
        }
        row.style.display = match ? "" : "none";
      });
    });
  }

  function autoHideFlash() {
    setTimeout(function () {
      document.querySelectorAll(".alert").forEach(function (alert) {
        alert.style.transition = "opacity 0.5s";
        alert.style.opacity = "0";
        setTimeout(function () { alert.style.display = "none"; }, 500);
      });
    }, 3000);
  }

  // Delegated row navigation: a [data-href] element navigates on click/Enter,
  // but real controls (links, buttons) inside it keep their own behaviour.
  function navigate(el) {
    const href = el.getAttribute("data-href");
    if (href) globalThis.location.href = href;
  }
  document.addEventListener("click", function (e) {
    if (e.target.closest("a, button, input, label")) return;
    const row = e.target.closest("[data-href]");
    if (row) navigate(row);
  });
  document.addEventListener("keydown", function (e) {
    if (e.key !== "Enter" && e.key !== " ") return;
    const row = e.target.closest("[data-href]");
    if (row && row === e.target) {
      e.preventDefault();
      navigate(row);
    }
  });

  document.addEventListener("DOMContentLoaded", function () {
    initTableSort();
    initFilter();
    autoHideFlash();
  });

  // Re-wire sorting on content that htmx swaps in (e.g. the hosts table refresh).
  document.addEventListener("htmx:afterSwap", function (e) {
    initTableSort(e.target);
  });

  // Fade out transient toasts (OOB-swapped into #toast by collect/scan responses).
  function hideToastSoon() {
    setTimeout(function () {
      document.querySelectorAll("#toast .alert").forEach(function (a) {
        a.style.transition = "opacity 0.5s";
        a.style.opacity = "0";
        setTimeout(function () { a.remove(); }, 500);
      });
    }, 5000);
  }
  document.addEventListener("htmx:oobAfterSwap", function (e) {
    if (e.target && e.target.id === "toast") hideToastSoon();
  });
})();
