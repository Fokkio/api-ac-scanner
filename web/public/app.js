(function () {
  "use strict";

  const body = document.body;
  const navToggle = document.querySelector("[data-nav-toggle]");
  const primaryNav = document.querySelector("[data-primary-nav]");

  if (body && navToggle && primaryNav) {
    body.classList.add("nav-enhanced");

    const setNavigationOpen = function (open) {
      navToggle.setAttribute("aria-expanded", String(open));
      navToggle.textContent = open ? "Close" : "Menu";
      primaryNav.setAttribute("data-open", String(open));
    };

    navToggle.addEventListener("click", function () {
      setNavigationOpen(navToggle.getAttribute("aria-expanded") !== "true");
    });

    primaryNav.addEventListener("click", function (event) {
      if (event.target instanceof HTMLAnchorElement) {
        setNavigationOpen(false);
      }
    });

    document.addEventListener("keydown", function (event) {
      if (event.key === "Escape") {
        setNavigationOpen(false);
        navToggle.focus();
      }
    });

    const currentPath = window.location.pathname;
    primaryNav.querySelectorAll("a[href]").forEach(function (link) {
      const linkPath = new URL(link.href, window.location.origin).pathname;
      const isCurrent = linkPath === "/"
        ? currentPath === "/"
        : currentPath === linkPath || currentPath.startsWith(linkPath + "/");
      if (isCurrent) {
        link.setAttribute("aria-current", "page");
      }
    });
  }

  const forms = Array.from(document.querySelectorAll("form"));
  forms.forEach(function (form) {
    form.addEventListener("submit", function () {
      const submitButton = form.querySelector('button[type="submit"]');
      if (!submitButton) return;
      submitButton.dataset.originalLabel = submitButton.textContent || "";
      submitButton.textContent = submitButton.dataset.loadingLabel || "Working...";
      submitButton.setAttribute("aria-busy", "true");
      submitButton.disabled = true;
    });
  });

  window.addEventListener("pageshow", function () {
    document.querySelectorAll('button[type="submit"][aria-busy="true"]').forEach(function (button) {
      button.textContent = button.dataset.originalLabel || "Submit";
      button.removeAttribute("aria-busy");
      button.disabled = false;
    });
  });

  const reportPage = document.querySelector("[data-report-id]");
  if (!reportPage) return;

  const reportId = reportPage.getAttribute("data-report-id");
  const initialStatus = reportPage.getAttribute("data-report-status");
  if (!reportId || (initialStatus !== "queued" && initialStatus !== "running")) return;

  const statusElement = document.querySelector("#scan-status");
  const stageElement = document.querySelector("#scan-stage");
  const progressElement = document.querySelector("#scan-progress");
  let pollHandle;

  async function pollReport() {
    try {
      const response = await fetch(`/api/scans/${encodeURIComponent(reportId)}`, {
        headers: { accept: "application/json" },
      });
      if (!response.ok) throw new Error(`status ${response.status}`);

      const payload = await response.json();
      const scan = payload.scan;
      if (statusElement) statusElement.textContent = scan.status;
      if (stageElement) stageElement.textContent = scan.stage;
      if (progressElement) progressElement.value = scan.progress;

      if (scan.status === "done" || scan.status === "error") {
        clearInterval(pollHandle);
        window.location.reload();
      }
    } catch (_error) {
      if (stageElement) stageElement.textContent = "Waiting for the service to reconnect";
    }
  }

  pollHandle = window.setInterval(pollReport, 1500);
  window.addEventListener("beforeunload", function () {
    clearInterval(pollHandle);
  });
}());
