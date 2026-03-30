(function () {
  const socket = window.io ? window.io() : null;
  const outputModalElement = document.getElementById("outputModal");
  const outputModal = outputModalElement ? new bootstrap.Modal(outputModalElement) : null;

  function updateDashboardStats() {
    const statsRoot = document.getElementById("dashboard-stats");
    if (!statsRoot) return;

    fetch("/api/dashboard/stats")
      .then((response) => response.json())
      .then((payload) => {
        Object.entries(payload).forEach(([key, value]) => {
          const element = statsRoot.querySelector(`[data-stat="${key}"]`);
          if (element) {
            element.textContent = value;
          }
        });
      })
      .catch(() => {});
  }

  function renderStatusBadge(status) {
    return `<span class="badge text-bg-secondary">${status || "-"}</span>`;
  }

  function formatDate(value) {
    if (!value) return "-";
    return new Date(value).toLocaleString();
  }

  function updateTargetRow(payload) {
    const row = document.getElementById(`target-row-${payload.target_id}`);
    if (!row) return;

    const setText = (field, value) => {
      const cell = row.querySelector(`[data-field="${field}"]`);
      if (cell) cell.textContent = value || "-";
    };

    const statusCell = row.querySelector('[data-field="status"]');
    if (statusCell) statusCell.innerHTML = renderStatusBadge(payload.status);
    setText("host_state", payload.host_state);
    setText("open_ports_count", String(payload.open_ports_count ?? 0));
    setText("open_ports_summary", payload.open_ports_summary);
    setText("services_summary", payload.services_summary);
    setText("os_guess", payload.os_guess);
    setText("duration_seconds", payload.duration_seconds ? `${Number(payload.duration_seconds).toFixed(1)}s` : "-");
  }

  function updateBatchSummary(payload) {
    const status = document.getElementById("batch-status");
    const completed = document.getElementById("batch-completed");
    const failed = document.getElementById("batch-failed");
    const running = document.getElementById("batch-running");
    const progress = document.getElementById("batch-progress-bar");
    if (status) status.textContent = payload.status;
    if (completed) completed.textContent = payload.completed_targets;
    if (failed) failed.textContent = payload.failed_targets;
    if (running) running.textContent = payload.running_targets;
    if (progress) {
      progress.style.width = `${payload.progress_percent}%`;
      progress.textContent = `${payload.progress_percent}%`;
    }
  }

  function bindOutputButtons() {
    document.querySelectorAll(".output-button").forEach((button) => {
      button.addEventListener("click", () => {
        fetch(button.dataset.outputUrl)
          .then((response) => response.json())
          .then((payload) => {
            document.getElementById("outputModalLabel").textContent = payload.label;
            document.getElementById("outputModalContent").textContent = payload.content || "No output captured.";
            outputModal.show();
          })
          .catch(() => {});
      });
    });
  }

  function toggleCustomBuilder() {
    const profileSelect = document.getElementById("profile-key");
    const panel = document.getElementById("custom-builder-panel");
    if (!profileSelect || !panel) return;

    const sync = () => {
      panel.style.display = profileSelect.value === "custom_safe" ? "block" : "none";
    };

    sync();
    profileSelect.addEventListener("change", sync);
  }

  bindOutputButtons();
  toggleCustomBuilder();
  updateDashboardStats();

  if (socket) {
    socket.on("dashboard_refresh", updateDashboardStats);
    socket.on("scan_update", updateTargetRow);
    socket.on("batch_progress", updateBatchSummary);
    socket.on("batch_finished", updateBatchSummary);

    if (window.reconmanPage?.type === "job-details" && window.reconmanPage.batchId) {
      socket.emit("subscribe_batch", { batch_id: window.reconmanPage.batchId });
    }
  }
})();
