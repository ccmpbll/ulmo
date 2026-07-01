function formatLocalTimes() {
  document.querySelectorAll("time.local-time[datetime]").forEach((el) => {
    const d = new Date(el.getAttribute("datetime"));
    if (!isNaN(d)) el.textContent = d.toLocaleString();
  });
}

document.addEventListener("DOMContentLoaded", formatLocalTimes);
document.body.addEventListener("htmx:afterSwap", formatLocalTimes);
