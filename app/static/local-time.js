// Timestamps arrive as UTC in <time class="local-time" datetime="...">. Show them in the viewer's
// own timezone; with data-relative show "5 min ago" / "in 2 h" and keep the full time as the hover text.
function relativeText(d) {
  const secs = Math.round((d - Date.now()) / 1000);
  const future = secs > 0;
  const s = Math.abs(secs);
  let text;
  if (s < 45) text = null;
  else if (s < 3600) text = Math.max(1, Math.round(s / 60)) + " min";
  else if (s < 86400) text = Math.round(s / 3600) + " h";
  else if (s < 7 * 86400) text = Math.round(s / 86400) + " d";
  else return d.toLocaleDateString();
  if (text === null) return future ? "in a moment" : "just now";
  return future ? "in " + text : text + " ago";
}

function formatLocalTimes() {
  document.querySelectorAll("time.local-time[datetime]").forEach((el) => {
    const d = new Date(el.getAttribute("datetime"));
    if (isNaN(d)) return;
    const full = d.toLocaleString();
    if (el.hasAttribute("data-relative")) {
      el.textContent = relativeText(d);
      el.title = full;
    } else {
      el.textContent = full;
    }
  });
}

document.addEventListener("DOMContentLoaded", formatLocalTimes);
