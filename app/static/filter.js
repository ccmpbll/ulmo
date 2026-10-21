// Filters a checklist as you type. Items hidden by the filter stay ticked and are still submitted.
document.addEventListener("input", function (e) {
  var box = e.target.closest ? e.target.closest("[data-filter]") : null;
  if (!box) return;
  var q = box.value.trim().toLowerCase();
  document.querySelectorAll(box.getAttribute("data-filter") + " .check-item").forEach(function (item) {
    item.hidden = q !== "" && item.textContent.toLowerCase().indexOf(q) === -1;
  });
});
