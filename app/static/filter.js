// Checklist helpers: filter as you type, Select all / Clear, and an "N of M selected" count.
// Select all / Clear act only on the rows currently shown, so filtering first narrows them.
// Rows hidden by the filter keep their ticks and are still submitted with the form.
(function () {
  function count(list) {
    var out = document.querySelector('[data-count-for="#' + list.id + '"]');
    if (!out) return;
    out.textContent =
      list.querySelectorAll("input:checked").length + " of " + list.querySelectorAll(".check-item").length + " selected";
  }

  document.addEventListener("input", function (e) {
    var box = e.target.closest ? e.target.closest("[data-filter]") : null;
    if (!box) return;
    var q = box.value.trim().toLowerCase();
    var shown = 0;
    document.querySelectorAll(box.getAttribute("data-filter") + " .check-item").forEach(function (item) {
      item.hidden = q !== "" && item.textContent.toLowerCase().indexOf(q) === -1;
      if (!item.hidden) shown++;
    });
    var none = document.querySelector(box.getAttribute("data-filter") + " .check-none");
    if (none) none.hidden = shown > 0;
  });

  document.addEventListener("click", function (e) {
    var btn = e.target.closest ? e.target.closest("[data-check]") : null;
    if (!btn) return;
    var list = document.querySelector(btn.getAttribute("data-target"));
    if (!list) return;
    var on = btn.getAttribute("data-check") === "all";
    list.querySelectorAll(".check-item").forEach(function (item) {
      if (!item.hidden) item.querySelector("input").checked = on;
    });
    count(list);
  });

  document.addEventListener("change", function (e) {
    var list = e.target.closest ? e.target.closest(".checklist") : null;
    if (list) count(list);
  });
})();
