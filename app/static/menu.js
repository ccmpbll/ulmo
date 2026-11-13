// The user menu in the top bar: opens on click, closes on an outside click or Escape.
(function () {
  var box = document.querySelector(".usermenu");
  if (!box) return;
  var btn = box.querySelector(".usermenu-btn");
  function set(open) {
    box.classList.toggle("open", open);
    btn.setAttribute("aria-expanded", open ? "true" : "false");
  }
  btn.addEventListener("click", function () { set(!box.classList.contains("open")); });
  document.addEventListener("click", function (e) { if (!box.contains(e.target)) set(false); });
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape" && box.classList.contains("open")) { set(false); btn.focus(); }
  });
})();
