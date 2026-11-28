// Light / dark / auto switch. The choice is kept in localStorage; index.html applies it before first paint.
(function () {
  const btn = document.getElementById("themebtn"), root = document.documentElement;
  const names = { auto: "Theme: automatic", light: "Theme: light", dark: "Theme: dark" };
  const order = ["auto", "light", "dark"];
  const get = () => { try { const t = localStorage.getItem("theme"); return t === "light" || t === "dark" ? t : "auto"; } catch (e) { return "auto"; } };
  function apply(t) {
    if (t === "auto") root.removeAttribute("data-theme"); else root.setAttribute("data-theme", t);
    try { if (t === "auto") localStorage.removeItem("theme"); else localStorage.setItem("theme", t); } catch (e) {}
    btn.textContent = names[t];
  }
  btn.textContent = names[get()];
  btn.addEventListener("click", () => apply(order[(order.indexOf(get()) + 1) % 3]));
})();
