/* Print button for the pentest report. Separate file so the page keeps its
 * strict CSP (no inline scripts). */
(function () {
  var btn = document.getElementById("print-report");
  if (btn) btn.addEventListener("click", function () { window.print(); });
})();
