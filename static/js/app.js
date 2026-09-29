// StudyVault — interações mínimas, cada uma com um propósito.
(() => {
  const $ = (s, el = document) => el.querySelector(s);
  const $$ = (s, el = document) => [...el.querySelectorAll(s)];
  const isMac = /Mac|iPhone|iPad/.test(navigator.platform);

  // Índice mobile: folha de tela cheia
  const rail = $("#rail");
  const setRail = (open) => {
    if (!rail) return;
    rail.classList.toggle("open", open);
    $$("[data-rail-toggle]").forEach((b) => b.setAttribute("aria-expanded", String(open)));
    document.body.style.overflow = open ? "hidden" : "";
  };
  $$("[data-rail-toggle]").forEach((b) =>
    b.addEventListener("click", () => setRail(!rail.classList.contains("open")))
  );

  // Confirmação antes de ações destrutivas
  $$("form[data-confirm]").forEach((f) =>
    f.addEventListener("submit", (e) => {
      if (!confirm(f.dataset.confirm)) e.preventDefault();
    })
  );

  // Textareas que crescem com o conteúdo (fallback para field-sizing)
  const grow = (t) => { t.style.height = "auto"; t.style.height = t.scrollHeight + "px"; };
  if (!CSS.supports("field-sizing", "content")) {
    $$("textarea[data-grow]").forEach((t) => {
      grow(t);
      t.addEventListener("input", () => grow(t));
    });
  }

  // Título em uma linha: Enter leva direto ao corpo
  $$("textarea[data-single-line]").forEach((t) =>
    t.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        $(".body-input")?.focus();
      }
    })
  );

  // Anexos: mostra o que foi selecionado
  const drop = $(".drop");
  if (drop) {
    const input = $("input[type=file]", drop);
    const label = $("[data-drop-label]", drop);
    const original = label.textContent;
    input.addEventListener("change", () => {
      const names = [...input.files].map((f) => f.name);
      label.innerHTML = names.length
        ? `<span class="files">${names.length} ${names.length === 1 ? "imagem" : "imagens"}</span> · ${names.join(", ").replace(/</g, "&lt;")}`
        : original;
    });
    ["dragenter", "dragover"].forEach((ev) => drop.addEventListener(ev, () => drop.classList.add("over")));
    ["dragleave", "drop"].forEach((ev) => drop.addEventListener(ev, () => drop.classList.remove("over")));
  }

  // Atalho de salvar
  const writer = $("form[data-writer]");
  $$("[data-kbd]").forEach((k) => (k.textContent = isMac ? "⌘S" : "Ctrl S"));

  document.addEventListener("keydown", (e) => {
    const typing = /INPUT|TEXTAREA/.test(document.activeElement?.tagName);

    if (writer && (e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "s") {
      e.preventDefault();
      writer.requestSubmit();
      return;
    }
    if (e.key === "/" && !typing) {
      const q = $("#q");
      if (q) { e.preventDefault(); q.focus(); q.select(); }
    }
    if (e.key === "Escape") {
      if (rail?.classList.contains("open")) setRail(false);
      else if (typing) document.activeElement.blur();
    }
  });
})();
