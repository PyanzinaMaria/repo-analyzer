// Generic group toggling for config-defined forms: radio fields whose name
// matches data-group-toggle show/hide fields with matching data-group.
// Works for any form built by components/form.html without per-app code.
document.addEventListener("change", function (event) {
    const input = event.target;
    if (!input.matches("[data-group-toggle]")) return;
    const form = input.closest("form");
    const toggleName = input.dataset.groupToggle;
    const activeGroup = input.value;
    for (const el of form.querySelectorAll("[data-group]")) {
        el.style.display = el.dataset.group === activeGroup ? "" : "none";
    }
    for (const radio of form.querySelectorAll(`[name="${toggleName}"]`)) {
        if (radio.checked) {
            // keep the chosen source kind visible even if its group is empty
            radio.closest(".field").style.display = "";
        }
    }
});
document.addEventListener("DOMContentLoaded", function () {
    for (const form of document.querySelectorAll("form[data-form-groups]")) {
        const checked = form.querySelector("[data-group-toggle]:checked");
        if (!checked) continue;
        const activeGroup = checked.value;
        for (const el of form.querySelectorAll("[data-group]")) {
            el.style.display = el.dataset.group === activeGroup ? "" : "none";
        }
        checked.closest(".field").style.display = "";
    }
});
