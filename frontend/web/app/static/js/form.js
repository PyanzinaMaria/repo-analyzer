// Generic group toggling for config-defined forms: radio fields whose name
// matches data-group-toggle show/hide fields with matching data-group.
// Works for any form built by components/form.html without per-app code.

// Hidden groups must also be disabled: browsers block form submission on a
// `required` input even when it is not displayed, which previously made
// file uploads impossible without filling the hidden URL field.
function applyGroups(form, activeGroup) {
    for (const el of form.querySelectorAll("[data-group]")) {
        const hidden = el.dataset.group !== activeGroup;
        el.style.display = hidden ? "none" : "";
        for (const input of el.querySelectorAll("input, select, textarea")) {
            input.disabled = hidden;
        }
    }
}

document.addEventListener("change", function (event) {
    const input = event.target;
    if (!input.matches("[data-group-toggle]")) return;
    const form = input.closest("form");
    const toggleName = input.dataset.groupToggle;
    applyGroups(form, input.value);
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
        applyGroups(form, checked.value);
        checked.closest(".field").style.display = "";
    }
});
