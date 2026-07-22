"use strict";

/**
 * Submit filter forms when an auto-submit field changes.
 */
document.querySelectorAll(
    "[data-auto-submit]"
).forEach((field) => {
    field.addEventListener(
        "change",
        () => {
            const form = field.closest("form");

            if (form === null) {
                return;
            }

            if (
                typeof form.requestSubmit
                === "function"
            ) {
                form.requestSubmit();
                return;
            }

            form.submit();
        }
    );
});
