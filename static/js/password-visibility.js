(() => {
    const eyeIcon = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6Z"/><circle cx="12" cy="12" r="2.75"/></svg>';
    const eyeOffIcon = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m3 3 18 18"/><path d="M10.6 6.2A10.9 10.9 0 0 1 12 6c6 0 9.5 6 9.5 6a17.2 17.2 0 0 1-3 3.6M6.1 6.1A17.3 17.3 0 0 0 2.5 12S6 18 12 18c1.3 0 2.5-.3 3.5-.8"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/></svg>';

    function addPasswordToggle(input) {
        if (input.dataset.passwordToggleReady === "true") return;

        const wrapper = document.createElement("div");
        wrapper.className = "password-field-control";
        input.parentNode.insertBefore(wrapper, input);
        wrapper.appendChild(input);

        const button = document.createElement("button");
        button.type = "button";
        button.className = "password-visibility-toggle";
        button.setAttribute("aria-label", "Show password");
        button.setAttribute("aria-pressed", "false");
        if (input.id) button.setAttribute("aria-controls", input.id);

        function render(isVisible) {
            button.setAttribute("aria-label", isVisible ? "Hide password" : "Show password");
            button.setAttribute("aria-pressed", String(isVisible));
            button.innerHTML = isVisible ? eyeOffIcon : eyeIcon;
        }

        button.addEventListener("click", () => {
            const isVisible = input.type === "text";
            input.type = isVisible ? "password" : "text";
            render(!isVisible);
        });

        input.dataset.passwordToggleReady = "true";
        render(false);
        wrapper.appendChild(button);
    }

    function initialisePasswordToggles() {
        document.querySelectorAll('input[type="password"]').forEach(addPasswordToggle);
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", initialisePasswordToggles);
    } else {
        initialisePasswordToggles();
    }
})();
