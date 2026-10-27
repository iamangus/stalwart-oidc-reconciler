// Presentation only: native organization-invitation validation independently
// rejects a changed recovery email on the server. Keep readonly (not disabled)
// so the bound address is submitted. Do not lock later UPDATE_EMAIL forms.
document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("kc-register-form");
  const email = form?.querySelector('input[name="email"]');
  if (email) {
    email.readOnly = true;
    email.setAttribute("aria-readonly", "true");
  }
});
