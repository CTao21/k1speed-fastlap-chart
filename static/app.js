k// Utility to disable & show spinner on buttons
function attachSpinner(selector) {
  document.querySelectorAll(selector).forEach(btn => {
    btn.addEventListener("click", () => {
      btn.disabled = true;
      // Preserve original text in data-attr
      const txt = btn.getAttribute("data-text") || btn.textContent;
      btn.setAttribute("data-text", txt);
      btn.innerHTML = `<span class="spinner"></span> ${txt}`;
    });
  });
}

// On DOM ready
document.addEventListener("DOMContentLoaded", () => {
  // Attach to your various buttons (add more selectors as needed)
  attachSpinner("#import-btn");
  attachSpinner("#reimport-btn");
  attachSpinner("#edit-profile-btn");
  attachSpinner(".track-link-btn");
  attachSpinner("#view-leaderboard-btn");

  // Inline profile edit toggling
  const editBtn = document.getElementById("edit-profile-btn");
  const formDiv = document.getElementById("profile-edit-form");
  if (editBtn && formDiv) {
    editBtn.addEventListener("click", () => {
      formDiv.style.display = "block";
    });
  }
  const cancelBtn = document.getElementById("cancel-edit-btn");
  if (cancelBtn && formDiv) {
    cancelBtn.addEventListener("click", () => {
      formDiv.style.display = "none";
    });
  }
});
