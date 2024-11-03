// loading-spinner.js

document.addEventListener("DOMContentLoaded", function() {
    const form = document.getElementById("file-upload-form");
    if (form) {
      form.onsubmit = function() {
        document.getElementById("loading-overlay").style.display = "flex";
      };
    }
  });
  