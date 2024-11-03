function showNotification(message, type = 'success') {
    const notification = $('#notification');
    notification.text(message).removeClass('error').addClass(type).fadeIn();
    setTimeout(() => notification.fadeOut(), 3000);
  }
  
  $(document).ready(() => {
    // Ajax for Search Form
    $('#search-form').on('submit', function(e) {
      e.preventDefault();
      $.ajax({
        url: $(this).attr('action'),
        type: 'POST',
        data: $(this).serialize(),
        dataType: 'json',
        success(response) {
          if (response.status === 'success') {
            showNotification(response.message);
            window.location.href = `/redirect_result?pdf_url=${encodeURIComponent(response.pdf_url)}`;
          } else {
            showNotification(response.message, 'error');
          }
        },
        error() {
          showNotification('An error occurred. Please try again.', 'error');
        }
      });
    });
  
    // Ajax for File Upload Form
    $('#file-upload-form').on('submit', function(e) {
      e.preventDefault();
      const formData = new FormData(this);
  
      $.ajax({
        url: $(this).attr('action'),
        type: 'POST',
        data: formData,
        processData: false,
        contentType: false,
        dataType: 'json',
        success(response) {
          if (response.status === 'success') {
            showNotification(response.message);
            window.location.href = `/redirect_result?pdf_url=${encodeURIComponent(response.pdf_url)}`;
          } else {
            showNotification(response.message, 'error');
          }
        },
        error() {
          showNotification('An error occurred. Please try again.', 'error');
        }
      });
    });
  });
  

  document.getElementById("file-upload-form").onsubmit = function() {
    document.getElementById("loading-overlay").style.display = "flex";
  };