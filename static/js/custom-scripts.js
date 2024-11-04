function showNotification(message, type = 'success') {
  const notification = $('#notification');
  notification.text(message).removeClass('error').addClass(type).fadeIn();
  setTimeout(() => notification.fadeOut(), 3000);
}

$(document).ready(() => {
  function showLoadingSpinner() {
    $('#loading-overlay').css('display', 'flex');
  }

  function hideLoadingSpinner() {
    $('#loading-overlay').css('display', 'none');
  }

  $('#search-form').on('submit', function(e) {
    e.preventDefault();
    showLoadingSpinner();

    $.ajax({
      url: $(this).attr('action'),
      type: 'POST',
      data: $(this).serialize(),
      dataType: 'json',
      success(response) {
        hideLoadingSpinner();
        if (response.status === 'success') {
          showNotification(response.message);
          window.location.href = `/redirect_result?pdf_url=${encodeURIComponent(response.pdf_url)}`;
        } else {
          showNotification(response.message, 'error');
        }
      },
      error() {
        hideLoadingSpinner();
        showNotification('An error occurred. Please try again.', 'error');
      }
    });
  });

  $('#file-upload-form').on('submit', function(e) {
    e.preventDefault();
    showLoadingSpinner();
    const formData = new FormData(this);

    $.ajax({
      url: $(this).attr('action'),
      type: 'POST',
      data: formData,
      processData: false,
      contentType: false,
      dataType: 'json',
      success(response) {
        hideLoadingSpinner();
        if (response.status === 'success') {
          showNotification(response.message);
          window.location.href = `/redirect_result?pdf_url=${encodeURIComponent(response.pdf_url)}`;
        } else {
          showNotification(response.message, 'error');
        }
      },
      error() {
        hideLoadingSpinner();
        showNotification('An error occurred. Please try again.', 'error');
      }
    });
  });
});
