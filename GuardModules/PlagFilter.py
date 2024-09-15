from django.core.exceptions import escape


def validate_file_extension(filename):
    if not filename.endswith(('.ps1', '.txt')):
        return False
    return True

def search_sanitize(searches):
    safesearch = escape(searches)
    return safesearch