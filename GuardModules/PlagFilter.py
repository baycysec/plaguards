import html


def validate_file_extension(filename):
    if not filename.endswith(('.ps1', '.txt')):
        return False
    return True

def search_sanitize(searches):
    safesearch = html.escape(searches)
    return safesearch
