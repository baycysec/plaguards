import html
import os

def validate_file_extension(file):
    valid_extensions = ['.ps1', '.txt']
    ext = os.path.splitext(file.name)[1]
    return ext.lower() in valid_extensions

def search_sanitize(searches):
    safesearch = html.escape(searches)
    return safesearch
