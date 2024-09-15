from django.shortcuts import render
from GuardModules.PlagFilter import *

# Create your views here.
def index(request): 
    context = {
        'title': 'Home',
    }
    return render(request, 'index.html', context)

def tools(request): 
    context = {
        'title': 'Tools',
    }
    return render(request, 'tools.html', context)

def about(request): 
    context = {
        'title': 'About',
    }
    return render(request, 'about.html', context)

def tutorial(request): 
    context = {
        'title': 'Tutorial',
    }
    return render(request, 'tutorial.html', context)

def file_upload(request):
    context = {}
    if request.method == 'POST':
        file = request.FILES['file']
        if not file:
            context['message'] = "No file uploaded. Please choose a file to upload."
            return render(request, 'tools.html', context)
        if validate_file_extension(file) == False:
            context['message'] = "Invalid file extension, please upload .ps1 or .txt files extension."
            return render(request, 'tools.html', context)

def search(request):
    if request.method == 'POST':
        searches = request.POST.get('search-bar', '')
        result = search_sanitize(searches)
        #ini nanti send ke fungsi pencarian ke MalwareBazaarya selanjutnya

