from django.shortcuts import render

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