from django.shortcuts import render
from django.http import JsonResponse
from GuardModules.PlagFilter import *
from GuardModules.PlagDeobfus import deobfuscate
from GuardModules.PlagParser import search_IOC_and_generate_report
import os

def index(request): 
    context = {
        'title': 'home',
    }
    return render(request, 'index.html', context)

def tools(request): 
    pdf_url = request.session.get('pdf_url', None)
    
    if pdf_url:
        del request.session['pdf_url']

    context = {
        'title': 'Tools',
        'pdf_url': pdf_url,
    }
    return render(request, 'tools.html', context)

def about(request): 
    context = {
        'title': 'about',
    }
    return render(request, 'about.html', context)

def tutorial(request): 
    context = {
        'title': 'tutorial',
    }
    return render(request, 'tutorial.html', context)

def results(request):
    pdf_url = request.session.get('pdf_url', None)
    
    context = {
        'title': 'Results',
        'pdf_url': pdf_url,
    }
    return render(request, 'results.html', context) 


def search(request):
    if request.method == 'POST':
        search_query = request.POST.get('search-bar', '').strip()
        queryinput = []
        queryinput.append(search_sanitize(search_query))
        
        output_pdf_path = search_IOC_and_generate_report(queryinput, search=True)

        print(output_pdf_path)

        if 'Error' in output_pdf_path:
            return JsonResponse({
                'status': 'error',
                'message': output_pdf_path
            })
        else:
            return JsonResponse({
                'status': 'success',
                'message': "Report generated successfully.",
                'pdf_url': output_pdf_path
            })
    return render(request, 'results.html')


def file_upload(request):
    if not request.FILES:
        return JsonResponse({
            'status': 'error',
            'message': "Error: No file uploaded."
        })
    elif request.method == 'POST':
        file = request.FILES['file']            
        if not validate_file_extension(os.path.splitext(file.name)[1].lower()):
            return JsonResponse({
                'status': 'error',
                'message': "Error: Invalid file extension, please upload a .ps1 or .txt file."
            })
         
        code = file.read().decode('utf-8')
        code,httplist,iplist = deobfuscate(code)

        if code == "Something's wrong with the code or input!":
            return JsonResponse({
                'status': 'error',
                'message': code
            })
        for i in range(len(httplist)):
            httplist[i] = search_sanitize('domain' + ' ' + httplist[i])
 
        for i in range(len(iplist)):
            iplist[i] = search_sanitize('ip' + ' ' + iplist[i]) 
        
        queryinput = httplist + iplist
        output_pdf_path = search_IOC_and_generate_report(queryinput, search=False, code=code)

        if 'Error' in output_pdf_path:
            return JsonResponse({
                'status': 'error',
                'message': output_pdf_path
            })
        else:
            return JsonResponse({
                'status': 'success',
                'message': "Report generated successfully.",
                'pdf_url': output_pdf_path
            })

    return render(request, 'results.html')

def redirect_result(request):
    pdf_url = request.GET.get('pdf_url')
    return render(request, 'results.html', {'pdf_url': pdf_url})

# def reports_view(request):
#     media_dir = settings.MEDIA_ROOT
#     if not os.path.exists(media_dir):
#         print("Media directory does not exist.")
#         return render(request, 'index.html', {'recent_pdfs': []})

#     pdf_files = [f for f in os.listdir(media_dir) if f.endswith('.pdf')]
#     print(f"Found PDF files: {pdf_files}")  # Debugging output
#     pdf_files = sorted(pdf_files, key=lambda x: os.path.getctime(os.path.join(media_dir, x)), reverse=True)[:4]
#     print(f"Recent PDFs: {pdf_files}")  # Debugging output
#     return render(request, 'index.html', {'recent_pdfs': pdf_files})
