from django.shortcuts import render
from django.conf import settings
from django.http import JsonResponse
from GuardModules.PlagFilter import *
from GuardModules.PlagDeobfus import deobfuscate
from GuardModules.PlagParser import search_IOC_and_generate_report


# Create your views here.
def index(request): 
    context = {
        'title': 'home',
    }
    return render(request, 'index.html', context)

# def tools(request): 
#     context = {
#         'title': 'tools',
#     }
#     return render(request, 'tools.html', context)

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
    context = {
        'title': 'Results',
    }
    return render(request, 'results.html', context)    

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
        search_query = request.POST.get('search-bar', '').strip()

        queryinput = []

        queryinput.append(search_sanitize(search_query))

        output_pdf_path = search_IOC_and_generate_report(queryinput)

        if output_pdf_path:
            return JsonResponse({
                'status': 'success',
                'message': "Report generated successfully.",
                'pdf_url': output_pdf_path
            })
        else:
            return JsonResponse({
                'status': 'error',
                'message': "Error: PDF generation failed."
            })
    return render(request, 'results.html')


def file_upload(request):
    if request.method == 'POST':
        file = request.FILES.get('file', None)
        if not file:
            return HttpResponse("Error: No file uploaded.")
        if not validate_file_extension(file):
            return HttpResponse("Error: Invalid file extension, please upload a .ps1 or .txt file.")
        
        # Handle file saving or processing here...

    return render(request, 'results.html')




# def results_view(request, report_id):
#     try:
#         report = Report.objects.get(id=report_id)
#         context = {
#             'title': 'Results',
#             'pdf_url': report.pdf_file.url if report.pdf_file else None,
#         }
#         return render(request, 'results.html', context)
#     except Report.DoesNotExist:
#         return HttpResponse("Report not found", status=404)
