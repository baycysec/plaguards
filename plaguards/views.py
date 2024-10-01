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


def search(request):
    if request.method == 'POST':
        search_query = request.POST.get('search-bar', '').strip()

        queryinput = []

        queryinput.append(search_sanitize(search_query))

        output_pdf_path = search_IOC_and_generate_report(queryinput, search = True)

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


#ini belum bisa ngambil file dr htmlnya
def file_upload(request):
    if request.method == 'POST':
        file = request.FILES.get('file', None)
        if not file:
            return JsonResponse({
                'status': 'error',
                'message': "Error: No file uploaded."
            })
        if not validate_file_extension(file):
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
            httplist[i] = search_sanitize('url' + ' ' + httplist[i])
 
        for i in range(len(iplist)):
            iplist[i] = search_sanitize('ip' + ' ' + iplist[i]) 
        
        queryinput = httplist + iplist
        output_pdf_path = search_IOC_and_generate_report(queryinput, search = False, code=code)

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
