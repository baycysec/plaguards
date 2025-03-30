from django.shortcuts import render
from django.http import JsonResponse
from GuardModules.PlagFilter import *
from GuardModules.PlagDeobfus import deobfuscate
from GuardModules.PlagParser import search_IOC_and_generate_report
import os
import string
import random
import hashlib
import pypandoc

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

        if 'Error' in output_pdf_path:
            return JsonResponse({
                'status': 'error',
                'message': output_pdf_path
            })
        elif 'No data' in output_pdf_path:
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

def generate_deobfus_md(powershell, previous_hash=None):
    md_content = []
    code, httplist,ip = deobfuscate(powershell)
    if "Something's wrong with the code or input!" in code:
        return JsonResponse({
            'status': 'error',
            'message': code
    })
    print(code)
    checkcode = code.split('\n')
    # print(code)
    md_content.append(f'```ps1')
    for line in checkcode:
        md_content.append(f'{line}')
    md_content.append(f'```')
    md_content.append(f'\n')

    md_path = './deob_result.md'
    with open(md_path, "w") as md_file:
        md_file.write('\n'.join(md_content))

    sha256sum = hashlib.sha256()
    with open(md_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256sum.update(byte_block)
    
    checksum_1 = sha256sum.hexdigest()
    code2, httplist, ip = deobfuscate(code)

    md_content2 = []
    checkcode2 = code2.split('\n')
    md_content2.append(f'```ps1')
    for line in checkcode2:
        md_content2.append(f'{line}')
    md_content2.append(f'```')
    md_content2.append('\n')

    md_path2 = './deob_result2.md'
    with open(md_path2, "w") as md_file:
        md_file.write('\n'.join(md_content2))
    sha256sum2 = hashlib.sha256()
    with open(md_path2, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256sum2.update(byte_block)
    checksum_2 = sha256sum2.hexdigest()

    if checksum_1 == checksum_2:
        return md_content2, httplist, ip
    else:
        print("[+] Hash Mismatch")
        return generate_deobfus_md(code2, previous_hash=checksum_2)

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
        md_deob_content,httplist,iplist = generate_deobfus_md(code)

        # if "Something's wrong with the code or input!" in deob_code:
        #     return JsonResponse({
        #         'status': 'error',
        #         'message': code
        #     })
        for i in range(len(httplist)):
            httplist[i] = search_sanitize('domain' + ' ' + httplist[i])
 
        for i in range(len(iplist)):
            iplist[i] = search_sanitize('ip' + ' ' + iplist[i]) 
        
        queryinput = httplist + iplist
        output_pdf_path = search_IOC_and_generate_report(queryinput, search=False, code=md_deob_content)

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
