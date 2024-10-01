from django.shortcuts import render

# Create your views here.
def index(request): 
    context = {
        'title': 'home',
    }
    return render(request, 'index.html', context)

def tools(request): 
    context = {
        'title': 'tools',
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

# def search(request):
#     if request.method == 'POST':
#         searches = request.POST.get('search-bar', '')
#         result = search_sanitize(searches)
#         #ini nanti send ke fungsi pencarian ke MalwareBazaarya selanjutnya
#         print(result)

#         # new LOCs
#         context = {''}


##################################
# from django.shortcuts import render
from django.http import HttpResponse
import os
import requests
import pypandoc

# Define the API endpoint
url = 'https://mb-api.abuse.ch/api/v1/'

def get_data(query_type, query_value):
    if query_type == 'hash':
        data = {
            'query': 'get_info',
            'hash': query_value,
            'limit': '1'
        }
    elif query_type == 'signature':
        data = {
            'query': 'get_siginfo',
            'signature': query_value,
            'limit': '50'
        }
    else:
        raise ValueError("Unsupported query type. Use 'hash' or 'signature'.")

    response = requests.post(url, data=data)

    if response.status_code == 200:
        return response.json()
    else:
        return None

def md_to_pdf(md_file, output_dir, template_path=None):
    try:
        # Ensure the output directory exists
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        # Create full path for the PDF file
        output_pdf = os.path.join(output_dir, 'RESULT')

        # LaTeX options to set margins and use the template if provided
        extra_args = [
            "--pdf-engine=xelatex",  # using xelatex for better font handling
            "-V", "geometry:margin=1in"
        ]
        
        # this one.
        # if template_path:
        #     extra_args.append(f"--template={template_path}")

        # Convert the Markdown file to PDF
        output = pypandoc.convert_file(md_file, 'pdf', outputfile=output_pdf, extra_args=extra_args)
        assert output == ""  # If the conversion is successful, output will be an empty string

        print(f"Successfully converted {md_file} to {output_pdf}")
    except Exception as e:
        print(f"Error occurred during PDF conversion: {e}")


def search(request):
    if request.method == 'POST':
        search_query = request.POST.get('search-bar', '').strip()

        # Split the search query into arguments
        args = search_query.split()

        if len(args) != 2:
            return HttpResponse("Error: Please enter exactly 2 arguments (e.g., 'hash <value>').")

        query_type = args[0]
        query_value = args[1]

        # Validate the query type
        if query_type not in ['hash', 'signature']:
            return HttpResponse("Error: Invalid query type. Use 'hash' or 'signature'.")

        # Call the API
        json_data = get_data(query_type, query_value)

        if not json_data:
            return HttpResponse("Error: No data returned from the API.")

        # Generate markdown content
        md_content = []
        for entry in json_data.get("data", []):
            mw_name = entry.get("signature", "Unknown Malware")
            md_content.append(f'# {mw_name}\n')
            md_content.append(f'- **File Name**: {entry.get("file_name", "N/A")}')
            md_content.append(f'- **SHA256 Hash**: {entry.get("sha256_hash", "N/A")}')
            md_content.append(f'- **File Size**: {entry.get("file_size", "N/A")} bytes')
            md_content.append(f'- **MD5 Hash**: {entry.get("md5_hash", "N/A")}')
            md_content.append(f'- **Imphash**: {entry.get("imphash", "N/A")}')
            
            tags = entry.get("tags", [])
            tags = ', '.join(tags) if isinstance(tags, list) else "N/A"
            md_content.append(f'- **Tags**: {tags}')
            
            intelligence = entry.get("intelligence", {})
            clamav_detections = intelligence.get("clamav", [])
            clamav_detections = ", ".join(clamav_detections) if isinstance(clamav_detections, list) else "N/A"
            md_content.append(f'- **ClamAV Detections**: {clamav_detections}')
            md_content.append(f'- **Downloads**: {intelligence.get("downloads", "N/A")}')
            md_content.append(f'- **Uploads**: {intelligence.get("uploads", "N/A")}')
            md_content.append(f'- **Mail Intelligence**: {intelligence.get("mail", "None")}')
            md_content.append('\n')

        # Save markdown file
        md_file_path = os.path.join('malware_data.md')
        with open(md_file_path, 'w') as md_file:
            md_file.write('\n'.join(md_content))

        # Convert to PDF
        # output_pdf_path = 'pdf_result'
        # template_path = os.path.join('pdf_templates', 'custom_template.tex')
        # md_to_pdf(md_file_path, output_pdf_path, template_path)
        output_pdf_path = os.path.join('malware_data.pdf')
        md_to_pdf(md_file_path, output_pdf_path)

        return HttpResponse(f"Markdown and PDF generated. PDF: {output_pdf_path}")

    return render(request, 'index.html')
