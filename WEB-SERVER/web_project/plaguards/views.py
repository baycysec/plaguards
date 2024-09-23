from django.shortcuts import render
from django.http import HttpResponse
import os
import requests
import pypandoc

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
    # Retrieve the PDF URL from the session
    pdf_url = request.session.get('pdf_url', None)
    
    # Clear the PDF URL from the session after retrieving it
    if pdf_url:
        del request.session['pdf_url']

    context = {
        'title': 'Tools',
        'pdf_url': pdf_url,  # Add the PDF URL to the context
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

# # Define the API endpoint
# url = 'https://mb-api.abuse.ch/api/v1/'
# url = 'https://www.virustotal.com/api/v3/domains/{domain}'

# Function to fetch data from the API
def get_data(query_type, query_value):
    if query_type == 'hash':
        data = {
            'query': 'get_info',
            'hash': query_value,
            'limit': '1'
        }
        response = requests.post('https://mb-api.abuse.ch/api/v1/', data=data)

    elif query_type == 'signature':
        data = {
            'query': 'get_siginfo',
            'signature': query_value,
            'limit': '50'
        }
        response = requests.post('https://mb-api.abuse.ch/api/v1/', data=data)

    elif query_type == 'domain':
        url = f'https://www.virustotal.com/api/v3/domains/{query_value}'
        headers = {
            'x-apikey': '685ca79fa45028696c796f773802c5cef7f495b9e63d74e817db0545701c029f'  # Replace with your actual VirusTotal API key
        }
        response = requests.get(url, headers=headers)

    elif query_type == 'ip':
        url = f'https://www.virustotal.com/api/v3/ip_addresses/{query_value}'
        headers = {
            'x-apikey': '685ca79fa45028696c796f773802c5cef7f495b9e63d74e817db0545701c029f'  # Replace with your actual VirusTotal API key
        }
        response = requests.get(url, headers=headers)

    elif query_type == 'url':
        # URLs need to be URL-encoded and then Base64 encoded
        url_id = base64.urlsafe_b64encode(query_value.encode()).decode().strip("=")
        url = f'https://www.virustotal.com/api/v3/urls/{url_id}'
        headers = {
            'x-apikey': '685ca79fa45028696c796f773802c5cef7f495b9e63d74e817db0545701c029f'  # Replace with your actual VirusTotal API key
        }
        response = requests.get(url, headers=headers)

    else:
        raise ValueError("Unsupported query type. Use 'hash', 'signature', 'domain', or 'ip'.")

    if response.status_code == 200:
        return response.json()
    else:
        return None

# Function to convert Markdown to PDF
def md_to_pdf(md_file, output_dir, template_path=None):
    try:
        # Ensure the output directory exists
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        # Create the full path for the PDF file
        output_pdf = os.path.join(output_dir, 'malware_data.pdf')

        # Set extra arguments for LaTeX processing
        extra_args = [
            "--pdf-engine=xelatex",
            "-V", "geometry:margin=1in",
            # "-V", "geometry:margin=0.9in, right=3.9in",
            # "-V", "geometry:margin=1in",
            # "-V", "geometry:padding=1in",
            "-V", "papersize=a4",
            # "-V", "documentclass=report",
            # "-V", "mainfont=Merriweather",
            "-V", "mainfont=Poppins",
            "-V", "monofont=Inconsolata",
            "-V", "sansfont=Open Sans",
            "-V", "colorlinks",
            "-V", "urlcolor=NavyBlue",
            "--variable", "linestretch=1.5",
            # "--pdf-engine-opt=-output-directory=../fonts",
            # "--pdf-engine-opt=-fontdir=../fonts",  
        ]

        # Optional template
        if template_path:
            extra_args.append(f"--template={template_path}")

        # Convert the Markdown file to PDF
        output = pypandoc.convert_file(md_file, 'pdf', outputfile=output_pdf, extra_args=extra_args)
        assert output == ""  # If the conversion is successful, output will be an empty string

        return output_pdf  # Return the path to the PDF
    except Exception as e:
        print(f"Error during PDF conversion: {e}")
        return None

# Main search view that processes API requests and converts the result to PDF
def search(request):
    if request.method == 'POST':
        search_query = request.POST.get('search-bar', '').strip()

        # Split the search query into arguments
        args = search_query.split()

        if len(args) != 2:
            return HttpResponse("Error: Please enter exactly 2 arguments (e.g., [hash / signature / domain / url / ip] [value]).")

        query_type = args[0]
        query_value = args[1]

        # Validate the query type
        if query_type not in ['hash', 'signature', 'domain', 'ip', 'url']:
            return HttpResponse("Error: Invalid query type. Use 'hash' or 'signature'.")

        # Call the API
        json_data = get_data(query_type, query_value)

        if not json_data:
            return HttpResponse("Error: No data returned from the API.")

         # Initialize markdown content
        md_content = []

        # Add report header based on API source
        if query_type in ['hash', 'signature']:
            # md_content.append(f'# Abuse.ch Report for {query_value}')
            # Generate report from Abuse.ch
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

        elif query_type == 'domain':
            md_content.append(f'# VirusTotal Domain Report for {query_value}')
            attributes = json_data.get("data", {}).get("attributes", {})
            md_content.append(f'- **Last Analysis Stats**: {attributes.get("last_analysis_stats", {})}')
            md_content.append(f'- **Reputation**: {attributes.get("reputation", "N/A")}')
            md_content.append(f'- **Tags**: {", ".join(attributes.get("tags", []))}')
            md_content.append('\n')

        elif query_type == 'ip':
            md_content.append(f'# VirusTotal IP Address Report for {query_value}')
            attributes = json_data.get("data", {}).get("attributes", {})
            md_content.append(f'- **Last Analysis Stats**: {attributes.get("last_analysis_stats", {})}')
            md_content.append(f'- **Reputation**: {attributes.get("reputation", "N/A")}')
            md_content.append(f'- **Tags**: {", ".join(attributes.get("tags", []))}')
            md_content.append('\n')

        elif query_type == 'url':
            md_content.append(f'# VirusTotal URL Report for {query_value}')
            attributes = json_data.get("data", {}).get("attributes", {})
            md_content.append(f'- **Last Analysis Stats**: {attributes.get("last_analysis_stats", {})}')
            md_content.append(f'- **Reputation**: {attributes.get("reputation", "N/A")}')
            md_content.append(f'- **Categories**: {", ".join(attributes.get("categories", {}).values())}')
            md_content.append(f'- **Last Final URL**: {attributes.get("last_final_url", "N/A")}')
            md_content.append(f'- **Title**: {attributes.get("title", "N/A")}')
            md_content.append('\n')

        # Save markdown file
        md_file_path = os.path.join('malware_data.md')
        with open(md_file_path, 'w') as md_file:
            md_file.write('\n'.join(md_content))

        # Convert to PDF
        output_pdf_path = os.path.join('RESULT')
        md_to_pdf(md_file_path, output_pdf_path)

        # request.session['pdf_url'] = output_pdf_path

        if output_pdf_path:
            return HttpResponse(f"Markdown and PDF generated. PDF: {output_pdf_path}")
            # return redirect('tools')
        else:
            return HttpResponse("Error: PDF generation failed.")

    return render(request, 'index.html')


# Example view to handle file uploads
def file_upload(request):
    if request.method == 'POST':
        file = request.FILES.get('file', None)
        if not file:
            return HttpResponse("Error: No file uploaded.")
        if not validate_file_extension(file):
            return HttpResponse("Error: Invalid file extension, please upload a .ps1 or .txt file.")
        
        # Handle file saving or processing here...

    return render(request, 'tools.html')

# Helper function to validate file extensions
def validate_file_extension(file):
    valid_extensions = ['.ps1', '.txt']
    ext = os.path.splitext(file.name)[1]
    return ext.lower() in valid_extensions
