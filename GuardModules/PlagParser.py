import requests
import pypandoc
import os

def FindQuery(query_type, query_value):
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
            'x-apikey': '685ca79fa45028696c796f773802c5cef7f495b9e63d74e817db0545701c029f'
        }
        response = requests.get(url, headers=headers)

    elif query_type == 'ip':
        url = f'https://www.virustotal.com/api/v3/ip_addresses/{query_value}'
        headers = {
            'x-apikey': '685ca79fa45028696c796f773802c5cef7f495b9e63d74e817db0545701c029f'
        }
        response = requests.get(url, headers=headers)

    elif query_type == 'url':
        url_id = base64.urlsafe_b64encode(query_value.encode()).decode().strip("=")
        url = f'https://www.virustotal.com/api/v3/urls/{url_id}'
        headers = {
            'x-apikey': '685ca79fa45028696c796f773802c5cef7f495b9e63d74e817db0545701c029f'
        }
        response = requests.get(url, headers=headers)

    else:
        raise ValueError("Unsupported query type. Use 'hash', 'signature', 'domain', or 'ip'.")

    if response.status_code == 200:
        return response.json()
    else:
        return None

def md_to_pdf(md_file, output_dir, template_path=None):
    try:
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

        if template_path:
            extra_args.append(f"--template={template_path}")

        output = pypandoc.convert_file(md_file, 'pdf', outputfile=output_pdf, extra_args=extra_args)
        assert output == ""

        return output_pdf
    except Exception as e:
        print(f"Error during PDF conversion: {e}")
        return None

def search_IOC_and_generate_report(queryinput, search = False, code = None):
    md_content = []

    if code:
        md_content.append(f'# Deobfuscated Code\n')
        md_content.append(code)

    for i in range(len(queryinput)):
        args = queryinput[i].split()

        if len(args) != 2:
            return "Error: Please enter exactly 2 arguments (e.g., [hash / signature / domain / url / ip] [value])."

        query_type = args[0]
        query_value = args[1]

        if query_type not in ['hash', 'signature', 'domain', 'ip', 'url']:
            return "Error: Invalid query type. Use 'hash' or 'signature'."

        json_data = FindQuery(query_type, query_value)

        if json_data['query_status'] == 'no_results' and search:
            return "Error: No data returned from the API."
        if json_data['query_status'] == 'no_results':
            md_content.append(f'# VirusTotal Report for {query_value}\n')
            md_content.append(f'No Information Found')
            continue


        if query_type in ['hash', 'signature']:
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

    md_file_path = os.path.join('malware_data.md')
    with open(md_file_path, 'w') as md_file:
        md_file.write('\n'.join(md_content))

    output_pdf_path = os.path.join('results')
    md_to_pdf(md_file_path, output_pdf_path)

    # request.session['pdf_url'] = output_pdf_path

    return output_pdf_path
