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

def md_to_pdf(md_file, output_dir, template_path="/usr/share/pandoc/data/templates/eisvogel.latex"):
    try:
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        # Create the full path for the PDF file
        output_pdf = os.path.join(output_dir, 'checker_result.pdf')

        
        extra_args = [
            "--pdf-engine=xelatex",
            "--template=eisvogel",
            "--listings",
            # "-V", "titlepage-background=/plaguards-main/others/bg.pdf"
        ]

        if template_path:
            extra_args.append(f"--template={template_path}")

        output = pypandoc.convert_file(md_file, 'pdf', outputfile=output_pdf, extra_args=extra_args)
        assert output == ""

        return output_pdf

    except Exception as e:
        print(f"Error during PDF conversion: {e}")
        print(f'TEMPLATE PATH --> {template_path}')
        return None

# def add_metadata(temp_md_file):
#     try:
#         with open(outputfile, 'r', encoding='utf-8') as file:
#             md_content = file.readlines()
        
#         md_content.insert(0, b'---\n')
#         md_content.insert(1, b'title: "Malware Report"\n')
#         md_content.insert(2, b'author: "Nicolas Saputra Gunawan"\n')
#         md_content.insert(3, b'date: "2024-10-18"\n')
#         md_content.insert(4, b'toc: true\n')
#         md_content.insert(5, b'ftoc-own-page: true\n')
#         md_content.insert(6, b'titlepage-background: "./plag.pdf"')
#         md_content.insert(7, b'...\n\n')

#         with open(outputfile, 'w', encoding='utf-8') as file:
#             file.writelines(md_content)
        
#         print("METADATA ADDED!!")

#     except Exception as e:
#         print(f'An error occured while adding metadata {e}')

def search_IOC_and_generate_report(queryinput, search=False, code=None):
    # add_metadata("others/templates.md")
    md_content = []


    md_content.append('---')
    md_content.append('title: ""')
    md_content.append('author: "PLAGUARDS"')
    md_content.append('date: "IOC Report"')
    md_content.append('titlepage: true') # cover
    # md_content.append('title-page-color: "FFFFFF"')
    md_content.append('titlepage-rule-color: "FFFFFF"')
    md_content.append('titlepage-text-color: "FFFFFF"')
    md_content.append('page-background: "/app/results/background.png"')
    md_content.append('toc: true') # daftar isi
    md_content.append('toc-own-page: true')
    md_content.append('titlepage-background: "/app/results/ioc-bg.pdf"')
    md_content.append('...')
    md_content.append('\n')


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

        if not json_data:
            return "Error: No data returned from the API."
        if 'query_status' in json_data:
            if (json_data['query_status'] == 'no_results' or json_data['query_status'] == 'illegal_hash') and search:
                return "Error: No data returned from the API."
            if json_data['query_status'] == 'no_results' or json_data['query_status'] == 'illegal_hash':
                md_content.append(f'# VirusTotal Report for {query_value}\n')
                md_content.append(f'No Information Found')
                continue

        if query_type in ['hash', 'signature']:
            for entry in json_data.get("data", []):
                mw_name = entry.get("signature", "Unknown Malware")
                md_content.append(f'# {mw_name}\n')
                md_content.append('## File Name(s):')
                md_content.append(f'{entry.get("file_name", "N/A")}\n')
                md_content.append(f'File Size: {entry.get("file_size", "N/A")} bytes')
                md_content.append('### File Hash:')
                md_content.append(f'SHA256 Hash: {entry.get("sha256_hash", "N/A")}')
                md_content.append(f'MD5 Hash**: {entry.get("md5_hash", "N/A")}')
                md_content.append(f'Imphash**: {entry.get("imphash", "N/A")}')

                tags = entry.get("tags", [])
                tags = ', '.join(tags) if isinstance(tags, list) else "N/A"
                md_content.append(f'## File Tag(s):')
                md_content.append(f'- **Tags**: {tags}')

                intelligence = entry.get("intelligence", {})
                clamav_detections = intelligence.get("clamav", [])
                clamav_detections = ", ".join(clamav_detections) if isinstance(clamav_detections, list) else "N/A"
                md_content.append(f'')
                md_content.append(f'## ClamAV Detections:')
                md_content.append(f'{clamav_detections}')
                md_content.append(f'')

                md_content.append(f'Downloads: {intelligence.get("downloads", "N/A")}')
                md_content.append(f'Uploads: {intelligence.get("uploads", "N/A")}')
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

    md_file_path = os.path.join('results/checker.md')
    with open(md_file_path, 'w') as md_file: # previously w mode.
        md_file.write('\n'.join(md_content))

    output_pdf_path = os.path.join('results')
    md_to_pdf(md_file_path, output_pdf_path)


    return output_pdf_path
