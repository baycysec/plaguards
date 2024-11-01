import requests
import pypandoc
import os
import base64
import string
import random

def generate_random_val(length):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

VT_API_KEY = os.getenv("VT_API_KEY")

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
            'x-apikey': VT_API_KEY
        }
        response = requests.get(url, headers=headers)

    elif query_type == 'ip':
        url = f'https://www.virustotal.com/api/v3/ip_addresses/{query_value}'
        headers = {
            'x-apikey': VT_API_KEY
        }
        response = requests.get(url, headers=headers)

    elif query_type == 'url':
        url_id = base64.urlsafe_b64encode(query_value.encode()).decode().strip("=")
        url = f'https://www.virustotal.com/api/v3/urls/{url_id}'
        headers = {
            'x-apikey': VT_API_KEY
        }
        response = requests.get(url, headers=headers)

    else:
        raise ValueError("Unsupported query type. Use 'hash', 'signature', 'domain', or 'ip'.")

    if response.status_code == 200:
        return response.json()
    else:
        return None

def md_to_pdf(md_file, path, randomval, template_path="/usr/share/pandoc/data/templates/eisvogel.latex"):
    try:
        if not os.path.exists(path):
            os.makedirs(path)

        # Create the full path for the PDF file
        output_pdf = os.path.join(path, f'checker_result_{randomval}.pdf')

        
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

def search_IOC_and_generate_report(queryinput, search=False, code=None):
    md_content = []
    if code:
        md_content.append('---')
        md_content.append('title: ""')
        md_content.append('author: "PLAGUARDS"')
        md_content.append('date: "Debfuscate and IOC Report"')
        md_content.append('titlepage: true') # cover
        # md_content.append('title-page-color: "FFFFFF"')
        md_content.append('titlepage-rule-color: "FFFFFF"')
        md_content.append('titlepage-text-color: "FFFFFF"')
        md_content.append('page-background: "/app/results/background.png"')
        md_content.append('toc: true') # daftar isi
        md_content.append('toc-own-page: true')
        md_content.append('titlepage-background: "/app/results/deobfus-bg.pdf"')
        md_content.append('...')
        md_content.append('\n')
        md_content.append(f'# Deobfuscated Code\n')
        checkcode = code.split('\n')

        md_content.append(f'```ps1')

        for i in checkcode:
            md_content.append(f'{i}')
        
        md_content.append(f'```')

        md_content.append('\n')
    else:
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

    for i in range(len(queryinput)):
        args = queryinput[i].split()

        if len(args) != 2:
            return "Error: Please enter exactly 2 arguments (e.g., [hash / signature / domain / url / ip] [value])."

        query_type = args[0]
        query_value = args[1]

        if query_type not in ['hash', 'signature', 'domain', 'ip', 'url']:
            return "Error: Invalid query type. Use 'hash' or 'signature'."

        json_data = FindQuery(query_type, query_value)

        if not json_data and search:
            return "Error: No data returned from the API."
        elif not json_data and search == False:
            md_content.append(f'# VirusTotal Report for {query_value}\n')
            md_content.append(f'No Information Found')
            md_content.append('\n')
            continue

        if 'query_status' in json_data:
            if (json_data['query_status'] == 'no_results' or json_data['query_status'] == 'illegal_hash') and search:
                return "Error: No data returned from the API."
            elif json_data['query_status'] == 'no_results' or json_data['query_status'] == 'illegal_hash':
                md_content.append(f'# VirusTotal Report for {query_value}\n')
                md_content.append(f'No Information Found')
                md_content.append('\n')
                continue

        if query_type in ['hash', 'signature']:
            for entry in json_data.get("data", []):
                mw_name = entry.get("signature", "Unknown Malware")
                md_content.append(f'# Threat Intelligence Report\n')
                md_content.append('## Overview')
                md_content.append(f"This report provides detailed information on a malicious file detected on **{entry.get('first_seen', 'N/A')}**. The file is identified associated with the **{mw_name}** malware.")
                md_content.append("\n---\n")
                
                # File Information Section
                md_content.append("## File Information")
                md_content.append(f"- **File Name:** `{entry.get('file_name', 'N/A')}`")
                md_content.append(f"- **File Size:** {entry.get('file_size', 'N/A')} bytes")
                md_content.append(f"- **File Type:** Executable (EXE)")
                md_content.append(f"- **MIME Type:** `{entry.get('file_type_mime', 'N/A')}`")
                md_content.append(f"- **SHA-256 Hash:** `{entry.get('sha256_hash', 'N/A')}`")
                md_content.append(f"- **SHA-3-384 Hash:** `{entry.get('sha3_384_hash', 'N/A')}`")
                md_content.append(f"- **SHA-1 Hash:** `{entry.get('sha1_hash', 'N/A')}`")
                md_content.append(f"- **MD5 Hash:** `{entry.get('md5_hash', 'N/A')}`")
                md_content.append(f"- **Reporter:** {entry.get('reporter', 'N/A')}")
                md_content.append(f"- **Origin Country:** {entry.get('origin_country', 'N/A')}")
                md_content.append(f"- **First Seen:** {entry.get('first_seen', 'N/A')}")
                md_content.append(f"- **Last Seen:** {entry.get('last_seen', 'N/A')}")
                md_content.append("\n---\n")
                
                # Malware Signatures and Hashes Section
                md_content.append("## Malware Signatures and Hashes")
                md_content.append(f"- **Signature:** {mw_name}")
                md_content.append(f"- **ImpHash:** `{entry.get('imphash', 'N/A')}`")
                md_content.append(f"- **TLSH:** `{entry.get('tlsh', 'N/A')}`")
                md_content.append(f"- **SSDeep:** `{entry.get('ssdeep', 'N/A')}`")
                md_content.append("\n---\n")
                
                # Threat Analysis by Vendors Section
                vendor_intel = entry.get("vendor_intel", {})
                md_content.append("## Threat Analysis by Vendors")
                for vendor, details in vendor_intel.items():
                    md_content.append(f"### {vendor}")
                    if isinstance(details, list):
                        for detail in details:
                            if isinstance(detail, dict):
                                md_content.append(f"- **Verdict:** {detail.get('verdict', 'N/A')}")
                                md_content.append(f"- **Malware Family:** {detail.get('malware_family', 'N/A')}")
                                tags = detail.get("tags", [])
                                md_content.append(f"- **Tags:** {', '.join(tags) if isinstance(tags, list) else tags}")
                                md_content.append(f"- **Analysis URL:** [View Analysis]({detail.get('analysis_url', '#')})")
                            else:
                                md_content.append(f"- **Detail:** {detail}")
                    else:
                        md_content.append(f"- **Details:** {details}")
                    md_content.append("\n")
                md_content.append("\n---\n")
    
                # Additional Details Section
                md_content.append("## Additional Details")
                intelligence = entry.get("intelligence", {})
                md_content.append(f"- **Downloads:** {intelligence.get('downloads', 'N/A')}")
                md_content.append(f"- **Uploads:** {intelligence.get('uploads', 'N/A')}")
                md_content.append(f"- **Mail Intelligence:** {intelligence.get('mail', 'N/A')}")
                md_content.append("\n---\n")
                
                # Recommendations Section
                md_content.append("## Recommendations")
                md_content.append("1. **Containment:** Block known URLs and C2 servers on the network firewall.")
                md_content.append("2. **Endpoint Protection:** Ensure antivirus definitions are up-to-date.")
                md_content.append("3. **Network Monitoring:** Monitor for unusual HTTP GET requests and credential harvesting activities.")
                md_content.append("\n---")

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
    
    randomval = generate_random_val(150)
    md_file_path = os.path.join(f'results/checker_{randomval}.md')
    with open(md_file_path, 'w') as md_file: # previously w mode.
        md_file.write('\n'.join(md_content))

    path = os.path.join('media')
    md_to_pdf(md_file_path, path, randomval)
    output_pdf_path = os.path.join(f'media/checker_result_{randomval}.pdf')

    return output_pdf_path
