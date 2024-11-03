import requests
import pypandoc
import os
import base64
import string
import random
from datetime import datetime

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
            'limit': '15'
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
        timestamp = datetime.now().strftime('%Y-%m-%d')
        md_content.append('---')
        md_content.append('title: ""')
        md_content.append('author: "DEOBFUS REPORT"')
        md_content.append(f'date: {timestamp}')
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
        timestamp = datetime.now().strftime('%Y-%m-%d')
        md_content = []
        md_content.append('---')
        md_content.append('title: ""')
        md_content.append('author: "IOC Report"')
        md_content.append(f'date: {timestamp}')
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

        if query_type in ['hash']:
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
                # md_content.append(f"- **SHA-256 Hash:** `{entry.get('sha256_hash', 'N/A')}`")
                md_content.append(f"- **SHA-1 Hash:** `{entry.get('sha1_hash', 'N/A')}`")
                md_content.append(f"- **MD5 Hash:** `{entry.get('md5_hash', 'N/A')}`")
                md_content.append(f"- **Reporter:** {entry.get('reporter', 'N/A')}")
                md_content.append(f"- **Origin Country:** {entry.get('origin_country', 'N/A')}")
                md_content.append(f"- **First Seen:** {entry.get('first_seen', 'N/A')}")
                md_content.append(f"- **Last Seen:** {entry.get('last_seen', 'N/A')}")
                md_content.append("\n")
                
                # Malware Signatures and Hashes Section
                md_content.append("## Identification & Classification")
                md_content.append(f"- **Signature:** {mw_name}")
                md_content.append(f"- **ImpHash:** `{entry.get('imphash', 'N/A')}`")
                md_content.append("\n---\n")

                # Threat Analysis by Vendors Section
                vendor_intel = entry.get("vendor_intel", {})
                md_content.append("## Threat Analysis by Vendors")

                for vendor, details in vendor_intel.items():
                    if isinstance(details, dict):  # For vendors with dictionary-type details
                        md_content.append(f"### {vendor}")
                        
                        # Standard fields in vendor details
                        verdict = details.get("verdict", "N/A")
                        malware_family = details.get("malware_family", "N/A")
                        link = details.get("link", "N/A")
                        md_content.append(f"- **Verdict:** {verdict}")
                        md_content.append(f"- **Malware Family:** {malware_family}")
                        
                        if link != "N/A":
                            md_content.append(f"- **Analysis Link:** [{vendor} Analysis]({link})")

                        # Additional specific fields for each vendor if they exist
                        score = details.get("score")
                        if score:
                            md_content.append(f"- **Score:** {score}")

                        behavior = details.get("behaviour")
                        if behavior:
                            md_content.append("- **Behavior Analysis:**")
                            for action in behavior:
                                threat_level = action.get("threat_level", "N/A")
                                rule = action.get("rule", "N/A")
                                md_content.append(f"  - **Threat Level:** {threat_level}, **Rule:** {rule}")
                        
                        maliciousness = details.get("maliciousness")
                        if maliciousness:
                            md_content.append(f"- **Maliciousness:** {maliciousness}")
                        
                        signatures = details.get("signatures", [])
                        if signatures:
                            md_content.append("- **Signatures:**")
                            for sig in signatures:
                                signature = sig.get("signature", "N/A")
                                score = sig.get("score", "N/A")
                                md_content.append(f"  - **Signature:** {signature}, **Score:** {score}")
                        
                        # Optional report or analysis URLs
                        analysis_url = details.get("analysis_url")
                        if analysis_url:
                            md_content.append(f"- **Analysis URL:** [{analysis_url}]({analysis_url})")

                    elif isinstance(details, list):  # For vendors with list-type details
                        md_content.append(f"### {vendor}")
                        for item in details:
                            if isinstance(item, dict):
                                md_content.append("- **Details:**")
                                for key, value in item.items():
                                    md_content.append(f"  - **{key.capitalize()}:** {value}")
                            else:
                                md_content.append(f"- **{item}**")
                    md_content.append("\n")

                # Additional Details Section
                md_content.append("# Additional Details")
                intelligence = entry.get("intelligence", {})
                md_content.append(f"- **Downloads:** {intelligence.get('downloads', 'N/A')}")
                md_content.append(f"- **Uploads:** {intelligence.get('uploads', 'N/A')}")
                md_content.append(f"- **Mail Intelligence:** {intelligence.get('mail', 'N/A')}")
                md_content.append("\n")

                # Recommendations Section
                md_content.append("# Recommendations")
                md_content.append("1. **Containment:** Block known URLs and C2 servers on the network firewall.")
                md_content.append("2. **Endpoint Protection:** Ensure antivirus definitions are up-to-date.")
                md_content.append("3. **Network Monitoring:** Monitor for unusual HTTP GET requests and credential harvesting activities.")
        
        elif query_type in ['signature']:
            count = 1
            for entry in json_data.get("data", []):
                mw_name = entry.get("signature", "Unknown Malware")
                md_content.append(f'# Threat Intelligence Report\n')
                # md_content.append('## Overview')
                # md_content.append(f"This report provides detailed information on a malicious file detected on **{entry.get('first_seen', 'N/A')}**. The file is identified associated with the **{mw_name}** malware.")
                # md_content.append("\n---\n")
                
                # File Information Section
                md_content.append(f"## File Information {count}")
                # md_content.append(f"- **File Name:** `{entry.get('file_name', 'N/A')}`")
                md_content.append(f'### File Name')
                md_content.append('\n')
                md_content.append(f'```txt')
                md_content.append(f"{entry.get('file_name', 'N/A')}")
                md_content.append(f'```')
                md_content.append('\n')

                md_content.append(f"- **File Size:** {entry.get('file_size', 'N/A')} bytes")
                md_content.append(f"- **File Type:** DLL (Dynamic Link Library)")
                md_content.append(f"- **MIME Type:** `{entry.get('file_type_mime', 'N/A')}`")
                md_content.append(f"- **SHA-1 Hash:** `{entry.get('sha1_hash', 'N/A')}`")
                md_content.append(f"- **MD5 Hash:** `{entry.get('md5_hash', 'N/A')}`")
                md_content.append(f"- **Reporter:** {entry.get('reporter', 'N/A')}")
                md_content.append(f"- **Origin Country:** {entry.get('origin_country', 'N/A')}")
                md_content.append(f"- **First Seen:** {entry.get('first_seen', 'N/A')}")
                md_content.append(f"- **Last Seen:** {entry.get('last_seen', 'N/A')}")
                md_content.append("\n")
                
                # Malware Signatures and Hashes Section
                md_content.append("## Malware Signatures and Hashes")
                md_content.append(f"- **Signature:** {mw_name}")
                md_content.append(f"- **ImpHash:** `{entry.get('imphash', 'N/A')}`")
                md_content.append(f"- **Dhash Icon:** `{entry.get('dhash_icon', 'N/A')}`")
                md_content.append("\n---\n")

                # Additional Details Section
                md_content.append("# Additional Details")
                intelligence = entry.get("intelligence", {})
                md_content.append(f"- **Downloads:** {intelligence.get('downloads', 'N/A')}")
                md_content.append(f"- **Uploads:** {intelligence.get('uploads', 'N/A')}")
                md_content.append(f"- **Mail Intelligence:** {intelligence.get('mail', 'N/A')}")
                md_content.append("\n")

                # Recommendations Section
                md_content.append("# Recommendations")
                md_content.append("1. **Containment:** Block known URLs and C2 servers on the network firewall.")
                md_content.append("2. **Endpoint Protection:** Ensure antivirus definitions are up-to-date.")
                md_content.append("3. **Network Monitoring:** Monitor for unusual HTTP GET requests and credential harvesting activities.")
                md_content.append("\n---\n")
                count = count + 1

        elif query_type == 'domain':
            md_content.append(f'# VirusTotal Domain Report for {query_value}')
            attributes = json_data.get("data", {}).get("attributes", {})
            md_content.append(f'# Threat Intelligence Report\n')
            md_content.append('# Domain Information')
            md_content.append(f'- **Domain Name**: {query_value}')
            md_content.append(f'- **Registrar**: {attributes.get("registrar", "N/A")}')
            md_content.append(f'- **Top-Level Domain (TLD)**: {attributes.get("tld", "N/A")}')
            md_content.append(f'- **Whois Record**:\n'
                            f'  - Creation Date: {attributes.get("creation_date", "N/A")}\n'
                            f'  - Updated Date: {attributes.get("last_modification_date", "N/A")}\n'
                            f'  - Expiry Date: {attributes.get("whois_date", "N/A")}\n'
                            f'  - Domain Status: clientTransferProhibited\n'
                            f'  - Name Servers: Duke and Miki via Cloudflare\n')

            # Analysis Summary
            md_content.append('## Analysis Summary')
            md_content.append(f'- **Last Analysis Date**: {attributes.get("last_analysis_date", "N/A")}')
            md_content.append(f'- **Overall Reputation**: {attributes.get("reputation", "N/A")}')
            total_votes = attributes.get("total_votes", {})
            md_content.append(f'- **Total Votes**: Harmless {total_votes.get("harmless", 0)}, Malicious {total_votes.get("malicious", 0)}')
            md_content.append(f'- **Last Update**: {attributes.get("last_update_date", "N/A")}')

            md_content.append('\n')
            # Analysis Statistics
            md_content.append('## Analysis Statistics')
            last_analysis_stats = attributes.get("last_analysis_stats", {})
            md_content.append(f'- **Malicious**: {last_analysis_stats.get("malicious", 0)} detections')
            md_content.append(f'- **Suspicious**: {last_analysis_stats.get("suspicious", 0)} detections')
            md_content.append(f'- **Undetected**: {last_analysis_stats.get("undetected", 0)} sources')
            md_content.append(f'- **Harmless**: {last_analysis_stats.get("harmless", 0)} sources')
            md_content.append(f'- **Timeout**: {last_analysis_stats.get("timeout", 0)}')

            md_content.append('\n')

            # IP Information
            md_content.append('# IP Information')
            dns_records = attributes.get("last_dns_records", [])
            for record in dns_records:
                md_content.append(f'- **Type {record.get("type", "N/A")} Record**:\n'
                                f'  - IP: {record.get("value", "N/A")}\n'
                                f'  - TTL: {record.get("ttl", "N/A")}')
            md_content.append(f'- **Last DNS Record Date**: {attributes.get("last_dns_records_date", "N/A")}')

            md_content.append('\n')

            # Popularity Ranks
            md_content.append('## Popularity Ranks')
            ranks = attributes.get("popularity_ranks", {}).get("Cisco Umbrella", {})
            md_content.append(f'- **Cisco Umbrella**: Rank {ranks.get("rank", "N/A")} (Timestamp: {ranks.get("timestamp", "N/A")})')

            md_content.append('\n')

            # HTTPS Certificate Details
            md_content.append('## HTTPS Certificate Details')
            certificate = attributes.get("last_https_certificate", {})
            cert_signature = certificate.get("cert_signature", {})
            validity = certificate.get("validity", {})
            public_key = certificate.get("public_key", {}).get("rsa", {})
            md_content.append(f'- **Certificate Signature Algorithm**: {cert_signature.get("signature_algorithm", "N/A")}')
            md_content.append(f'- **Validity**:\n'
                            f'  - Not Before: {validity.get("not_before", "N/A")}\n'
                            f'  - Not After: {validity.get("not_after", "N/A")}')
            md_content.append(f'- **Issuer**: {certificate.get("issuer", {}).get("CN", "N/A")}, '
                            f'Country: {certificate.get("issuer", {}).get("C", "N/A")}')
            md_content.append(f'- **Public Key**: RSA, Key Size: {public_key.get("key_size", "N/A")} bits')

            md_content.append('\n')

            md_content.append('-----')

            # Last Analysis Results (Selected Engines)
            md_content.append('# Last Analysis Results (Selected Engines)')
            last_analysis_results = attributes.get("last_analysis_results", {})
            engines = ["Antiy-AVL", "CyRadar", "AlphaSOC", "Emsisoft", "Forcepoint ThreatSeeker"]
            for engine in engines:
                result = last_analysis_results.get(engine, {})
                md_content.append(f'## {engine}:\n'
                                f'  - Category: {result.get("category", "N/A")}\n'
                                f'  - Result: {result.get("result", "N/A")}')
                md_content.append('\n')

        elif query_type == 'ip':
            md_content.append(f'# VirusTotal IP Address Report for {query_value}')
            ip_attr = json_data.get("data", {}).get("attributes", {})
            md_content.append(f'# Threat Intelligence Report\n')
            md_content.append('# IP Address Information')
            md_content.append(f'- **IP Address**: {query_value}')
            md_content.append(f'- **Network**: {ip_attr.get("network", "N/A")}')
            md_content.append(f'- **Country**: {ip_attr.get("country", "N/A")}')
            md_content.append(f'- **Continent**: {ip_attr.get("continent", "N/A")}')
            md_content.append(f'- **ASN**: {ip_attr.get("asn", "N/A")}')
            md_content.append(f'- **AS Owner**: {ip_attr.get("as_owner", "N/A")}')
            md_content.append(f'- **Regional Internet Registry**: {ip_attr.get("regional_internet_registry", "N/A")}')
            md_content.append(f'- **Whois Date**: {ip_attr.get("whois_date", "N/A")}')
            md_content.append('\n')

            # Analysis Summary
            md_content.append('## Analysis Summary')
            md_content.append(f'- **Last Analysis Date**: {ip_attr.get("last_modification_date", "N/A")}')
            md_content.append(f'- **Reputation**: {ip_attr.get("reputation", "N/A")}')
            total_votes = ip_attr.get("total_votes", {})
            md_content.append(f'- **Total Votes**: Harmless {total_votes.get("harmless", 0)}, Malicious {total_votes.get("malicious", 0)}')
            md_content.append('\n')

            # Analysis Statistics
            md_content.append('## Analysis Statistics')
            last_analysis_stats = ip_attr.get("last_analysis_stats", {})
            md_content.append(f'- **Malicious**: {last_analysis_stats.get("malicious", 0)} detections')
            md_content.append(f'- **Suspicious**: {last_analysis_stats.get("suspicious", 0)} detections')
            md_content.append(f'- **Undetected**: {last_analysis_stats.get("undetected", 0)} sources')
            md_content.append(f'- **Harmless**: {last_analysis_stats.get("harmless", 0)} sources')
            md_content.append(f'- **Timeout**: {last_analysis_stats.get("timeout", 0)}')
            md_content.append('\n')

            # WHOIS Information
            md_content.append('# WHOIS Information')
            whois = ip_attr.get("whois", "N/A").replace("\n", "\n  ")
            md_content.append(f'```whois\n{whois}\n```')
            md_content.append('\n')
            md_content.append('-----')
            # Last Analysis Results (Selected Engines)
            md_content.append('# Last Analysis Results (Selected Engines)')
            last_analysis_results = ip_attr.get("last_analysis_results", {})
            engines = ["Acronis", "Antiy-AVL", "AlphaSOC", "Emsisoft", "Fortinet"]
            for engine in engines:
                result = last_analysis_results.get(engine, {})
                md_content.append(f'## {engine}:\n'
                                f'  - Category: {result.get("category", "N/A")}\n'
                                f'  - Result: {result.get("result", "N/A")}')
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
