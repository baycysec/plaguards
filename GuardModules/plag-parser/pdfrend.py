import requests
import json
import sys
import pypandoc
import os

'''
pip3 install pypandoc
sudo apt-get install pandoc
sudo apt-get install texlive-full
'''

# Define the API endpoint
url = 'https://mb-api.abuse.ch/api/v1/'

def get_data(query_type, query_value):
    if query_type == 'hash':
        data = {
            'query': 'get_info',
            'hash': query_value,
            'limit': '1'  # Adjust as needed
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
        print(f"Failed to retrieve data. Status code: {response.status_code}")
        return None

def md_to_pdf(md_file, output_pdf):
    try:
        # LaTeX options to set margins and wrap text
        extra_args = [
            "--pdf-engine=xelatex",  # using xelatex for better font handling
            "-V", "geometry:margin=1in",  # Set 1-inch margin on all sides
            "-V", "geometry:top=1in",  # Custom top margin
            "-V", "geometry:left=1in",  # Custom left margin
            "-V", "geometry:right=1in",  # Custom right margin
            "-V", "geometry:bottom=1in"  # Custom bottom margin
        ]
        
        output = pypandoc.convert_file(md_file, 'pdf', outputfile=output_pdf, extra_args=extra_args)
        assert output == ""
        print(f"Successfully converted {md_file} to {output_pdf}")
    except Exception as e:
        print(f"Error occurred: {e}")

def main():
    if len(sys.argv) != 3:
        print("Usage: script.py <query_type> <query_value>")
        print("query_type: 'hash' or 'signature'")
        sys.exit(1)

    query_type = sys.argv[1]
    query_value = sys.argv[2]

    if query_type not in ['hash', 'signature']: # signature --> malware name.
        print("Error: Invalid query type. Use 'hash' or 'signature'.")
        sys.exit(1)

    json_data = get_data(query_type, query_value)

    if json_data:
        md_content = []  # list to hold the Markdown content

        for entry in json_data.get("data", []):
            mw_name = entry.get("signature", "Unknown Malware")
            md_content.append(f'# {mw_name}\n')
            md_content.append(f'- **File Name**: {entry.get("file_name", "N/A")}')
            md_content.append(f'- **SHA256 Hash**: {entry.get("sha256_hash", "N/A")}')
            md_content.append(f'- **File Size**: {entry.get("file_size", "N/A")} bytes')
            md_content.append(f'- **MD5 Hash**: {entry.get("md5_hash", "N/A")}')
            md_content.append(f'- **Imphash**: {entry.get("imphash", "N/A")}')
            
            tags = entry.get("tags", [])
            if isinstance(tags, list):
                tags = ', '.join(tags)
            else:
                tags = "N/A"
            md_content.append(f'- **Tags**: {tags}')

            intelligence = entry.get("intelligence", {})
            clamav_detections = intelligence.get("clamav", [])
            
            if isinstance(clamav_detections, list):
                md_content.append(f'- **ClamAV Detections**: {", ".join(clamav_detections)}')
            else:
                md_content.append('- **ClamAV Detections**: N/A')
            
            md_content.append(f'- **Downloads**: {intelligence.get("downloads", "N/A")}')
            md_content.append(f'- **Uploads**: {intelligence.get("uploads", "N/A")}')
            md_content.append(f'- **Mail Intelligence**: {intelligence.get("mail", "None")}')
            md_content.append('\n')

        markdown_string = '\n'.join(md_content)

        md_file_path = 'malware_data.md'
        with open(md_file_path, 'w') as md_file:
            md_file.write(markdown_string)

        print(f"Markdown content saved to '{md_file_path}'.")

        # Convert the Markdown file to PDF
        output_pdf_path = 'malware_data.pdf'
        md_to_pdf(md_file_path, output_pdf_path)

if __name__ == "__main__":
    main()
