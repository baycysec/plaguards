# convert JSON to MD file

import json
import pypandoc
from pwn import *

def jsonTomd(json_input, md_output):
    # Load JSON data
    with open(json_input, 'r') as f:
        data = json.load(f)
    
    # convert JSON data to a string
    json_str = json.dumps(data, indent=4)
    
    md_content = pypandoc.convert_text(json_str, 'markdown', format='json')
    
    with open(md_output, 'w') as f:
        f.write(md_content)
        
if __name__ == "__main__":
    # specify the input JSON file and the output MarkDown file
    json_input = 'input.json'
    md_output = 'output.md'
    
    # Convert JSON to MD
    
    jsonTomd(json_input, md_output)
    log.success(f'OPERATION SUCCESS')
    
