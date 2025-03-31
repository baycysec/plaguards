import re
import base64
from urllib.parse import unquote
import ast
import requests
import pypandoc
import os
import string
import random
from datetime import datetime
import time
import sys
import hashlib

def remove_string(code):
    pattern = re.compile(r'\[string\]', re.IGNORECASE)
    newcode = []
    for line in code.strip().splitlines():
        newcoderes = pattern.sub('', line).strip()
        newcode.append(newcoderes)
    return "\n".join(newcode)

def remove_space_from_char(code):
    code = re.compile(r'(\[ChaR\])\s*\(', re.IGNORECASE).sub(r'\1(', code)
    code = re.compile(r'(\[Char\])\s*(\d+)', re.IGNORECASE).sub(r'\1(\2)', code)
    return code

def change_bxor_and_to_chr(code):
    def replace_bxor_and_to_chr(match):
        res = match.group(1)
        changebxor = res.replace('-bxor', '^')
        return f'Chr({changebxor})'
    
    return re.compile(r'\[char\]\(([\d\-+\*/\s()]+(?:\s?-bxor\s?[\d\-+\*/\s()]+)*)\)', re.IGNORECASE).sub(replace_bxor_and_to_chr, code)
                      
 
def convertercode(code):    
    checkcode = code.split('\n')
    newcoderes = []
    for i in checkcode:        
        while True:
            i, count1 = re.subn(r"\s*-replace\s*\(?('[^']+'|\"[^\"]+\"|[\w\s]+)\s*,\s*('[^']+'|\"[^\"]+\"|[\S]+)\)?", r".replace(\1,\2)", i, flags=re.IGNORECASE)
            i,count2 = re.subn(r"\s*-split\s+(['\"][^'\"]+['\"]|[\S]+)",  lambda m: f".split({m.group(1)})", i, flags=re.IGNORECASE)
            i,count3 = re.subn(r'((?:\$\w+\s*=\s*)*)(.+?)\s+-join\s+("[^"]+"|\'[^\']+\'|\S+)',lambda m: f"{m.group(3)}.join([{m.group(2)}]) " if not m.group(1) else f"{m.group(1)} {m.group(3)}.join([{m.group(2)}]) ",i,flags=re.IGNORECASE)        
            if count1 == 0 and count2 == 0 and count3 == 0:
                break
        newcoderes.append(i)

    newcode = ''.join([i + '\n' for i in newcoderes])
    return newcode.strip()

def removequote(code):
    def quoteremover(match):
        if ".replace(" in match.group(0).lower() or ".split(" in match.group(0).lower() or "-split" in match.group(0) or "-replace" in match.group(0) or match.group(0) == '" "' or match.group(0) == "' '":
            return match.group(0)
        else:
            return match.group(0).strip("'\"")
        
    checkcode = code.split('\n')
    newcoderes = []
    for i in checkcode:
        i = re.sub(r"(\(?'[^']*'\)?\.replace\([^)]+\))|(\(?\"[^\"]*\"\)?\.replace\([^)]+\))|(\'[^\']*\'\.split\([^)]+\))|(\"[^\"]*\"\.split\([^)]+\))|(\s*-replace\s*\(?('[^']+'|\"[^\"]+\")\s*,\s*('[^']+'|\"[^\"]+\")\)?)|((\(?(['\"].+['\"])+)\)?\s+-split\s+('[^']+'|\"[^\"]+\"))|('[^']*'|\"[^\"]*\")", quoteremover, i, flags=re.IGNORECASE)
        newcoderes.append(i)
    newcode = ''.join([i + '\n' for i in newcoderes])
    return newcode.strip()


def decode_chr(expr):
    expr = re.sub(r'-\s*-', '+', expr)
    numbers = list(map(int, re.findall(r'-?\d+', expr)))
    symbol = re.compile(r'\d+\s*(\^|\+|\-|\/|\*{1,2}|\%|\^)', re.IGNORECASE).findall(expr)

    for i in range(len(numbers)):
        if i != 0 and numbers[i] < 0:
            numbers[i] = abs(numbers[i])

    numlist = []
    oprlist = []

    def operator(opr, a, b):
        if opr == '+': return a + b
        elif opr == '-': return a - b
        elif opr == '*': return a * b
        elif opr == '/': return a // b
        elif opr == '%': return a % b
        elif opr == '^': return a ^ b
        elif opr == '**': return a ** b
    
    precedence = {'+': 1, '-': 1, '*': 2, '/': 2, '%': 2, '^': 2, '**': 2}
    for number, symbol in zip(numbers[:-1], symbol):
        numlist.append(number)
        while oprlist and (precedence[symbol] <= precedence[oprlist[-1]]):
            b = numlist.pop()
            a = numlist.pop()
            op = oprlist.pop()
            numlist.append(operator(op, a, b))
        oprlist.append(symbol)
    numlist.append(numbers[-1])

    while len(numlist) > 1:
        b = numlist.pop()
        a = numlist.pop()
        op = oprlist.pop()
        numlist.append(operator(op, a, b))

    return chr(numlist[0])

def validate_input(input_string):
    input_string = input_string.strip()
    while re.search(r'(\w)\s*\+\s*(\w)', input_string):
        input_string = re.sub(r'(\w)\s*\+\s*(\w)', r'\1\2', input_string)
    input_string = re.sub(r'\s*\+\s*', '', input_string)
    return input_string

def check_concat_plus(symbol):
    chr_pattern = re.compile(r'chr\([^()]*\)', re.IGNORECASE)
    chr_substrings = chr_pattern.findall(symbol)
    temp_string = chr_pattern.sub("temp", symbol)
    
    temp_string = validate_input(temp_string)
    
    for chr_substring in chr_substrings:
        temp_string = temp_string.replace("temp", chr_substring, 1)
    return ' ' + temp_string


def concat_code(code):
    concatregex = re.compile(r'(Chr\([^()]*\))(\s*\+\s*(Chr\([^()]*\)))*', re.IGNORECASE)
    
    matches = concatregex.finditer(code)
    results = []
    for match in matches:
        results.append(match.group(1))
        remaining_text = match.group(0)[len(match.group(1)):].strip()
        while remaining_text:
            chr_match_after_plus = re.match(r'\s*\+\s*(Chr\([^()]*\))', remaining_text, re.IGNORECASE)
            if chr_match_after_plus:
                results.append(chr_match_after_plus.group(1))
                remaining_text = remaining_text[chr_match_after_plus.end():].strip()
            else:
                break
    gabungin = [decode_chr(result) for result in results]
    splitslashn = [splitslash for splitslash in code.strip().splitlines()]
    check = []
    for i in splitslashn:
        check.append(i + '\n')
    newcoderes = []
    for i in range(len(check)):
        check[i] = check[i]
        if "+=" in check[i]:
            parts = [part.lstrip(' ') for part in check[i].split('+=')]
            if "+" in parts[1] and not re.search(r'\$\w+', parts[1]):
                newparts = check_concat_plus(parts[1])
            else:
                newparts = parts[1]
            check[i] = parts[0] + "+=" + ' ' + newparts + "\n"
            newcoderes.append(check[i])
        elif "=" in check[i]:
            valid = 0
            parts = [part.lstrip(' ') for part in check[i].split('=')]  
            for j in range(len(parts)):
                if "+" in parts[j] and (re.search(r'\$\w+', parts[j]) or "++" in parts[j].replace("'","").replace('"','')):
                    newcoderes.append(check[i])
                    valid = 1
                    break
            if valid == 0:
                pluscount = 0
                res = ''
                for i in range(len(parts)):
                    if '+' in parts[i]:
                        newparts = check_concat_plus(parts[i])
                        pluscount = 1
                    else:
                        newparts = parts[i]
                    if pluscount == 0 and i == len(parts) - 1:
                        res += ' '
                    if i == len(parts) - 1:
                        res += newparts + '\n'
                    else:
                        res += newparts + '='
                newcoderes.append(res)
        else:
            if '+' in check[i]:
                check[i] = check_concat_plus(check[i])
            if '\n' not in check[i]:
                check[i] += '\n'
            newcoderes.append(check[i])
    newcode = ''.join([i for i in newcoderes])
    for i, element in enumerate(gabungin):
        if len(element) == 1:
            newcode = newcode.replace(results[i], element)
    return newcode


def backtick(code):
    backtick_dict = {
        '`b': '\b',
        '`f': '\f',
        '`n': '\n',
        '`r': '\r',
        '`t': '\t',
        '`v': '\v'
    }
    checkcode = code.split('\n')
    for i in range(len(checkcode)):
        for backtick, backtickvalue in backtick_dict.items():
            if backtick in checkcode[i]:
                checkcode[i] = checkcode[i].replace(backtick,backtickvalue)
        if not checkcode[i].endswith('\n'):
            checkcode[i] += '\n'
    newcode = ''.join([i for i in checkcode])
    return newcode.strip()


def combine_and_concat_multiple_variables_value(code):
    value_dict = {}
    notvariablevalue = []
    equalmorethan1pattern = r'={2,}'
    plusequalcount = {}
    
    def replace_equal_more_than_1(match):
        return '%3D' * len(match.group(0))
    
    checkcode = [check for check in code.splitlines() if check != '']

    for i in range(len(checkcode)):
        checkcode[i] = re.sub(equalmorethan1pattern, replace_equal_more_than_1, checkcode[i])
        if "++=" in checkcode[i]:
            checkcode[i] = checkcode[i].replace('++=', '+=')
        if "+=" in checkcode[i]:
            parts = checkcode[i].split('+=')
            var = parts[0].strip().replace('(','').replace(')', '').replace('"','').replace("'", "")
            value = parts[1].strip()
            if not var.startswith("$"):
                var = "$" + var
            plusequalcount[var] = 0
            if re.search(r'\$\w+', value_dict.get(var, "")) and plusequalcount[var] != 1:
                value_dict[var] = value_dict.get(var, "") + "+" + value
                plusequalcount[var] = 1
            else:
                value_dict[var] = value_dict.get(var, "") + value
        
        elif "=" in checkcode[i] and "!=" not in checkcode[i]:
            split_equal = checkcode[i].split('=')
            for i in range(len(split_equal)-1, 0, -1):
                var = split_equal[i-1].strip().split()[-1].replace('(','').replace(')', '').replace('"','').replace("'", "")
                if not var.startswith("$"):
                    var = "$" + var
                value = split_equal[i].strip().split('=')[0].strip()
                value_dict[var] = value
        else:
            notvariablevalue.append(checkcode[i])
            
    for var, value in list(value_dict.items()):
        if value in value_dict:
            initialvalue = value
            value = value_dict[value]
            value_dict[initialvalue] = value

    for var, value in value_dict.items():
        newvaluetemp = ""
        for match in re.split(r'(\$?\w+)', value):
            if match in value_dict:
                newvaluetemp += value_dict[match]
            else:
                newvaluetemp += match
        value_dict[var] = newvaluetemp

    reverse_value_dict = {}
    for var, value in value_dict.items():
        if value in reverse_value_dict:
            reverse_value_dict[value].append(var)
        else:
            reverse_value_dict[value] = [var]

    codetemp = []
    for value, vars in reverse_value_dict.items():
        if len(vars) > 1:
            codetemp.append(" = ".join(vars) + f" = {value}")
        else:
            codetemp.append(f"{vars[0]} = {value}")
    newcodetemp = []
    j,k = 0, 0
    for i in range(len(checkcode)):
        if k != len(notvariablevalue) and checkcode[i] == notvariablevalue[k]:
            newcodetemp.append(notvariablevalue[k])
            k += 1
        elif j != len(codetemp):
            newcodetemp.append(codetemp[j])
            j += 1
        elif j == len(codetemp):
            if k == len(notvariablevalue):
                break
            newcodetemp.append(notvariablevalue[k])
            k += 1

    variables = {}
    for line in newcodetemp:
        match = re.match(r'^(\$\w+(?:\s*=\s*\$\w+)*\s*)=\s*(.+)', line)
        if match:
            value = match.group(2).strip()
            vars = [v.strip() for v in match.group(1).split('=')]
            prev_var = value
            for var in vars:
                variables[var] = prev_var
                prev_var = var

    def replace_var(match):
        var = match.group(0)
        while var in variables:
            var = variables[var]
        return var
    
    newcode = []
    for line in newcodetemp:
        if not '=' in line.strip():
            line = re.sub(r'\$\w+', replace_var, line)
        newcode.append(line)

    newcodewithslashn = []
    for i in newcode:
        newcodewithslashn.append(i + '\n')
    newcoderes = []
    for i in newcodewithslashn:
        parts = i.split('=')
        res = ''
        for j in parts:
            if '+' in j:
                check = check_concat_plus(j)
                if parts.index(j) == len(parts) - 1:
                    check += '\n'
            else:
                check = j
            res += check
            if "\n" not in j:
                res += "="
        newcoderes.append(res)
    newcoderes[-1] = newcoderes[-1].strip('\n')
    newcode = ''.join([i for i in newcoderes])
    return newcode


def fixingcodequote(code):
    checkcode = code.split('\n')
    newcoderes = []
    for i in checkcode:
        match1 = re.search(r'(?:\$\w+\s*=\s*)*(.*?)(?=\.replace\([^,]+,[^)]+\))', i, flags=re.IGNORECASE)
        match2 = re.search(r'(?:\$\w+\s*=\s*)*(.*?)(?=\.split\([^)]+\))', i, flags=re.IGNORECASE)
        match3 = re.search(r'([\'\"]\s*[\'\"]|\S+)\.join\(\[(.*?)\]\)', i, flags=re.IGNORECASE)
        if match1 or match2 or match3:
            if match1:
                val = match1.group(1)
            elif match2:
                val = match2.group(1)
            elif match3:
                val = match3.group(1)
                val2 = match3.group(2).split(',')
                addquote = [f'"{valuearr.strip()}"' if not valuearr.strip().startswith(('"', "'")) else valuearr.strip() for valuearr in val2]
                withquoteres = f"{val}.join([{', '.join(addquote)}])"
                i = re.sub(r'\S+\.join\(\[.*?\]\)', withquoteres, i)

            if re.match(r"^\.+$",val):
                i = re.sub(r'(\.+)(?=\.join\(\[.*?\]\))', r"'\1'", i, flags=re.IGNORECASE)        
            elif not val.startswith("(") and val.count('"') != 2 and val.count("'") != 2:
                if '"' in val:
                    i = i.replace(val, "'" + val + "'")
                else:
                    i = i.replace(val, '"' + val + '"')
            elif not ((val.startswith("'") and val.endswith("'")) or (val.startswith('"') and val.endswith('"'))):
                if "'" in val:
                    i = i.replace(val, '"' + val + '"')
                else:
                    i = i.replace(val, "'" + val + "'")
        newcoderes.append(i)

    newcode = ''.join([i + '\n' for i in newcoderes])
    return newcode.strip()


def decoding(code):
    checkcode = code.split('\n')
    newcoderes = []

    for i in checkcode:
        if i == '':
            continue

        while 1:
            match_from_base64 = re.search(r'[^\s]*fromBase64String\(([^)]+)\)', i, re.IGNORECASE)
            matchb64 = re.search(r'(?i)([A-Za-z0-9]+%3D%3D)', i)

            if match_from_base64:
                try:
                    newmatch = match_from_base64.group(1).replace('"','').replace("'", "").replace("(", "").replace(")","")

                    if newmatch.endswith('%3D%3D'):
                        content = newmatch.replace('%3D%3D', '==')
                    else:
                        content = newmatch + '=='
                    get_decode = base64.b64decode(content)
                    get_clean = get_decode.replace(b'\x00', b'')

                    decoded_str = get_clean.decode("utf-8", errors="ignore")

                    decoded_line = i.replace(match_from_base64.group(0), decoded_str)
                    i = decoded_line

                except Exception as e:
                    print(f'Error during decoding: {e}')
                    newcoderes.append(i)
                    break

            elif matchb64:
                try:
                    encoded = unquote(matchb64.group(0).replace('%3D%3D', '=='))
                    decoded = base64.b64decode(encoded)

                    decoded_clean = re.sub(b'\x00', b'', decoded)

                    decoded_str = decoded_clean.decode("utf-8", errors="ignore")

                    decoded_line = i.replace(matchb64.group(0), decoded_str)
                    i = decoded_line

                except Exception as e:
                    print(f'Error during URL-encoded Base64 decoding: {e}')
                    newcoderes.append(i)
                    break
            else:
                newcoderes.append(i)
                break

    newcode = ''.join([i + '\n' for i in newcoderes])
    return newcode.strip()

def replacecode(code):
    def replace_func(match):
        if len(match.groups()) == 4:
            stringmatch1,stringmatch2,oldword,newword = match.groups()
            if stringmatch1:
                if not oldword in stringmatch1 and oldword.replace("(","").replace(")","") in stringmatch1:
                    return '"' + stringmatch1.replace(oldword.replace("'","").replace('"',"").replace("(","").replace(")",""), newword.replace("'","").replace('"',"").replace("(","").replace(")","")) + '"'
                
                return '"' + stringmatch1.replace(oldword.replace("'","").replace('"',""), newword.replace("'","").replace('"',"")) + '"'
            elif stringmatch2:
                if not oldword in stringmatch2 and oldword.replace("(","").replace(")","") in stringmatch2:
                    return '"' + stringmatch2.replace(oldword.replace("'","").replace('"',"").replace("(","").replace(")",""), newword.replace("'","").replace('"',"").replace("(","").replace(")","")) + '"'
                return "'" + stringmatch2.replace(oldword.replace("'","").replace('"',""), newword.replace("'","").replace('"',"")) + "'"
            
        elif len(match.groups()) == 3:
            stringmatch,oldword,newword = match.groups()
            return "'" + stringmatch.replace(oldword.replace("'","").replace('"',""), newword.replace("'","").replace('"',"")) + "'"
    
    checkcode = code.split('\n')
    for i in range(len(checkcode)):
        while True:
            newcode, count = re.subn(r'\(["\']([^"\']*)["\']\)\.replace\(([^,]+),([^)]+)\)', replace_func, checkcode[i], flags=re.IGNORECASE)
            if count == 0:
                break
            checkcode[i] = newcode

        while True:
            newcode, count = re.subn(r'(?:"([^"]+)"|\'([^\']+)\')\.replace\(([^,]+),([^)]+)\)', replace_func, checkcode[i], flags=re.IGNORECASE)
            if count == 0:
                break
            checkcode[i] = newcode

    newcode = ''.join([i + '\n' for i in checkcode])
    return newcode.strip()

def joincode(code):
    def join_func(match):
        separator, array = match.groups()
        separator = separator.replace("'","").replace('"',"")
        return separator.join(ast.literal_eval(array))

    checkcode = code.split('\n')
    newcoderes = []
    for i in checkcode:
        while True:
            i,count = re.subn(r'(\'[^\']*\'|"[^"]*")\.join\((\[[^\]]+\])\)',join_func, i, flags=re.IGNORECASE)
            if count == 0:
                break
        newcoderes.append(i)

    newcode = ''.join([i + '\n' for i in newcoderes])
    return newcode.strip()

def splitcode(code):
    def split_func(match):
        string,objtosplit = match.groups()
        listsplit = string.split(objtosplit.replace("'","").replace('"',''))
        res = ', '.join(f'{valuearr}' for valuearr in listsplit)
        return res

    checkcode = code.split('\n')
    for i in range(len(checkcode)):
        while True:
            checkcode[i],count = re.subn(r'(["\'][^"\']*["\'])\.split\(([^)]+)\)', split_func, checkcode[i], flags=re.IGNORECASE)
            if checkcode[i].count('(') != checkcode[i].count(')'):
                checkcode[i] = checkcode[i].replace("(","").replace(")","")
            if count == 0:
                break

    newcode = ''.join([i + '\n' for i in checkcode])
    return newcode.strip().replace("'","").replace('"', "")

def http_and_ip_grep(code):    
    httplist = re.findall(r'https?://(?!\d+\.\d+\.\d+\.\d+)([^\s/]+)', code, re.IGNORECASE)
    iplist = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', code)
    
    return list(set(httplist)), list(set(iplist))

def deobfuscate(code):
    try:
        code = remove_string(code)
        code = remove_space_from_char(code)
        code = change_bxor_and_to_chr(code)
        codetemp = []
        checkcode = code.split('\n')
        for i in range(len(checkcode)):
            checkcode[i] += "\n"
            checkcode[i] = re.sub(r'\)\s*\(', ');(', checkcode[i])
            if ';' in checkcode[i]:
                parts = [part.lstrip(' ') for part in checkcode[i].split(';')]
                if parts[-1] == '\n':
                    parts = parts[:-1]
                if len(parts) == 1:
                    codetemp.append(parts[0] + '\n')
                    continue
                for j in parts:
                    if parts.index(j) == len(parts) - 1:
                        codetemp.append(j)
                    else:
                        codetemp.append(j + '\n')
            else:
                codetemp.append(checkcode[i])
                        
        code = ''.join([i if i != codetemp[-1] else i.rstrip('\n') for i in codetemp])
        code = concat_code(code)
        code = removequote(code)
        code = backtick(code)
        code = combine_and_concat_multiple_variables_value(code)
        code = convertercode(code)
        code = fixingcodequote(code)
        code = decoding(code)
        code = joincode(code)
        code = replacecode(code)
        code = splitcode(code)
        httplist,iplist = http_and_ip_grep(code)
    except Exception as e:
        code = f"Something's wrong with the code or input!"
        return code,[],[]
    return code,httplist,iplist

def checktimefile():
    for filename in os.listdir('media'):
        timenow = time.time()

        file_path = os.path.join('media', filename)
        
        if os.path.isfile(file_path):
            file_creation_time = os.path.getctime(file_path)
            
            if timenow - file_creation_time > 300:
                os.remove(file_path)
                
    for filename in os.listdir('results'):
        timenow = time.time()

        file_path = os.path.join('results', filename)
        
        if os.path.isfile(file_path):
            file_creation_time = os.path.getctime(file_path)
            
            if timenow - file_creation_time > 300 and filename.endswith('.md'):
                os.remove(file_path)  

def generate_random_val(length):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

VT_API_KEY = "INSERT_YOUR_VT_API_KEY_HERE"

def FindQuery(query_type, query_value):
    if query_type == 'domain':
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

    else:
        raise ValueError("Unsupported query type. Use 'domain', or 'ip'.")

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
        return f"Error"

def get_integrity(file_path):
    sha256sum = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256sum.update(byte_block)
    
    checksum = sha256sum.hexdigest()
    return checksum

def generate_deobfus_md(powershell, previous_hash=None):
    md_content = []
    code, httplist, ip = deobfuscate(powershell)
    
    checkcode = code.split('\n')
    md_content.append(f'```ps1')
    for line in checkcode:
        md_content.append(f'{line}')
    md_content.append(f'```')
    md_content.append(f'\n')

    md_path = 'plaguards-cli-results/deob_result.md'
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

    md_path2 = 'plaguards-cli-results/deob_result2.md'
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
        return generate_deobfus_md(code2, previous_hash=checksum_2)


def deobfuscate_and_generate_report(queryinput, search=False, code=None):
    md_content = []

    deobf_code, httplist, ip = generate_deobfus_md(code)
    timestamp = datetime.now().strftime('%Y-%m-%d')
    header = [
        '---',
        'title: ""',
        'author: "DEOBFUS REPORT"',
        f'date: {timestamp}',
        'titlepage: true',
        # 'title-page-color: "FFFFFF"',  # commented out if not used
        'titlepage-rule-color: "FFFFFF"',
        'titlepage-text-color: "FFFFFF"',
        'page-background: "results/background.png"',
        'toc: true',
        'toc-own-page: true',
        'titlepage-background: "results/deobfus-bg.pdf"',
        '...',
        '\n',
        '# Deobfuscated Code\n'
    ]
    md_content = header + deobf_code
    

    for i in range(len(queryinput)):
        args = queryinput[i].split()

        query_type = args[0]
        query_value = args[1]

        if query_type not in ['domain', 'ip']:
            return "Error: Invalid query type. Use 'domain', or 'ip'."

        json_data = FindQuery(query_type, query_value)

        if not json_data and search:
            return "No data returned from the API."
        elif not json_data and search == False:
            md_content.append(f'# VirusTotal Report for {query_value}\n')
            md_content.append(f'No Information Found')
            md_content.append('\n')
            continue

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

            md_content.append('-----\n')

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

            md_content.append('\n')

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
                
    
    randomval = generate_random_val(150)
    md_file_path = os.path.join(f'plaguards-cli-results/checker_{randomval}.md')
    with open(md_file_path, 'w') as md_file:
        md_file.write('\n'.join(md_content))

    path = os.path.join('media')
    res = md_to_pdf(md_file_path, path, randomval)
    
    if "Error" in res:
    	return "Error during PDF conversion"
    	
    output_pdf_path = os.path.join(f'media/checker_result_{randomval}.pdf')
    
    return output_pdf_path

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 plaguards-cli.py [obfuscated.ps1] OR python3 plaguards-cli.py [obfuscated.txt]")
        sys.exit(1)

    ps1_file = sys.argv[1]
    
    if not os.path.isfile(ps1_file):
        print(f"\033[1;31m[!] Error: File '{ps1_file}' not found.\033[0m")
        sys.exit(1)

    if not (ps1_file.lower().endswith('.ps1') or ps1_file.lower().endswith('.txt')):
        print("\033[1;31m[!] Error: Invalid file type. Only .ps1 and .txt are supported.\033[0m")
        sys.exit(1)

    with open(ps1_file, 'r') as f:
        ps_code = f.read()

    print("\033[1;36m[#] Plaguards is deobfuscating", end="", flush=True)
    for _ in range(3):
        time.sleep(0.8)
        print(".", end="", flush=True)
    print("\n")
    print("\033[1;33m[+] Please kindly wait..\033[0m")
    time.sleep(0.5)

    deobf_code, domains, ips = deobfuscate(ps_code)
    queryinput = []
    for domain in domains:
        queryinput.append(f'domain {domain}')
    for ip in ips:
        queryinput.append(f'ip {ip}')

    # Run deobfuscation + VT queries + generate PDF
    pdf_path = deobfuscate_and_generate_report(queryinput, search=False, code=ps_code)

    if "Error" in pdf_path:
        print("\033[1;31m[!] PDF generation failed.\033[0m")
    else:
        print(f"\033[1;92m[#] Deobfuscation complete. Report saved to: {pdf_path}\033[0m")


if __name__ == "__main__":
    main()

