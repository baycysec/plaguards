import re
import base64
from urllib.parse import unquote

chrregex = re.compile(r'Chr\(([-]?\d+)(\s+(\^|\+|\-|\/|\*|\%)\s+(\d+))*\)', re.IGNORECASE)
stringregex = re.compile(r'(".*?"|\'.*?.\')')

concatregex = re.compile(r'({chr}|{string})(\s*\+\s*({chr}|{string}))*'.format(chr=chrregex.pattern, string=stringregex.pattern))

def remove_spaces_bracket(match):
    return f"[Char]({match.group(1)}{match.group(2)}{match.group(3)})"

def remove_string(code):
    pattern = re.compile(r'\[string\]', re.IGNORECASE)
    newcode = []
    for line in code.strip().splitlines():
        newcoderes = pattern.sub('', line).strip()
        newcode.append(newcoderes)
    return "\n".join(newcode)

def char_intended(code):
    code = re.compile(r'\[Char\]\s+\(([-\d\+\*/\^]+)\)', re.IGNORECASE).sub(r'[Char](\1)', code)
    resultnumber = re.compile(r'\[Char\]\s+(\d+)', re.IGNORECASE).sub(r'[Char]\1', code)
    resultexpr = re.compile(r'\[Char\]\s*\(\s*(-?\d+)\s*([+\-*/])\s*(-?\d+)\s*\)', re.IGNORECASE).sub(remove_spaces_bracket, resultnumber)
    resultbxor = re.compile(r'\s*(-?\d+)\s*-\s*bxor\s*(-?\d+)\s*', re.IGNORECASE).sub(r'\1 -bxor \2', resultexpr)
    resultplus = re.compile(r'(\[Char\]\(\d+[+\-*/]\d+\))\s*\+\s*', re.IGNORECASE).sub(r'\1 + ', resultbxor)
    final_result = re.compile(r'(\[Char\]\([^\)]+\))\s*\+\s*(\[Char\]\([^\)]+\))', re.IGNORECASE).sub(r'\1 + \2', resultplus)
    return final_result

def replace_match(match):
    res = match.group(1)
    matchsymbol = re.sub(r'(?<=\d)([\+\*/\^])(?=\d)', r' \1 ', res)
    minussymbol = re.sub(r'(?<=\d)-(?=\d)', r' - ', matchsymbol)
    changebxor = minussymbol.replace('-bxor', '^')
    final_result = re.sub(r'^\((.*)\)$', r'\1', changebxor)
    return f'Chr({final_result})'

def char_transform(code):
    return re.compile(r'\[char\]\(([-\d\+\*/\^\s]+(?:\s?-bxor\s?[-\d\+\*/\^\s]+)?)\)|\[Char\]([-0-9]+)', re.IGNORECASE).sub(replace_match, code)

 
def decode_chr(expr):
    numbers = list(map(int, re.findall(r'-?\d+', expr)))
    simbol = re.compile(r'[-]?\d+\s*(\^|\+|\-|\/|\*|\%|\^)', re.IGNORECASE).findall(expr)
    result = numbers[0]
    for i in range(len(simbol)):
        if simbol[i] == '+':
            result += numbers[i+1]
        elif simbol[i] == '-':
            result -= numbers[i+1]
        elif simbol[i] == '*':
            result *= numbers[i+1]
        elif simbol[i] == '/':
            result //= numbers[i+1]
        elif simbol[i] == '%':
            result %= numbers[i+1]
        elif simbol[i] == '^':
            result ^= numbers[i+1]
    return chr(result)

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
    concatregex = re.compile(r'(Chr\([^()]*\)|".*?")(\s*\+\s*(Chr\([^()]*\)|".*?"))*', re.IGNORECASE)
    
    matches = concatregex.finditer(code)
    results = []
    for match in matches:
        results.append(match.group(1))
        remaining_text = match.group(0)[len(match.group(1)):].strip()
        while remaining_text:
            next_match = re.match(r'\s*\+\s*(Chr\([^()]*\)|".*?")', remaining_text, re.IGNORECASE)
            if next_match:
                results.append(next_match.group(1))
                remaining_text = remaining_text[next_match.end():].strip()
            else:
                break
    gabungin = [decode_chr(result) if result.startswith('Chr') else result.strip('"') for result in results]
    splitslashn = [splitslash for splitslash in code.strip().splitlines()]
    check = []
    for i in splitslashn:
        check.append(i + '\n')
    newcoderes = []
    for i in range(len(check)):
        check[i] = check[i].replace('"', "").replace("'", "")
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
                if "+" in parts[j] and re.search(r'\$\w+', parts[j]):
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
            newcoderes.append(check[i])
    newcode = ''.join([i for i in newcoderes])
    for i, element in enumerate(gabungin):
        if len(element) == 1:
            newcode = newcode.replace(results[i], element)
    return newcode.replace("(", "").replace(")", "")


def Replace(code):
    pattern = re.compile(r'Replace(\w+),([!@#$%^&*\w]+)', re.IGNORECASE)
    def replacer(match):
        return match.group(2)
    newcode = pattern.sub(replacer, code)
    splitslashn = [splitslash for splitslash in newcode.strip().splitlines()]
    newcoderes = []
    for i in range(len(splitslashn)):
        if "+=" in splitslashn[i]:
            newcoderes.append(re.sub(r'(\w)\+=\s*(\w)', r'\1 += \2', splitslashn[i]).strip())
        elif "=" in splitslashn[i]:
            newcoderes.append(re.sub(r'(?<!\s)=(?!\s)', ' = ', splitslashn[i]).strip())
        else:
            newcoderes.append(splitslashn[i].strip())
    newcode = ''.join([i + '\n' for i in newcoderes])
    return newcode.strip()


def decoding(code):
    match = re.search(r'(?i)B64_decode_([A-Za-z0-9%_=]+)', code)
    if match:
        try:
            encoded = unquote(match.group(1))
            decoded = base64.b64decode(encoded).decode()
            code = code.replace(match.group(0), decoded)
        except:
            return code
    return code

def replace_multiple_variables_and_extra_concat(code):
    append_pattern = r'(\$\w+)\s*\+=\s*(.+)'
    
    value_dict = {}
    for line in code.splitlines():
        if "+=" in line:
            append_match = re.match(append_pattern, line)
            if append_match:
                var, value = append_match.groups()
                value_dict[var] = value_dict.get(var, "") + value.strip()
        else:
            assignments = line.split('=')
            for i in range(len(assignments)-1, 0, -1):
                var = assignments[i-1].strip().split()[-1]
                value = assignments[i].strip().split('=')[0].strip()
                value_dict[var] = value

    for var, value in list(value_dict.items()):
        chain = []
        while value in value_dict and value not in chain:
            chain.append(value)
            value = value_dict[value]
        for v in chain:
            value_dict[v] = value
        value_dict[var] = value

    for var, value in value_dict.items():
        concat = ""
        for token in re.split(r'(\$?\w+)', value):
            if token in value_dict:
                concat += value_dict[token]
            else:
                concat += token
        value_dict[var] = concat

    reverse_dict = {}
    for var, value in value_dict.items():
        if value in reverse_dict:
            reverse_dict[value].append(var)
        else:
            reverse_dict[value] = [var]

    newcode = []
    for value, vars in reverse_dict.items():
        if len(vars) > 1:
            newcode.append(" = ".join(vars) + f" = {value}")
        else:
            newcode.append(f"{vars[0]} = {value}")

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
    newcode = ''.join([i for i in newcoderes])
    return newcode

def replace_multiple_variables2(code):
    lines = code.split('\n')
    variables = {}
    for line in lines:
        match = re.match(r'^(\$\w+(?:\s*=\s*\$\w+)*\s*)=\s*(.+)', line)
        if match:
            value = match.group(2).strip()
            var_chain = reversed([v.strip() for v in match.group(1).split('=')])
            prev_var = value
            for var in var_chain:
                variables[var] = prev_var
                prev_var = var
    
    def replace_var(match):
        var = match.group(0)
        while var in variables:
            var = variables[var]
        return var
    
    newcode = []
    for line in lines:
        if not line.strip().startswith('$'):
            line = re.sub(r'\$\w+', replace_var, line)
        newcode.append(line)
    
    return '\n'.join(newcode)


def deobfuscate(code):
    try:
        code = remove_string(code)
        code = char_intended(code)
        code = char_transform(code)
        codetemp = []
        checkcode = code.split('\n')
        for i in range(len(checkcode)):
            checkcode[i] += "\n"
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
        code = Replace(code)
        codetobecheckedonly = []
        notvariablevalue = []
        checkcode = code.split('\n')
        checkcode = [check for check in checkcode if check != '']
        codetemp2 = [i + '\n' if i != checkcode[-1] else i for i in checkcode]
        for j in range(len(codetemp2)):
            if re.match(r'\$\w+\s*[\+=]+\s*.+', codetemp2[j]):
                codetobecheckedonly.append(codetemp2[j])
            else:
                notvariablevalue.append(j)
        code = ''.join([i for i in codetobecheckedonly])
        code = replace_multiple_variables_and_extra_concat(code)
        checkcode = code.split('\n')
        checkcode = [check for check in checkcode if check != '']
        codetemp3 = []
        j = 0
        for i in range(len(codetemp2)):
            if i in notvariablevalue:
                codetemp3.append(codetemp2[i])
                continue
            elif j != len(checkcode):
                checkcode[j] += "\n"
                codetemp3.append(checkcode[j])
                j += 1
                continue
            if j == len(checkcode):
                for k in range(i, len(codetemp2)):
                    if k in notvariablevalue:
                        codetemp3.append(codetemp2[k])
                break

        code = ''.join([i if i != codetemp3[-1] else i.rstrip('\n') for i in codetemp3])
        code = decoding(code)
        code = replace_multiple_variables2(code)
        reverse = input("Want to reverse the code? (y/n): ")
        if reverse.lower() == 'y':
            code = code[::-1]
    except:
        code = "Something's wrong with the code!"
    return code
