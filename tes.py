import re


REGEX = True


def vba_collapse_long_lines(vba_code):
    if (vba_code is None):
        return ""
    if vba_code[-1] != '\n':
        vba_code += '\n'

    vba_code = vba_code.replace(' _\r\n', ' ')
    vba_code = vba_code.replace(' _\r', ' ')
    vba_code = vba_code.replace(' _\n', ' ')
    return vba_code


if REGEX:

    CHR = re.compile(r'Chr\((\d+)(\s+(Xor|\+|\-|\/|\*|\%)\s+(\d+))*\)', re.IGNORECASE)
    STRING = re.compile(r'(".*?"|\'.*?.\')')

    CONCAT_RUN = re.compile('(?P<entry>{chr}|{string})(\s+[&+]\s+(?P<other>{chr}|{string}))*'.format(chr=CHR.pattern, string=STRING.pattern))


def decode_chr(expr):
    numbers = list(map(int, re.findall(r'-?\d+', expr)))
    simbol = re.findall(r'(Xor|\+|\-|\/|\*|\^|\%)', expr, re.IGNORECASE)
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
        elif simbol[i] == '^' or re.search(r'xor', simbol[i], re.IGNORECASE):
            result ^= numbers[i+1]
    return chr(result)

def check_symbols(symbol):
    chr_pattern = re.compile(r'chr\([^()]*\)', re.IGNORECASE)
    chr_substrings = chr_pattern.findall(symbol)
    temp_string = chr_pattern.sub("temp", symbol)
    temp_string = temp_string.replace(" & ", "").replace(" + ", "")
    for chr_substring in chr_substrings:
        temp_string = temp_string.replace("temp", chr_substring, 1)
    
    return temp_string

def _replace_concat_runs(code):
    matches = CONCAT_RUN.finditer(code)
    results = []
    for match in matches:
        results.append(match.group('entry'))
        remaining_text = match.group(0)[len(match.group('entry')):].strip()
        while remaining_text:
            next_match = re.match(r'\s*[&+]\s*(?P<entry>{chr}|{string})'.format(chr=CHR.pattern, string=STRING.pattern), remaining_text)
            if next_match:
                results.append(next_match.group('entry'))
                remaining_text = remaining_text[next_match.end():].strip()
            else:
                break
    gabungin = ''.join([decode_chr(result) if result.startswith('Chr') else result.strip('"') for result in results])
    check = code.split('=')
    newcoderes = []    
    for i in range(len(check)):
        newcoderes.append(check_symbols(check[i]))
        if i != len(check) - 1:
            newcoderes.append('=')
    
    newcode = ''.join([i  for i in newcoderes]).strip('\n')
    code = []
    for i in range(len(results)):
        newcode = newcode.replace(results[i], gabungin[i])
    return newcode


def deobfuscate(code):
    code = vba_collapse_long_lines(code)
    if REGEX:
        # code = _replace_var_runs(code)
        code = _replace_concat_runs(code)
    return code

text = 'tes = Chr(123 Xor 11) + Chr(99 + 14) & Chr(109 Xor 4) & Chr(99 Xor 13) = tes2 + Chr(99 Xor 13) & Chr(109 Xor 4)'
print(deobfuscate(text))
