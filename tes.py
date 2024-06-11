import re

chrregex = re.compile(r'Chr\(([-]?\d+)(\s+(\^|\+|\-|\/|\*|\%)\s+(\d+))*\)', re.IGNORECASE)
stringregex = re.compile(r'(".*?"|\'.*?.\')')

concatregex = re.compile(r'({chr})(\s*\+\s*({chr}))*'.format(chr=chrregex.pattern, string=stringregex.pattern))

def replace_match(match):
    res = match.group(1)
    res_space = re.sub(r'(?<=\d)([\+\-\*/\^])(?=\d)', r' \1 ', res)
    return f'Chr({res_space})'

def char_transform(code):
    return re.compile(r'char\[\]([-\d\+\-\*/\^]+)', re.IGNORECASE).sub(replace_match, code)
    

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
    temp_string = temp_string.replace(" + ", "")
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
            next_match = re.match(r'\s*\+\s*({chr})'.format(chr=chrregex.pattern, string=stringregex.pattern), remaining_text)
            if next_match:
                results.append(next_match.group(1))
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
    code = char_transform(code)
    code = concat_test(code)
    return code

# testing = 'tes = Chr(-11 + 100) + Chr(99 ^ 14) + Chr(109 ^ 4) + Chr(99 ^ 13) = tes2 + Chr(99 ^ 13) + Chr(109 ^ 4)'
testing = 'tes = Char[]-11+100 + ChAr[]99^14 + CHar[]109^4 + ChaR[]99^13 = tes2 + ChaR[]99^13 + CHar[]109^4'
print(deobfuscate(testing))

#TO DO
# Read next line.

