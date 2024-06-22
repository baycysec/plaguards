import re

# Given string
testing = """
$tes = [Char]        70 + [Char](-11   +   100) + [ChAr](99 -bxor 14) + [CHar](109 -bxor 4) + [ChaR](99 -bxor 13)
$tes2 = [ChaR](99   -  10)+[CHAR](109 -bxor   4)
$tes3 = [ChaR](99 -bxor 13)  +  [CHar](109-bxor   4)
$tes4 = [ChaR](99+13)   +   [CHar](109 -bxor 4)
$tes5 = [ChaR](99   *  10) + [ChaR](99 /  10)
"""

# Patterns to match
pattern_char_number = re.compile(r'\[Char\]\s+(\d+)', re.IGNORECASE)
pattern_char_expression = re.compile(r'\[Char\]\s*\(\s*(-?\d+)\s*([+\-*/])\s*(-?\d+)\s*\)', re.IGNORECASE)
pattern_bxor = re.compile(r'\s*(-?\d+)\s*-\s*bxor\s*(-?\d+)\s*', re.IGNORECASE)
pattern_plus = re.compile(r'(\[Char\]\(\d+[+\-*/]\d+\))\s*\+\s*', re.IGNORECASE)

# Function to remove spaces inside Char elements
def remove_spaces_inside(match):
    return f"[Char]({match.group(1)}{match.group(2)}{match.group(3)})"


# Replace matches with the correct format
result = pattern_char_number.sub(r'[Char]\1', testing)
result = pattern_char_expression.sub(remove_spaces_inside, result)
result = pattern_bxor.sub(r'\1 -bxor \2', result)
result = pattern_plus.sub(r'\1 + ', result)


# Universal adjustment for all occurrences
pattern_adjust = re.compile(r'(\[Char\]\([^\)]+\))\s*\+\s*(\[Char\]\([^\)]+\))', re.IGNORECASE)
result = pattern_adjust.sub(r'\1 + \2', result)

print(result)

