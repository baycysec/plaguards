import os
import pypandoc

def md_to_pdf(md_input, pdf_output):
    # Check if the input file exists
    if not os.path.isfile(md_input):
        raise FileNotFoundError(f"The input file {md_input} does not exist.")
    
    # Convert Markdown file to PDF using pdflatex from MiKTeX with enhanced formatting options
    extra_args = [
        '--pdf-engine=pdflatex',
        '--variable=mainfont:CMU Serif',
        '--variable=monofont:CMU Typewriter Text',
        '--variable=geometry:margin=1in',  # Set uniform margin for all sides
        '--highlight-style=pygments',
        '--variable=linestretch:1.25',  # Adjust line spacing for readability
        '--variable=fontfamily:cm',  # Ensure font family is Computer Modern
        '--variable=geometry:a4paper',  # Ensure using A4 paper size for better control
        '--variable=geometry:margin=1in'  # Setting consistent margins
    ]
    pypandoc.convert_file(md_input, 'pdf', outputfile=pdf_output, extra_args=extra_args)
    print(f"Converted {md_input} to {pdf_output}")

if __name__ == "__main__":
    # Specify the input Markdown file and the output PDF file
    md_input = 'C:\SKRIPZI\DEVELOPMENT\using-pandoc\output.md'  # Ensure this path is correct and the file exists
    pdf_output = 'hasil.pdf'
    
    # Convert Markdown to PDF
    md_to_pdf(md_input, pdf_output)
