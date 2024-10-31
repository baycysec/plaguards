# Plaguards: Open Source PowerShell Deobfuscation and IOC Detection Engine for Blue Teams.

<p align="center" width="100">

<img src="static/assets/PlaguardsBanner.png">

</p>

[![License](https://img.shields.io/badge/License-AGPLv3-purple.svg?&logo=none)](https://www.gnu.org/licenses/agpl-3.0)
![Powershell-Deobfuscator](https://img.shields.io/badge/Powershell_Deobfuscator-blue)
![Powershell-Deobfuscator](https://img.shields.io/badge/IOC_Checker-red)
![Automated Reporting](https://img.shields.io/badge/Automated_Reporting-white)

<p align="justify">Plaguards is a cutting-edge security tool built to streamline and automate the deobfuscation of obfuscated PowerShell scripts, empowering security teams to rapidly identify Indicators of Compromise (IOCs) and determine whether they represent verified threats (VT) or false positives (FP). Each analysis is documented in a comprehensive PDF report, designed to provide deep insights and actionable intelligence.

As a web app, Plaguards offers users the flexibility to conduct powerful, on-demand analysis from anywhere, at any time, making it invaluable to blue teams tasked with responding to complex malware threats. This innovation not only accelerates workflows but also enhances detection accuracy, positioning Plaguards as a vital asset in proactive threat response.</p>


## Security Warning

**WARNING**: There are known security vulnerabilities within certain versions of Plaguards. Before proceeding, please read through Plaguards [Security Advisories]() for a better understanding of how you might be impacted.

## Main Features

|No.|Main Features|Notes|
|:-:|:------------|:---|
|1. | Powershell Deobfuscation| Plaguards introduces deobfuscation features such as concatenating both strings and variable values, moving a variable's value while concatenating it with a new string or variable, merging variables with identical values, decoding base64, reading backtick functions, splitting a single line into multiple lines (if separated by ";" or "(*)"), flexible variable value changes, performing arithmetic operations within characters to generate a string, executing replace functions, executing split functions, interpreting whitespace consistently (ensuring identical results regardless of whitespace length during arithmetic operations in chars, replace, or split), and extracting domain and IP values found within the provided code.|
|2. | IOC Checker| Plaguards offers five parameters for analyzing Indicators of Compromise (IOCs): `hash`, `ip`, `domain`, `url`, and `signature`. To initiate a query, users select one of these parameters and provide a second argument as the IOC value to be checked. Plaguards then cross-references this value with public threat intelligence sources, including VirusTotal and Malware Bazaar, via API. The resulting JSON data is parsed into a structured Markdown format, which is then converted into a downloadable, viewable PDF report—delivering actionable insights in a professional, easy-to-read format.|
|3. | Automated Reporting in PDF format.| Plaguards provides automated PDF reporting for both PowerShell deobfuscation results and IOC checker outcomes, all formatted in an easy-to-read template for clear and accessible insights.|

## Requirements

- VPN Server (Recommended for Production Server).
- Domain for HTTPS (Recommended for Production Server).
- Docker
- Docker Compose v2
- Python 3.x
- Port 8000

**(No manual installation needed – we’ll handle everything for you!)**

## Deployment and Usage

#### To deploy Plaguards:

1. Clone this repository.

```txt
git clone https://github.com/Bread-Yolk/plaguards.git
cd plaguards-main
```

2. Run the setup script.

```txt
chmod 777 plaguards.sh
sudo ./plaguards.sh
```

3. By default, Plaguards dashboard will listen at port **8000**.


## Demo


https://github.com/user-attachments/assets/68bc5ee4-ae3e-4671-9f91-c776fb874160



https://github.com/user-attachments/assets/4dfbbaea-3d36-47c3-83d1-82551423a67d



## Authors
- [jon-brandy](https://github.com/jon-brandy)
- [LawsonSchwantz](https://github.com/LawsonSchwantz)
- [tkxldk](https://github.com/tkxldk)
