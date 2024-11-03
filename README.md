# Plaguards: Open Source PowerShell Deobfuscation and IOC Detection Engine for Blue Teams.

<p align="center" width="100">

<img src="static/assets/PlaguardsBanner.png">

</p>

[![License](https://img.shields.io/badge/License-AGPLv3-purple.svg?&logo=none)](https://www.gnu.org/licenses/agpl-3.0)
![Powershell-Deobfuscator](https://img.shields.io/badge/Powershell_Deobfuscator-blue)
![Powershell-Deobfuscator](https://img.shields.io/badge/IOC_Checker-red)
![Automated Reporting](https://img.shields.io/badge/Automated_Reporting-white)

<p align="justify">Plaguards is a cutting-edge security tool built to streamline and automate the deobfuscation of obfuscated PowerShell scripts, empowering security teams to rapidly identify Indicators of Compromise (IOCs) and determine whether they represent valid threats (VT) or false positives (FP). Each analysis is documented in a comprehensive PDF report, designed to provide deep insights and actionable intelligence.</p>

<p align="justify">As a web app, Plaguards offers users the flexibility to conduct powerful, on-demand analysis from anywhere, at any time, making it invaluable to blue teams tasked with responding to complex malware threats. This innovation not only accelerates workflows but also enhances detection accuracy, positioning Plaguards as a vital asset in proactive threat response.</p>


# Motivation Behind Plaguards

<p align="justify">Plaguards was created to address a significant challenge faced by Incident Response (IR) teams in analyzing obfuscated PowerShell scripts during malware and ransomware incidents. These incidents are high-priority due to their potential to disrupt business operations severely. While numerous JavaScript deobfuscation tools exist, there is a stark lack of equivalent resources tailored for PowerShell—a critical gap given the recent rise of fileless PowerShell-based attacks in 2024.</p>

<p align="justify">Recognizing this need, Plaguards offers automated deobfuscation specifically for PowerShell scripts, empowering IR teams to swiftly identify Indicators of Compromise (IOCs) and validate whether these IOCs represent legitimate threats or false positives. By focusing on PowerShell, Plaguards equips security teams with a dedicated tool to respond more efficiently and effectively to modern threats.</p>

<p align="justify">The platform’s capabilities are further enhanced by its templated PDF reports, which document each deobfuscated line of code (LOC) along with IOCs, such as IP addresses and HTTP references. These are cross-referenced with threat intelligence to provide actionable insights, ensuring that IR teams can respond with both speed and depth. With its specialized focus and streamlined reporting, Plaguards stands out as an essential asset in the proactive defense against complex malware threats.</p>


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

2. Configure your Virus Total API key. 

> For instructions on obtaining your API key, Click [here](https://github.com/Bread-Yolk/plaguards/wiki/Configure-your-Virus-Total-API-Key).

```Dockerfile
# At Dockerfile
ENV VT_API_KEY="your_api_key_goes_here"
```
 
3. Run the setup script.

```txt
chmod 777 plaguards.sh
sudo ./plaguards.sh
```

4. By default, Plaguards dashboard will listen at port **8000**.


## Demo for Main Features


|IOC Checker|PDF Report|
|:---------:|:-----------------------:|
|<img src="static/assets/demo.gif" width="550"> | <img src="static/assets/portrait.gif" width="200"> |

|Powershell Deobfuscation|PDF Report|
|:---------:|:-----------------------:|
|<img src="static/assets/demo.gif" width="550"> | <img src="static/assets/portrait.gif" width="200"> |



## Authors
- [jon-brandy](https://github.com/jon-brandy)
- [LawsonSchwantz](https://github.com/LawsonSchwantz)
- [tkxldk](https://github.com/tkxldk)
