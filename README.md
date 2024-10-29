# Plaguards: Powershell Deobfuscator and IOC Checker with automated report.

![Plaguards](https://github.com/user-attachments/assets/f902d2b5-43ec-4919-b880-d41a64db2f15)

[![License](https://img.shields.io/badge/License-AGPLv3-purple.svg?&logo=none)](https://www.gnu.org/licenses/agpl-3.0)
![Powershell-Deobfuscator](https://img.shields.io/badge/powershell_deobfuscator-blue)
![Powershell-Deobfuscator](https://img.shields.io/badge/ioc_checker-red)

<p align="justify">Plaguards is a cutting-edge security tool built to streamline and automate the deobfuscation of obfuscated PowerShell scripts, empowering security teams to rapidly identify Indicators of Compromise (IOCs) and determine whether they represent verified threats (VT) or false positives (FP). Each analysis is documented in a comprehensive PDF report, designed to provide deep insights and actionable intelligence.

As a web app, Plaguards offers users the flexibility to conduct powerful, on-demand analysis from anywhere, at any time, making it invaluable to blue teams tasked with responding to complex malware threats. This innovation not only accelerates workflows but also enhances detection accuracy, positioning Plaguards as a vital asset in proactive threat response.</p>


## What We Offer?

1. IOC Checker.
2. Powershell Deobfuscation.
3. Automated Reporting in PDF format.

## Requirements

- VPN Server (Recommended for Production Server).
- Domain for HTTPS (Recommended for Production Server).
- Docker
- Docker Compose v2
- Python 3.x
- Port 8000

**(You don't need to install anything manually, we'll do it for you!)**

<br>

## Deployment and Usage

#### To deploy Plaguards:

1. Clone this repository.

> Command

```console
git clone https://github.com/Bread-Yolk/plaguards.git
cd plaguards-main
```

2. Run the setup script.

```
./plaguards.sh
```

3. By default, Plaguards dashboard will listen at port **8000**.

## Main Features

## Authors
- [jon-brandy](https://github.com/jon-brandy)
- [LawsonSchwantz](https://github.com/LawsonSchwantz)
- [tkxldk](https://github.com/tkxldk)
