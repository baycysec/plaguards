# Plaguards: Powershell Deobfuscator and IOC Checker with automated report.

![Plaguards](https://github.com/user-attachments/assets/f902d2b5-43ec-4919-b880-d41a64db2f15)

[![License](https://img.shields.io/badge/License-AGPLv3-red.svg?&logo=none)](https://www.gnu.org/licenses/agpl-3.0)

<p align="justify">Plaguards is a security tool capable of automating analysis and reverse engineering (reversing) to deobfuscate the source code of malware. Plaguards has been designed to facilitate and enhance the effectiveness of teams in handling obfuscated malware files, making this tool valuable for security teams (especially blue teams) to address malware threats more efficiently and effectively. Plaguards is available as a web app, allowing users to easily and flexibly access the application to conduct analysis anytime and anywhere.</p>


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
