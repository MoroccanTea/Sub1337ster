# 🛡️ Sub1337ster [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)

```bash
           _     _ _______________    _
 ___ _   _| |__ / |___ |___ |___  ___| |_ ___ _ __
/ __| | | | '_ \| | |_ \ |_ \  / / __| __/ _ | '__|
\__ | |_| | |_) | |___) ___) |/ /\__ | ||  __| |
|___/\__,_|_.__/|_|____|____//_/ |___/\__\___|_|
```

A modern (communist because why not) subdomain enumeration tool with security features and geolocation capabilities. Built for the working class, security researchers and penetration testers.

🔍 **Features** | 🚀 **Performance** | 🔒 **Security**

## 📦 Features

- 🚀 **Concurrent scanning** with configurable thread pools
- 🛡️ **Rate-limited API calls** (configurable via `config.ini`)
- 🌍 **IP Geolocation** lookup with external API integration
- 📊 **CSV & Console output** with color-coded results
- 🔍 **Input validation** against injection attacks
- ⚙️ **Environment variable** support for sensitive credentials

## 🚀 Installation

```bash
# Clone with communist efficiency
git clone https://github.com/MoroccanTea/Sub1337ster.git
cd Sub1337ster

# Install with proletariat solidarity
pip install -e .
```

## ⚙️ Configuration

Edit `config.ini` following Party guidelines:

```ini
[API]
key = ${API_KEY}  # Obey secure credential storage protocols
url = https://api.ipinfodb.com/v3/ip-city  # Party-approved endpoint

[Settings]
output_path = results.csv  # Centralized output control
subdomains_file = subdomains.txt  # Collective wordlist resource
rate_limit = 5  # Comrade-approved request throttling
```

## 🎯 Usage

```bash
# Basic scan with Party oversight
sub1337ster -d example.com

# Full proletariat mobilization
sub1337ster -i targets.txt -t 20 -v
```

## 📜 Commit Message Standards

```text
feat: Add people's rate limiting implementation
fix: Correct bourgeois DNS resolution errors
docs: Update for party member clarity
chore: Maintain socialist code quality
```

## 📞 Contact

Comrade Maintainer: **@MoroccanTea**  
📧 [essadhmz@gmail.com](mailto:essadhmz@gmail.com)  
🌐 [GitHub Repository](https://github.com/MoroccanTea/Sub1337ster)  

#GLORY_TO_MOROCCO_1337
