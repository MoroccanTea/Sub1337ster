# Sub1337ster

Sub1337ster is a subdomain enumeration tool that checks for live subdomains, gathers IP addresses, and optionally looks up geolocation data. It supports concurrency (threaded scanning), flexible configuration, and CSV output for easy reporting.

---

## Features

- **Concurrent** subdomain checks (via threaded executor).
- **DNS resolution or Ping** fallback to detect live subdomains.
- **Geolocation** lookups using a configurable external API.
- **CSV logging** of discovered subdomains, IP addresses, and geolocation.
- **Extensible** via a simple config system and external wordlists.

---

## Installation

### 1. Clone or Download

    git clone https://github.com/YourUser/Sub1337ster.git
    cd Sub1337ster

### 2. Install via setup.py

Install the package in your current Python environment (a virtual environment is recommended):

    pip install .

(You can also use `python setup.py install`, but `pip install .` is the more modern approach.)

**Note**: This will install dependencies (like `requests` and `termcolor`) automatically, as defined in setup.py.

### 3. Verify Installation

Once installed, you should have a console command named `sub1337ster`. Test it with:

    sub1337ster --help

You should see a help message describing the available flags.

---

## Usage

### Command-Line Arguments

Sub1337ster provides a straightforward CLI:

- `-d / --domain`: A single domain to enumerate  
- `-i / --ifile`: A file of domains, one per line  
- `-o / --ofile`: Output CSV path (overrides config)  
- `-w / --wordlist`: Path to a subdomain wordlist (overrides config)  
- `-t / --threads`: Number of worker threads for concurrency  
- `-v / --verbose`: Enable verbose (debug) logging

#### Example Commands

Quick single-domain enumeration with default config:

    sub1337ster --domain example.com

Enumerate multiple domains from a file using 20 threads and verbose logging:

    sub1337ster -i domains.txt -t 20 -v

Use a custom wordlist and write output to `my_results.csv`:

    sub1337ster -d google.com -w custom_subdomains.txt -o my_results.csv

If you run without `-d` or `-i`, Sub1337ster exits with an error message.

---

## Configuration

By default, the script looks for a file named `config.ini` (and checks environment variables) to load settings:

    [API]
    key = YOUR_API_KEY_HERE
    url = https://api.ipinfodb.com/v3/ip-city

    [Settings]
    output_path = output.csv
    subdomains_file = subdomains.txt

1. `API.key`: Your geolocation API key (e.g., from ipinfodb.com)  
2. `API.url`: Endpoint for the geolocation service  
3. `Settings.output_path`: Default CSV output location (can be overridden with `-o`)  
4. `Settings.subdomains_file`: Default path to the subdomain wordlist (can be overridden with `-w`)

### Environment Variables

Sub1337ster checks environment variables first (e.g., `API_KEY`, `API_URL`, `OUTPUT_PATH`, `SUBDOMAINS_FILE`) before falling back to `config.ini`. Example:

    export API_KEY="MySecretApiKey"
    export OUTPUT_PATH="results.csv"
    sub1337ster -d example.com

---

## Subdomain Wordlist

`subdomains.txt` should contain one subdomain per line:

    www
    mail
    ftp
    test
    api

Feel free to create different wordlists (short, extended, specialized) and select them at runtime via `-w`.

---

## Example Commands

1. **Quick Scan a Single Domain**

       sub1337ster -d example.com

   This outputs logs to the console and writes CSV to the default path (`output.csv` or your configured `--ofile`).

2. **Multiple Domains from File**

       sub1337ster -i domains.txt -t 20

   Concurrently scans subdomains for each domain in `domains.txt` using 20 threads.

3. **Use a Custom Wordlist and Custom Output**

       sub1337ster -d google.com -w small_wordlist.txt -o my_results.csv

---

## License & Disclaimer

This project is under the **MIT License**. Please see [LICENSE](./LICENSE) for details.

**Important**: Use Sub1337ster only on domains you own or have explicit permission to test. Unauthorized subdomain enumeration can be illegal or violate terms of service.

---

## Contributing

Contributions are welcome! Feel free to open pull requests or issues on GitHub with improvements, bug fixes, or feature requests.

---

## Contact

Created by **Hamza ESSAD**  
Repository: https://github.com/MoroccanTea/Sub1337ster  
Email: essadhmz@gmail.com

---

Happy subdomain hunting!
