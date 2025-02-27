#!/usr/bin/env python3

import argparse
import csv
import logging
import os
import re
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import quote

import requests
from termcolor import colored

from config_manager import ConfigManager


# Global regex for IPv4 addresses (simple approach)
IP_PATTERN = r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"


def setup_logging(verbose: bool = False):
    """
    Set up the logging configuration.
    :param verbose: If True, uses DEBUG level. Otherwise INFO.
    """
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S"
    )


def parse_args():
    """
    Parse command-line arguments using argparse.
    :return: argparse.Namespace with all arguments.
    """
    parser = argparse.ArgumentParser(
        description="Sub1337ster - Subdomain Enumeration Tool"
    )
    parser.add_argument(
        '-d', '--domain',
        help="Single domain to enumerate (overrides -i/--ifile)."
    )
    parser.add_argument(
        '-i', '--ifile',
        help="Path to a file containing a list of domains to enumerate."
    )
    parser.add_argument(
        '-o', '--ofile',
        help="Path to write CSV output (overrides config if used)."
    )
    parser.add_argument(
        '-w', '--wordlist',
        help="Path to a subdomain wordlist (overrides config if used)."
    )
    parser.add_argument(
        '-t', '--threads',
        type=int,
        default=10,
        help="Number of threads to use for concurrency (default=10)."
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help="Enable verbose logging for debugging."
    )
    return parser.parse_args()


def read_domain_list(domain: str, domain_file: str) -> list:
    """
    Read either a single domain or multiple domains from file.
    :param domain: Single domain from CLI.
    :param domain_file: Path to file containing domains, one per line.
    :return: A list of domains (strings).
    """
    domains = []
    if domain:
        # Validate single domain
        if not is_valid_domain(domain):
            logging.error(f"Invalid domain syntax: {domain}")
            sys.exit(1)
        domains.append(domain.strip())
    elif domain_file:
        if not os.path.isfile(domain_file):
            logging.error(f"Domains file not found: {domain_file}")
            sys.exit(1)
        try:
            with open(domain_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and is_valid_domain(line):
                        domains.append(line)
                    else:
                        logging.warning(f"Skipping invalid domain: {line}")
        except IOError as e:
            logging.error(f"Error reading domains file: {str(e)}")
            sys.exit(1)
    else:
        logging.error("No domain specified. Use -d or -i.")
        sys.exit(1)
    return domains


def is_valid_domain(domain: str) -> bool:
    """
    Validate domain using a simple regex approach for standard domain syntax.
    :param domain: Domain string to validate.
    :return: True if domain looks valid, False otherwise.
    """
    domain_regex = re.compile(r"^([a-zA-Z0-9]+(-[a-zA-Z0-9]+)*\.)+[a-zA-Z]{2,}$")
    return bool(domain_regex.match(domain))


def load_subdomains(wordlist_path: str) -> list:
    """
    Load subdomain wordlist from file.
    :param wordlist_path: Path to subdomain list.
    :return: A list of subdomain strings.
    """
    subdomains = []
    if not os.path.isfile(wordlist_path):
        logging.error(f"Subdomains file not found: {wordlist_path}")
        sys.exit(1)
    try:
        with open(wordlist_path, 'r', encoding='utf-8') as f:
            for line in f:
                sub = line.strip()
                if sub:
                    subdomains.append(sub)
    except IOError as e:
        logging.error(f"Error reading subdomains file: {str(e)}")
        sys.exit(1)
    return subdomains


def resolve_ip(subdomain: str, domain: str) -> str:
    """
    Attempt to resolve IP address for subdomain.domain using socket.gethostbyname.
    If socket fails, fallback to OS-specific dig/ping approach.
    :param subdomain: The subdomain prefix (e.g. "www").
    :param domain: The domain string (e.g. "example.com").
    :return: The IP address as a string, or None if not found.
    """
    full_subdomain = f"{subdomain}.{domain}"
    # 1) Try Python's built-in DNS resolution
    try:
        ip = socket.gethostbyname(full_subdomain)
        return ip
    except socket.gaierror:
        logging.debug(f"socket.gethostbyname failed for {full_subdomain}")

    # 2) If that fails, do platform-based fallback
    system_name = platform.system().lower()
    if 'win' in system_name:
        # Use ping -n 1
        cmd = ["ping", "-n", "1", full_subdomain]
    else:
        # Assume a *nix system
        cmd = ["ping", "-c", "1", full_subdomain]

    try:
        proc = Popen(cmd, stdout=PIPE, stderr=PIPE)
        output, error = proc.communicate(timeout=5)
        if proc.returncode == 0:
            # Attempt to extract IP with a regex
            match_ips = re.findall(IP_PATTERN, output.decode())
            return match_ips[0] if match_ips else None
    except Exception as e:
        logging.debug(f"Fallback resolution error: {str(e)}")

    return None


def geolocate_ip(ip: str, api_url: str, api_key: str) -> dict:
    """
    Get geolocation data for the specified IP address using an external API.
    :param ip: IP address string.
    :param api_url: API base URL from config.
    :param api_key: API key from config.
    :return: A dict with geolocation fields or {} on error.
    """
    if not ip or not re.match(IP_PATTERN, ip):
        return {}
    
    # Sanitize inputs
    safe_ip = quote(ip)
    safe_key = quote(api_key)
    
    full_url = f"{api_url}?key={safe_key}&ip={safe_ip}&format=json"
    
    # Retry logic with rate limiting
    max_retries = 3
    retry_delay = 1  # seconds
    
    for attempt in range(max_retries):
        try:
            resp = requests.get(full_url, timeout=5)
            resp.raise_for_status()
            
            # Rate limit based on config
            rate_limit = int(config.get_rate_limit())
            if rate_limit > 0:
                time.sleep(1 / rate_limit)
                
            data = resp.json()
            
            # Validate response structure
            if not isinstance(data, dict):
                raise ValueError("Invalid API response format")
                
            # Filter out some fields
            excluded_keys = {'statusCode', 'statusMessage', 'ipAddress'}
            return {k: v for k, v in data.items() if k not in excluded_keys}
            
        except requests.RequestException as e:
            if attempt == max_retries - 1:
                logging.debug(f"Geolocation API error for {ip}: {str(e)}")
                return {}
            time.sleep(retry_delay * (attempt + 1))
        except ValueError as e:
            logging.debug(f"Invalid API response for {ip}: {str(e)}")
            return {}


def check_subdomain(sub: str, domain: str, api_url: str, api_key: str) -> dict:
    """
    Check whether sub.domain is up, resolve IP, and optionally geolocate it.
    :param sub: Subdomain prefix.
    :param domain: Root domain.
    :param api_url: Geolocation API URL from config.
    :param api_key: Geolocation API key from config.
    :return: Dictionary with 'domain', 'subdomain', 'ip', 'geolocation', and 'status' fields.
    """
    full_subdomain = f"{sub}.{domain}"
    result = {
        'domain': domain,
        'subdomain': full_subdomain,
        'ip': None,
        'geolocation': {},
        'status': 'down'
    }

    ip = resolve_ip(sub, domain)
    if ip:
        # Mark as up
        result['status'] = 'up'
        result['ip'] = ip
        # Retrieve geolocation
        geo = geolocate_ip(ip, api_url, api_key)
        result['geolocation'] = geo
    return result


def write_output(csv_path: str, data: dict, write_header: bool = False):
    """
    Write subdomain result to CSV file.
    :param csv_path: Output CSV path.
    :param data: Dictionary with enumeration results.
    :param write_header: If True, write column headers first.
    """
    headers = ['Domain', 'Subdomain', 'IP Address', 'Geolocation']
    row = [
        data.get('domain', ''),
        data.get('subdomain', ''),
        data.get('ip', ''),
        data.get('geolocation', {}),
    ]

    try:
        with open(csv_path, 'a', encoding='utf-8', newline='') as csv_file:
            writer = csv.writer(csv_file)
            if write_header:
                writer.writerow(headers)
            writer.writerow(row)
    except IOError as e:
        logging.error(f"Could not write to CSV file {csv_path}: {str(e)}")


def main():
    """
    Main entry point. Parses arguments, loads config, enumerates subdomains concurrently, and logs results.
    """
    args = parse_args()
    setup_logging(args.verbose)

    # Load config
    try:
        config = ConfigManager()
    except Exception as e:
        logging.error(f"Error loading configuration: {str(e)}")
        sys.exit(1)

    # Domain(s) list
    domains = read_domain_list(args.domain, args.ifile)

    # Determine subdomains file (CLI overrides config)
    subdomains_file = args.wordlist or str(config.get_subdomains_file())
    subdomains_list = load_subdomains(subdomains_file)

    # Determine CSV output path (CLI overrides config)
    output_path = args.ofile or str(config.get_output_path())

    # Check if we need to write CSV header
    write_header = not os.path.isfile(output_path)

    # Pull API data from config
    api_url = config.get_api_url()
    api_key = config.get_api_key()

    # Start scanning
    start_time = datetime.now()
    logging.info("Starting Sub1337ster scan...")

    up_subdomains = []
    tasks = []
    results = []

    # Thread pool for concurrency
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        # Submit all subdomain checks
        for domain in domains:
            for sub in subdomains_list:
                tasks.append(
                    executor.submit(
                        check_subdomain,
                        sub, domain, api_url, api_key
                    )
                )

        for future in as_completed(tasks):
            # Each future returns a dict
            data = future.result()
            results.append(data)

    # Sort or filter results as desired
    # For example, let's keep 'up' subdomains in up_subdomains
    for r in results:
        if r['status'] == 'up':
            up_subdomains.append(r['subdomain'])
        # Also write to CSV
        write_output(output_path, r, write_header)
        write_header = False  # only write header once

        # Print color-coded result to console
        if r['status'] == 'up':
            logging.info(
                colored(f"[UP] {r['subdomain']} -> IP: {r['ip']}", "green", attrs=['bold'])
            )
        else:
            logging.debug(
                colored(f"[DOWN/UNRESOLVED] {r['subdomain']}", "red")
            )

    elapsed = datetime.now() - start_time
    logging.info(
        colored(
            f"Scan finished! Tested {len(results)} subdomains total. "
            f"Found {len(up_subdomains)} up. Time elapsed: {elapsed}.",
            attrs=['bold']
        )
    )


if __name__ == "__main__":
    main()
