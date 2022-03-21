#!/usr/bin/python

import os
import sys
import requests  # TODO: add this to requirements
import csv
import re
from termcolor import colored  # TODO: add this to requirements
from subprocess import Popen, PIPE
from datetime import datetime

domains_list = []
domains_file = ''  # Domains file you want to scan.
subdomains_file_name = 'subdomains.txt'
subdomains_file = open(subdomains_file_name, "r")  # Subdomain file you want to use as a wordlist
subdomains_list = []
up_subdomains = []
api_key = ""  # Change this with your api key from ipinfodb.com
ip_pattern = "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"  # Changing this will break the code if you don't have a good regex
output_path = "output.csv"  # Full path to output file


def GetIpAddressWin(response):  # Get the Ip address for the subdomain
    return re.findall(ip_pattern, response)[0]


def GetIpAddressLin(subdomain):  # Get the Ip address for the subdomain
    subproc = Popen("dig " + subdomain + " +short", stdout=PIPE, shell=True)
    output, errorCode = subproc.communicate()
    result = re.findall(ip_pattern, str(output))[0]
    return result


def getGeolocation(ip):  # Get geolocation of domain using api
    req = requests.get(
        "https://api.ipinfodb.com/v3/ip-city/?key=" + api_key + "&ip=" + ip + "&format=json").json()
    geolocation = {key: val for key, val in req.items() if key not in ['statusCode', 'statusMessage', 'ipAddress']}
    return geolocation


def sanitize_json(json):  # Prints the results of geolocation in a better
    for key in json.keys():
        print(key, ":", json.get(key))
    print("\n")


def writing_output(data):  # Writes output to csv file
    titles = ['Domain', 'Subdomain', 'Ip address', 'Geolocation']
    file_exists = os.path.isfile(output_path)
    with open(output_path, 'a', encoding='UTF8') as csv_file:
        writer = csv.writer(csv_file)
        if not file_exists:
            writer.writerow(titles)
        writer.writerow(data)


def machine_type():  # Checks if Windows or Linux
    if sys.platform != "linux":
        return "windows"
    else:
        return "linux"


def windows_enum(sub, domain):  # Called when OS is Windows
    os.system('color')
    subdomain = sub + "." + domain
    print(colored("Scanning " + subdomain + " :\n", attrs=['bold']))
    response = os.popen(f"ping {subdomain}").read()  # Starts pinging to see if the host is up
    if "Received = 4" in response:  # Check if host is up
        print(
            colored("[+] " + subdomain + " exists and seems to be up.", "green", attrs=['bold']))
        up_subdomains.append(subdomain)
        print("ipAddress : ", GetIpAddressWin(response))
        sanitize_json(getGeolocation(GetIpAddressWin(response)))
        data = [domain, subdomain, GetIpAddressWin(response),
                getGeolocation(GetIpAddressWin(response))]
        writing_output(data)
    else:
        subdomainNotFound(subdomain)


def linux_enum(sub, domain):  # Called when OS is Linux
    subdomain = sub + "." + domain
    print(
        colored("Scanning: " + subdomain + " :\n",
                attrs=['bold']))
    response = os.system("ping -c 4 " + subdomain + " > /dev/null 2>&1")  # Starts pinging to see if the host is up
    if response == 0:  # Check if host is up
        subdomainFound(domain, subdomain)
    else:
        subdomainNotFound(subdomain)


def subdomainFound(domain, subdomain):
    print(
        colored("[+] " + subdomain + " exists and seems to be up.", "green",
                attrs=['bold']))
    print("ipAddress : ", GetIpAddressLin(subdomain))
    sanitize_json(getGeolocation(GetIpAddressLin(subdomain)))
    data = [domain, subdomain, GetIpAddressLin(subdomain),
            getGeolocation(GetIpAddressLin(subdomain))]
    writing_output(data)


def subdomainNotFound(subdomain):
    print(colored(
        "[-] " + subdomain + " is either down, doesn't exist or is blocking pings.\n",
        "red", attrs=['bold']))


def showStats(nbrFound, startTime):
    totalNbrOfDomains = str(len(subdomains_list) * len(domains_list))
    time_elapsed = datetime.now() - startTime
    print(colored("Sub1337ster scan finished !\n"
                  "Tested " + totalNbrOfDomains + " subdomains,\n"
                                                  "Found " + str(len(nbrFound)) + " subdomains UP,\n"
                                                                                  "Time elapsed {}:".format(
        time_elapsed).split('.')[0]
                  , attrs=['bold']))


def read_args():
    global domains_file
    global output_path
    global subdomains_file_name
    if len(sys.argv) == 1:
        print_help()
        exit()
    elif len(sys.argv) == 2:
        if sys.argv[1] == '' or sys.argv[1] == '-h' or sys.argv[1] == '--help':
            print_help()
            exit()
    elif len(sys.argv) == 3:
        if sys.argv[1] == '-d' or sys.argv[1] == '--domain':
            domain = sys.argv[2]
            domains_list.append(domain)
        elif sys.argv[1] == '-i' or sys.argv[1] == '--ifile':
            domains_file_name = sys.argv[2]
            domains_file = open(domains_file_name, 'r')
            for domain in domains_file:
                domains_list.append(domain.strip())
    elif len(sys.argv) == 4:
        if sys.argv[1] == '-d' or sys.argv[1] == '--domain' and sys.argv[3] == '-o' or sys.argv[3] == '--ofile':
            domain = sys.argv[2]
            domains_list.append(domain)
            output_path = sys.argv[4]
        elif sys.argv[1] == '-i' or sys.argv[1] == '--ifile' and sys.argv[3] == '-o' or sys.argv[3] == '--ofile':
            domains_file_name = sys.argv[2]
            domains_file = open(domains_file_name, 'r')
            for domain in domains_file:
                domains_list.append(domain.strip())
            output_path = sys.argv[4]
        elif sys.argv[1] == '-w' or sys.argv[1] == '--wordlist' and sys.argv[3] == '-d' or sys.argv[3] == '--domain':
            subdomains_file_name = sys.argv[2]
            domain = sys.argv[4]
            domains_list.append(domain)
        elif sys.argv[1] == '-w' or sys.argv[1] == '--wordlist' and sys.argv[3] == '-i' or sys.argv[3] == '--ifile':
            subdomains_file_name = sys.argv[2]
            domains_file_name = sys.argv[2]
            domains_file = open(domains_file_name, 'r')
            for domain in domains_file:
                domains_list.append(domain.strip())
    else:
        print_error()


def main():
    welcome_message()
    read_args()
    start = datetime.now()
    for sub in subdomains_file:
        subdomains_list.append(sub.strip())
    for domain in domains_list:
        for sub in subdomains_list:
            if machine_type() != "linux":
                windows_enum(sub, domain)
            else:
                linux_enum(sub, domain)
    showStats(up_subdomains, start)


def welcome_message():  # Prints the welcome message
    print("Welcome to Sub1337ster V1.0\n"
          "Created with love by MoroccanTea\n"
          "https://github.com/MoroccanTea\n")


# Prints the help message
def print_help():
    print("HELP :\n"
          "     -h | --help | Prints this message.\n"
          "     -i | --ifile [File path or name] | Takes input from a file to use as domains.\n"
          "     -d | --domain [Domain to test] | Start testing a domain.\n"
          "     -o | --ofile [File path or name] | Writes the output to a file.\n"
          "     -w | --wordlist [File path or name] | Import your own wordlist to use instead of the default one.\n\n"
          "USAGE :\n"
          "     Sub1337ster.py -d google.com\n"
          "     Sub1337ster.py -d google.com -o outfile.csv\n"
          "     Sub1337ster.py -i domains.lst -o outfile.csv\n"
          "     Sub1337ster.py -w wordlist.txt -i domains.lst -o outfile.csv\n")


def print_error():  # Prints the error message
    print(colored("ERROR: Wrong input !\n", "red"))
    print_help()


if __name__ == "__main__":
    main()

# TODO: fix stats in Linux
