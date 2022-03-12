import os
import sys
import requests
import csv
import re
from termcolor import colored
from subprocess import Popen, PIPE

domains_list = ["google.com"] # Domain list you want to scan.
subdomains_list = open("subdomains.txt", "r") # Subdomain list you want to use as a wordlist
api_key = ""  # Change this with your api key from ipinfodb.com
ip_pattern = "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"  # Changing this will break the code if you don't have a good regex


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


def sanitize_json(json):  # Shows the results of geolocation in a better
    for key in json.keys():
        print(key, ":", json.get(key))


def writing_output(data):  # Writes output to csv file
    titles = ['Domain', 'Subdomain', 'IP', 'Geolocation']
    file_exists = os.path.isfile('./output.csv')
    with open('./output.csv', 'a', encoding='UTF8') as csv_file:
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
    response = os.popen(f"ping {sub[:-1] + '.' + domain}").read()  # Starts pinging to see if the host is up
    if "Received = 4" in response:  # Check if host is up
        print(
            colored("[+] " + sub[:-1] + "." + domain + " exists and seems to be up.", "green", attrs=['bold']))
        print("IP Address : ", GetIpAddressWin(response))
        sanitize_json(getGeolocation(GetIpAddressWin(response)))
        subdomain = sub[:-1] + "." + domain
        data = [domain, subdomain, GetIpAddressWin(response),
                getGeolocation(GetIpAddressWin(response))]
        writing_output(data)
    else:
        print(colored("[-] " + sub[:-1] + "." + domain + " is either down, doesn't exist or is blocking pings.",
                      "red", attrs=['bold']))


def linux_enum(sub, domain):  # Called when OS is Linux
    subdomain = sub[:-1] + "." + domain
    response = os.system("ping -c 4 " + subdomain + " 2>&1 >/dev/null")  # Starts pinging to see if the host is up
    if response == 0:  # Check if host is up
        print(
            colored("[+] " + sub[:-1] + "." + domain + " exists and seems to be up.", "green",
                    attrs=['bold']))
        print("IP Address : ", GetIpAddressLin(subdomain))
        sanitize_json(getGeolocation(GetIpAddressLin(subdomain)))
        data = [domain, subdomain, GetIpAddressLin(subdomain),
                getGeolocation(GetIpAddressLin(subdomain))]
        writing_output(data)
    else:
        print(colored(
            "[-] " + sub[:-1] + "." + domain + " is either down, doesn't exist or is blocking pings.",
            "red", attrs=['bold']))


def run():  # Starts the script
    for domain in domains_list:
        for sub in subdomains_list:
            if machine_type() != "linux":
                windows_enum(sub, domain)
            else:
                linux_enum(sub, domain)


run()
