import os
import requests
import csv
import re
from termcolor import colored

domains_list = ["google.com"]
subdomains_list = open("subdomains.txt", "r")
api_key = ""  # Change this with your api key from ipinfodb.com
ip_pattern = "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"


def check_if_up(domain):
    response = os.popen(f"ping {domain}").read()  # Starts pinging to see if the host is up
    if "Received = 4" in response:  # if host is up
        print(colored("[+] " + domain + " exists and seems to be up.", "green"))
        GetIpAddress(response)
        getGeolocation(api_key, domain)
    else:
        print(colored("[-] " + domain + " is either down, doesn't exist or is blocking pings.", "red"))


def GetIpAddress(response):  # Get th Ip address for the subdomain
    return re.findall(ip_pattern, response)[0]


def getGeolocation(key, ip):  # Get geolocation of domain using api
    req = requests.get(
        "https://api.ipinfodb.com/v3/ip-city/?key=" + key + "&ip=" + ip + "&format=json").json()
    geolocation = {key: val for key, val in req.items() if key not in ['statusCode', 'statusMessage', 'ipAddress']}
    return geolocation


def sanitize_json(json):
    for key in json.keys():
        print(key, ":", json.get(key))


def writingOutput(data):  # Writes output to csv file
    titles = ['Domain', 'Subdomain', 'IP', 'Geolocation']
    file_exists = os.path.isfile('./output.csv')
    with open('./output.csv', 'a', encoding='UTF8') as csv_file:
        writer = csv.writer(csv_file)
        if not file_exists:
            writer.writerow(titles)
        writer.writerow(data)


def main():  # Starts the script
    os.system('color')
    for domain in domains_list:
        for sub in subdomains_list:
            response = os.popen(f"ping {sub[:-1] + '.' + domain}").read()  # Starts pinging to see if the host is up
            if "Received = 4" in response:  # Check if host is up
                print(colored("[+] " + sub[:-1] + "." + domain + " exists and seems to be up.", "green"))
                print("IP Address : ", GetIpAddress(response))
                sanitize_json(getGeolocation(api_key, GetIpAddress(response)))
                subdomain = sub[:-1] + "." + domain
                data = [domain, subdomain, GetIpAddress(response),
                        getGeolocation(api_key, GetIpAddress(response))]
                writingOutput(data)
            else:
                print(colored("[-] " + sub[:-1] + "." + domain + " is either down, doesn't exist or is blocking pings.",
                              "red"))


main()
