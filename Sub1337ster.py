#!/usr/bin/python

import getopt
import sys
from typing import List,Dict


def main(argv):
    welcome_message()
    inputFile = ''
    outputFile = ''
    args: Dict[str,str] = read_args()
    results: List[str] = subdomains_enumeration(args["domain"])
    print(args)
    print(len(results))

def read_args() -> Dict[str,str]:
    """Check for valid CLI Args and return them in a dictionary."""
    if len((sys.argv)) != 2:
        print_help()
        exit()
    return {
        "domain": sys.argv[1],
    }


# Prints the welcome message
def welcome_message():
    print("Welcome to Sub1337ster V0.1\n"
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
          "     Sub1337ster -d google.com\n"
          "     Sub1337ster -d google.com -o outfile.md\n"
          "     Sub1337ster -i domains.lst -o outfile.md\n"
          "     Sub1337ster -w wordlist.txt -i domains.lst -o outfile.md\n")


# Prints the error message
def print_error():
    print("ERROR: Wrong input !\n")
    print_help()

def subdomains_enumeration(domain: str, inputFile: str, outputFile: str) -> List[str]:
    """FUZZING for subdomains"""
    server_status: List[str] = []
    ...
    return server_status


if __name__ == "__main__":
    main(sys.argv[1:])
