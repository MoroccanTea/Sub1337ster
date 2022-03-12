# Sub1337ster
A simple tool for subdomain enumeration

-------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Commands :

HELP :
       -h | --help | Prints this message.
       -i | --ifile [File path or name] | Takes input from a file to use as domains.
       -d | --domain [Domain to test] | Start testing a domain.
       -o | --ofile [File path or name] | Writes the output to a file.
       -w | --wordlist [File path or name] | Import your own wordlist to use instead of the default one.
USAGE :
       Sub1337ster -d google.com
       Sub1337ster -d google.com -o outfile.md
       Sub1337ster -i domains.lst -o outfile.md
       Sub1337ster -w wordlist.txt -i domains.lst -o outfile.md
