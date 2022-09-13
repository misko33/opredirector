#!/usr/bin/env python3

import argparse
import requests
import sys
import re

from urllib.parse import urlsplit, parse_qs, urlparse

redirectTest = "https://www.google.com"

def validateUrl(url):
    regex = re.compile(
        r'^(?:http|ftp)s?://'
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'
        r'localhost|'
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        r'(?::\d+)?'
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        
    if(re.match(regex, url)): return True
    else: return False

def test_open_redirect(url):
    try:
        req = requests.get(url, allow_redirects=False)
        if("Location" in req.headers):
            if(req.headers["Location"] == redirectTest):
                print("[+] Open redirect: " + url)
    except socket.gaierror:
        print("ConnectionError detected. Target is not acccessible. Exiting...")
        sys.exit(-1)
    except NewConnectionError:
        print("ConnectionError detected. Target is not accessible. Exiting...")
        sys.exit(-1)
    except requests.exceptions.ConnectionError:
        print("ConnectionError detected. Target is not accessible. Exiting...")
        sys.exit(-1)
    except urllib3.exceptions.MaxRetryError:
        print("ConnectionError detected. Target is not accessible. Exiting...")
        sys.exit(-1)
    except KeyboardInterrupt:
        print("KeyboardInterrupt detected. Exiting...")
        sys.exit(-1)

    return
def main():
    
    # -u option functionality (test single url)
    if(args.url):
        url = args.url
        
        if(not args.url.startswith("http")):
            url = "http://" + args.url
        
        if("Strict-Transport-Security" in requests.get(url).headers and not args.url.startswith("http")):
            url = "https://" + args.url
        
        if(not validateUrl(url)):
            print("Url '" + url + "' not valid. Exiting...")
            sys.exit(-1)

        #Dictionary of GET parameters
        getParams = dict(parse_qs(urlsplit(url).query))
        if(len(getParams) == 0):
            print("No parameters to test inside URL.")

        #Test all GET parameters one by one
        for k,v in getParams.items():
            print("Testing parameter '" + k + "'")
            test_open_redirect(url.replace(''.join(v), redirectTest))


if(__name__ == "__main__"):

    parser = argparse.ArgumentParser(description='opredirector, Open Redirection tester tool', add_help = False)
    generalGroup= parser.add_argument_group('GENERAL')
    generalGroup.add_argument('-u', type=str, metavar='url', dest='url', help='\t\t Specify endpoint to test')
    otherGroup = parser.add_argument_group('OTHER')
    otherGroup.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS, help='\t\t Print this help message\n\n')
    
    args = parser.parse_args()
    
    # Check if -u is specified (mandatory)
    if(not args.url):
        print("Please enter url to test. Exiting.")
        sys.exit(-1)
    
    #Start of execution
    main()
