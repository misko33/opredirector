#!/usr/bin/env python3

import argparse
import socket
import requests
import random
import sys
import urllib
import re
import os

from urllib.parse import urlsplit, parse_qs, urlparse

redirectTest = "https://www.google.com"

def validateUrl(url):
    if(not args.url.startswith("http")):
        url = "http://" + args.url
        
    if("Strict-Transport-Security" in requests.get(url).headers and not args.url.startswith("http")):
        url = "https://" + args.url
    
    regex = re.compile(
        r'^(?:http|ftp)s?://'
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'
        r'localhost|'
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        r'(?::\d+)?'
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        
    if(re.match(regex, url)): return True
    else: return False

def processAndTestUrl(url):
    placeholder = {}
    
    #Dictionary of GET parameters
    getParams = dict(parse_qs(urlsplit(url).query))
    if(len(getParams) == 0):
        print("No parameters to test inside URL.")
        return

    u = urlparse(url)
    query = parse_qs(u.query)

    scheme = u.scheme
    creds = u.netloc
    path = u.path
    q = query

    baseUrl = ""
    baseUrl += scheme
    baseUrl += "://"
    baseUrl += creds
    baseUrl += path

    for test in getParams.keys():
        # If '-v' or '--verbose' is specified
        if(args.verbose):
            print("    Testing '" + str(test) + "' parameter ...")
        
        testParameter = "".join(test)
        recreated = baseUrl
    
        c = 0
        for k, v in getParams.items():
            if(c == 0): recreated += "?"
            else: recreated += "&"

            recreated += "".join(k)
            recreated += "="
            if("".join(k) == testParameter):
                recreated += redirectTest
            else: 
                num = len(v)
                tmp = 0
                
                # If parameter is not passed as array
                if(num <= 1):
                    recreated += "".join(v)

                # Multiple parameters are passed with same name (as array)
                else:
                    for item in v:
                        if(tmp != 0): recreated += "&" + "".join(k) + "="
                        recreated += item
                        tmp += 1
            c+= 1

        # Perform actual vulnerability testing on recreated/parsed url
        test_open_redirect(recreated)

def test_open_redirect(url):
    try:
        req = requests.get(url, allow_redirects=False)
        if("Location" in req.headers):
            if(req.headers["Location"] == redirectTest):
                print("[+] Open redirect: " + url)
    except ConnectionError:
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
        
        if(not validateUrl(url)):
            print("Url '" + url + "' not valid. Exiting.")
            sys.exit(-1)

        # Test single url
        processAndTestUrl(url)
    
    # -f option functionality (test multiple urls from a file)
    if(args.file):
        file = args.file

        if(not(os.path.exists(file))):
            print("Specified file '" + file + "' doesn't exist. Exiting.")
            sys.exit(-1)

        # Test urls one by one from a file
        with open(file, "r") as f:
            lines = f.readlines()
            for line in lines:
                print("\n[i] Processing url: " + line.strip())
                processAndTestUrl(line.strip())

if(__name__ == "__main__"):

    parser = argparse.ArgumentParser(description='opredirector, Open Redirection tester tool', add_help = False)
    
    generalGroup= parser.add_argument_group('GENERAL')
    generalGroup.add_argument('-u', type=str, metavar='url', dest='url', help='\t\t Specify single url to test')
    generalGroup.add_argument('-f', type=str, metavar='file', dest='file', help='\t\t Specify multiple urls from a file')
    
    otherGroup = parser.add_argument_group('OTHER')
    otherGroup.add_argument('-v', '--verbose', action='store_true', dest='verbose', help='\t\t Print verbose output')
    otherGroup.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS, help='\t\t Print this help message\n\n')
    
    args = parser.parse_args()
    
    # Check if -u is specified (mandatory)
    if(not args.url and not args.file):
        print("Mandatory argument '-u' or '-f' not specified. Refer to help menu with '-h'. Exiting.")
        sys.exit(-1)
    

    #Start of execution
    main()

