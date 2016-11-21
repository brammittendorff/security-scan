"""This is the security scanner module.

It scans your given url or urllist.txt
"""
import SecurityScanner
import argparse
import sys

parser = argparse.ArgumentParser(description='A simple security scanner.')
parser.add_argument('--url', help='a url to scan', type=str)
parser.add_argument('--file', help='a url file list to scan', nargs='?', type=argparse.FileType('r'), default=sys.stdin)
parser.add_argument('--all', help='the mother of all scans', action='store_true')
parser.add_argument('--directories', help='scan directories after url', action='store_true')
parser.add_argument('--smtpbrute', help='bruteforce usernames on mailserver using VRFY or RCPT', action='store_true')
parser.add_argument('--headers', help='only scan the headers', action='store_true')
parser.add_argument('--dns', help='only scan DNS', action='store_true')
parser.add_argument('--log', help='a file to write the logs to')
args = parser.parse_args()

if args.url:
    scanner = SecurityScanner.SecurityScanner()
    if args.log:
        scanner.log_to_file(args.log)
    scanner.add_url(args.url)

    if args.all or args.directories:
        scanner.search_directories()
    if args.all or args.smtpbrute:
        if args.smtpbrute == 'RCPT':
            scanner.search_email_server(args.smtpbrute)
        else:
            scanner.search_email_server()
    if args.all or args.headers:
        scanner.search_headers()
    if args.all or args.dns:
        scanner.search_dns()
elif args.file is not sys.stdin:
    scanner = SecurityScanner.SecurityScanner()
    if args.log:
        scanner.log_to_file(args.log)
    scanner.add_file(args.file)

    if args.all or args.directories:
        scanner.search_directories()
    if args.all or args.smtpbrute:
        if args.smtpbrute == 'RCPT':
            scanner.search_email_server(args.smtpbrute)
        else:
            scanner.search_email_server()
    if args.all or args.headers:
        scanner.search_headers()
    if args.all or args.dns:
        scanner.search_dns()
else:
    parser.print_help()
