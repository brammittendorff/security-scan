"""This is the security scanner module.

It scans your given url or urllist.txt
"""
import SecurityScanner
import argparse
import sys

p = argparse.ArgumentParser(description='A simple security scanner.')
p.add_argument('--url', help='a url to scan', type=str)
p.add_argument('--file', help='a url file list to scan', nargs='?', type=argparse.FileType('r'), default=sys.stdin)
p.add_argument('--all', help='the mother of all scans', action='store_true')
p.add_argument('--directories', help='scan directories after url', action='store_true')
p.add_argument('--smtpbrute', help='bruteforce mailserver using VRFY or RCPT', action='store', default='VRFY')
p.add_argument('--headers', help='only scan the headers', action='store_true')
p.add_argument('--dns', help='only scan DNS', action='store_true')
p.add_argument('--log', help='a file to write the logs to')
args = p.parse_args()

if args.url:
    scanner = SecurityScanner.SecurityScanner()
    if args.log:
        scanner.log_to_file(args.log)
    scanner.add_url(args.url)

    print args.smtpbrute

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
    p.print_help()
