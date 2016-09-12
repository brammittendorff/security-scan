import SecurityScanner
import argparse
import sys

parser = argparse.ArgumentParser(description='A simple security scanner.')
parser.add_argument('--url', help='a url to scan', type=str)
parser.add_argument('--file', help='a url file list to scan', nargs='?', type=argparse.FileType('r'), default=sys.stdin)
parser.add_argument('--all', help='the mother of all scans', action='store_true')
parser.add_argument('--headers', help='only scan the headers', action='store_true')
parser.add_argument('--dns', help='only scan DNS', action='store_true')
args = parser.parse_args()

if args.url:
    scanner = SecurityScanner.SecurityScanner()
    scanner.addUrl(args.url)
    if args.all or args.headers:
        scanner.searchHeaders()
    if args.all or args.dns:
        scanner.scanDNS()
elif args.file:
    scanner = SecurityScanner.SecurityScanner()
    scanner.addFile(args.file)
    if args.all or args.headers:
        scanner.searchHeaders()
    if args.all or args.dns:
        scanner.scanDNS()
else:
    parser.print_help()
