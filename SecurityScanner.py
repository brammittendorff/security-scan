import requests
import sys
import os
import threading
import socket
import re

try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse

try:
    import Queue as Queue
except ImportError:
    import queue as Queue

class SecurityScanner:

    def __init__(self):
        requests.packages.urllib3.disable_warnings()
        self.urls = []
        self.queue = None
        self.concurrent = 200
        self.session = requests.Session()
        self.bruteEmailType = 'VRFY'

    def run_requests(self, run_function, run_array):
        self.queue = Queue.Queue(self.concurrent * 2)
        for _ in range(self.concurrent):
            t = threading.Thread(name='run_requests', target=run_function)
            t.daemon = True
            t.start()
        try:
            for request in run_array:
                self.queue.put(request)
            self.queue.join()
        except KeyboardInterrupt:
            sys.exit(1)

    def add_url(self, url):
        if isinstance(url, str):
            parsed_url = urlparse(url)
            if parsed_url.scheme:
                correct_url = '{scheme}://{netloc}'.format(scheme=parsed_url.scheme, format=parsed_url.netloc)
            else:
                correct_url = 'http://{url}'.format(url=url)
            print("Scanning: %s" % correct_url)
            self.urls.append(correct_url)

    def add_file(self, file_location):
        # strip /n
        file_location = [word.strip() for word in file_location]
        for url in file_location:
            parsed_url = urlparse(url)
            if parsed_url.scheme:
                correct_url = '{scheme}://{netloc}'.format(scheme=parsed_url.scheme, format=parsed_url.netloc)
            else:
                correct_url = 'http://{url}'.format(url=url)
            print("Scanning: %s" % correct_url)
            self.urls.append(correct_url)

    def search_directories(self):
        directory_requests = []
        directory_file_name = 'resources/directories.txt'
        if os.path.isfile(directory_file_name):
            for url in self.urls:
                with open(directory_file_name) as directoryFile:
                    for filename in directoryFile:
                        directory_requests.append('{url}/{filename}'.format(url=url, filename=filename))
            self.run_requests(self.run_directories, directory_requests)
        else:
            print("File '%s' does not exist" % directory_file_name)

    def run_directories(self):
        while True:
            url = self.queue.get()
            try:
                request = self.session.get(url, verify=False)
                if request.status_code != 404:
                    print('{status} on url: {url}'.format(status=request.status_code, url=url.rstrip()))
            except KeyboardInterrupt:
                sys.exit(1)
            except requests.exceptions.RequestException as requestsError:
                print(requestsError)
            self.queue.task_done()

    def search_email_server(self, smtp_type=None):
        if smtp_type == 'RCPT':
            self.bruteEmailType = smtp_type
        socket_email_commands = []
        directory_unix_users = 'resources/unix-users.txt'
        if os.path.isfile(directory_unix_users):
            with open(directory_unix_users) as directoryFile:
                for unix_user in directoryFile:
                    if smtp_type == 'RCPT':
                        socket_email_commands.append('RCPT TO: {user}'.format(user=unix_user))
                    else:
                        socket_email_commands.append('VRFY {user}'.format(user=unix_user))
        for url in self.urls:
            print("Bruteforcing host: %s\n" % url)
            self.run_email_server(socket_email_commands, url)

    def run_email_server(self, smtp_command, host):
        for command in smtp_command:
            my_socket = socket.socket()
            my_socket.settimeout(10)
            received_data = None
            domain = urlparse(host).netloc
            ip_address = socket.gethostbyname(domain)
            try:
                my_socket.connect((ip_address, 25))
                if self.bruteEmailType == 'RCPT':
                    c_mail_from = ('MAIL FROM:test@{domain}\n'.format(domain=domain))
                    my_socket.sendall(c_mail_from.encode('utf-8'))
                    c_rcpt_to = '{command}@{domain}\n'.format(command=command, domain=domain)
                    error = my_socket.sendall(c_rcpt_to.encode('utf-8'))
                else:
                    error = my_socket.sendall(command.encode('utf-8'))
                my_socket.recv(512)
                if error:
                    print('Timeout on: {command}'.format(command=command))
                else:
                    try:
                        received_data = my_socket.recv(512)
                    except KeyboardInterrupt:
                        sys.exit(1)
                    except socket.timeout:
                        print('Timeout on: {command}'.format(command=command))
                if received_data:
                    if self.bruteEmailType == 'RCPT':
                        if re.match('250', str(received_data.decode('utf-8')).split('\n')[1]):
                            print('Found user: {user}'.format(user=command.replace('RCPT TO: ', '')))
                    else:
                        if re.match('250', str(received_data.decode('utf-8'))):
                            print('Found user: {user}'.format(user=command.replace('VRFY ', '')))
                        elif re.match('252', str(received_data.ecode('utf-8'))):
                            print('Found user: {user}'.format(user=command.replace('VRFY ', '')))
                else:
                    print('Did not received any data for command: {command}'.format(command=command))
            except KeyboardInterrupt:
                sys.exit(1)
            except socket.error as socket_error:
                print('Caught exception socket.error: {error}'.format(error=socket_error))
            my_socket.shutdown(2)
            my_socket.close()

    def search_headers(self):
        self.run_requests(self.run_headers, self.urls)

    def run_headers(self):
        while True:
            url = self.queue.get()
            try:
                request = self.session.get(url, verify=False)
                print(request.headers)
            except KeyboardInterrupt:
                sys.exit(1)
            except requests.exceptions.RequestException as requestsError:
                print(requestsError)
            self.queue.task_done()

    def search_dns(self):
        dns_requests = []
        for url in self.urls:
            print(url)
        self.run_requests(self.run_dns, dns_requests)

    def run_dns(self):
        while True:
            url = self.queue.get()
            try:
                request = self.session.get(url, verify=False)
                print(request.headers)
            except KeyboardInterrupt:
                sys.exit(1)
            except requests.exceptions.RequestException as requestsError:
                print(requestsError)
            self.queue.task_done()
