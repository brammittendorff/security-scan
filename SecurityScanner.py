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

    """A simple security scanner"""

    def __init__(self):
        requests.packages.urllib3.disable_warnings()
        self.urls = []
        self.queue = None
        self.concurrent = 200
        self.session = requests.Session()

    def runRequests(self, runFunction, listRequests):
        self.queue = Queue.Queue(self.concurrent * 2)
        # call method by name in string
        method = getattr(SecurityScanner, runFunction)
        # unbound to bound method
        boundMethod = method.__get__(self, SecurityScanner)
        for _ in range(self.concurrent):
            t = threading.Thread(name='run_requests', target=boundMethod)
            t.daemon = True
            t.start()
        try:
            for request in listRequests:
                self.queue.put(request)
            self.queue.join()
        except KeyboardInterrupt:
            sys.exit(1)

    def runCommands(self, runFunction, listCommands):
        # call method by name in string
        method = getattr(SecurityScanner, runFunction)
        # unbound to bound method
        boundMethod = method.__get__(self, SecurityScanner)
        for command in listCommands:
            boundMethod(command)

    def addUrl(self, url):
        if isinstance(url, str):
            correctUrl = urlparse(url).scheme + '://' + urlparse(url).netloc
            print("Scanning: %s" % (correctUrl))
            self.urls.append(correctUrl)

    def addFile(self, fileLocation):
        # strip /n
        fileLocation = [word.strip() for word in fileLocation]
        for url in fileLocation:
            correctUrl = urlparse(url).scheme + '://' + urlparse(url).netloc
            print("Scanning: %s" % (correctUrl))
            self.urls.append(correctUrl)

    def searchDirectories(self):
        directoryRequests = []
        directoryFileName = 'resources/directories.txt'
        if(os.path.isfile(directoryFileName)):
            for url in self.urls:
                with open(directoryFileName) as directoryFile:
                    for filename in directoryFile:
                        directoryRequests.append(url + '/' + filename)
            self.runRequests('resultDirectories', directoryRequests)
        else:
            print("File '%s' does not exist" % (directoryFileName))

    def resultDirectories(self):
        while True:
            url = self.queue.get()
            try:
                request = self.session.get(url, verify=False)
                if(request.status_code != 404):
                    print("%s status on url: %s" % (request.status_code, url.rstrip()))
            except KeyboardInterrupt:
                sys.exit(1)
            except requests.exceptions.RequestException as requestsError:
                print(requestsError)
            self.queue.task_done()

    def searchEmailserver(self):
        socketEmailCommands = []
        directoryUnixUsers = 'resources/unix-users.txt'
        if(os.path.isfile(directoryUnixUsers)):
            with open(directoryUnixUsers) as directoryFile:
                for unixUser in directoryFile:
                    socketEmailCommands.append('VRFY ' + unixUser)
        self.runCommands('resultEmailserver', socketEmailCommands)

    def resultEmailserver(self, smtpCommand):
        for url in self.urls:
            mySocket = socket.socket()
            mySocket.settimeout(10)
            receivedData = 0
            ipAddress = socket.gethostbyname(urlparse(url).netloc)
            try:
                mySocket.connect((ipAddress, 25))
                error = mySocket.sendall(smtpCommand+"\n")
                mySocket.recv(512)
                if error:
                    print("Timeout on: %s" % (smtpCommand))
                else:
                    try:
                        receivedData = mySocket.recv(512)
                    except socket.timeout:
                        print("Timeout on: %s" % (smtpCommand))
                if receivedData:
                    if re.match("250", receivedData):
                        print("Found user: %s" % (smtpCommand.replace('VRFY ', '')))
                    elif re.match("252", receivedData):
                        print("Found user: %s" % (smtpCommand.replace('VRFY ', '')))
                else:
                    print("Did not received data!")
            except KeyboardInterrupt:
                sys.exit(1)
            except socket.error as socketError:
                print("Caught exception socket.error: %s" % socketError)
            mySocket.shutdown(2)
            mySocket.close()

    def searchHeaders(self):
        self.runRequests('resultHeaders', self.urls)

    def resultHeaders(self):
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

    def searchDNS(self):
        dnsRequests = []
        for url in self.urls:
            print(url)
        self.runRequests('resultDNS', dnsRequests)

    def resultDNS(self):
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
