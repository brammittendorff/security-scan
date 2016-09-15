import requests
import sys
import Queue
import threading

class SecurityScanner:

    """A simple security scanner"""

    def __init__(self):
        requests.packages.urllib3.disable_warnings()
        self.urls = []
        self.concurrent = 200
        self.queue = None
        self.session = requests.Session()

    def runRequests(self, function, listRequests):
        self.queue = Queue.Queue(self.concurrent * 2)
        # call method by name in string
        method = getattr(SecurityScanner, function)
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

    def addUrl(self, url):
        if isinstance(url, str):
            self.urls.append(url)

    def addFile(self, fileLocation):
        # strip /n
        fileLocation = [word.strip() for word in fileLocation]
        for url in fileLocation:
            self.urls.append(url)

    def searchHeaders(self):
        headerRequests = []
        self.runRequests('resultHeaders', headerRequests)

    def resultHeaders(self):
        url = self.queue.get()
        request = self.session.get(url)
        print(request.headers)
        self.queue.task_done()


    def searchDNS(self):
        dnsRequests = []
        self.runRequests('resultDNS', dnsRequests)

    def resultDNS(self):
        url = self.queue.get()
        request = self.session.get(url)
        print(request.headers)
        self.queue.task_done()
