import requests

class SecurityScanner:

    """A simple security scanner"""

    def __init__(self):
        self.data = []
        self.session = requests.Session()

    def addUrl(self, url):
        if isinstance(url, str):
            self.data.append(url)

    def addFile(self, fileLocation):
        # strip /n
        fileLocation = [word.strip() for word in fileLocation]
        for url in fileLocation:
            self.data.append(url)

    def searchHeaders(self):
        for url in self.data:
            request = self.session.get(url)
            print(request.headers)

    def scanDNS(self):
        for url in self.data:
            print(self.session.get(url))
