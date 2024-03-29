# Security Scan

This is a quick scan to check the most known vulnerabilities in your web application.

## Installation

### python2

Run the following command to install all external packages:

```pip install -r requirements.txt```

### python3

Run the following command to install all external packages:

```pip3 install -r requirements.txt```

## Usage

### python2

```python Scan.py```

### python3

```python3 Scan.py```

## Todo

#### HEADERS

Check for the following headers:

 - X-Frame-Options
 - X-XSS-Protection
 - X-Content-Type-Options
 - Strict-Transport-Security
 - Content-Security-Policy
 - Public-Key-Pins

#### DNS

Use the following tools:

 - subbrute
 - dnsrecon
 -

#### SSL

 - testssl.sh
 - qualys

#### OPEN SOURCE SCANNERS

 - droopescan
 - magescan
 - wpscan
 - vbscan

#### BENCHMARKS

##### requests

 - boom
 - ab
