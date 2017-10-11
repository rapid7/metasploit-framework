This module downloads PDF files and extracts the author's name from the document metadata.

## Verification Steps

  1. Start `msfconsole`
  2. Do: `use auxiliary/gather/http_pdf_authors`
  3. Do: `set URL [URL]`
  4. Do: `run`


## Options

**URL**

The URL of a PDF to analyse.

**URL_LIST**

File containing a list of PDF URLs to analyze.

**OUTFILE**

File to store extracted author names.


## Scenarios

### URL

  ```
  msf auxiliary(http_pdf_authors) > set url http://127.0.0.1/test4.pdf
  url => http://127.0.0.1/test4.pdf
  msf auxiliary(http_pdf_authors) > run

  [*] Processing 1 URLs...
  [*] Downloading 'http://127.0.0.1/test4.pdf'
  [*] HTTP 200 -- Downloaded PDF (38867 bytes)
  [+] PDF Author: Administrator
  [*] 100.00% done (1/1 files)

  [+] Found 1 authors: Administrator
  [*] Auxiliary module execution completed
  ```

### URL_LIST with OUTFILE

  ```
  msf auxiliary(http_pdf_authors) > set outfile /root/output
  outfile => /root/output
  msf auxiliary(http_pdf_authors) > set url_list /root/urls
  url_list => /root/urls
  msf auxiliary(http_pdf_authors) > run

  [*] Processing 8 URLs...
  [*] Downloading 'http://127.0.0.1:80/test.pdf'
  [*] HTTP 200 -- Downloaded PDF (89283 bytes)
  [*]  12.50% done (1/8 files)
  [*] Downloading 'http://127.0.0.1/test2.pdf'
  [*] HTTP 200 -- Downloaded PDF (636661 bytes)
  [+] PDF Author: sqlmap developers
  [*]  25.00% done (2/8 files)
  [*] Downloading 'http://127.0.0.1/test3.pdf'
  [*] HTTP 200 -- Downloaded PDF (167478 bytes)
  [+] PDF Author: Evil1
  [*]  37.50% done (3/8 files)
  [*] Downloading 'http://127.0.0.1/test4.pdf'
  [*] HTTP 200 -- Downloaded PDF (38867 bytes)
  [+] PDF Author: Administrator
  [*]  50.00% done (4/8 files)
  [*] Downloading 'http://127.0.0.1/test5.pdf'
  [*] HTTP 200 -- Downloaded PDF (34312 bytes)
  [+] PDF Author: ekama
  [*]  62.50% done (5/8 files)
  [*] Downloading 'http://127.0.0.1/doesnotexist.pdf'
  [*] HTTP 404 -- Downloaded PDF (289 bytes)
  [-] Could not parse PDF: PDF is malformed
  [*]  75.00% done (6/8 files)
  [*] Downloading 'https://127.0.0.1/test.pdf'
  [-] Connection failed: Failed to open TCP connection to 127.0.0.1:443 (Connection refused - connect(2) for "127.0.0.1" port 443)
  [*] Downloading 'https://127.0.0.1:80/test.pdf'
  [-] Connection failed: SSL_connect returned=1 errno=0 state=unknown state: unknown protocol

  [+] Found 4 authors: sqlmap developers, Evil1, Administrator, ekama
  [*] Writing data to /root/output...
  [*] Auxiliary module execution completed
  ```

