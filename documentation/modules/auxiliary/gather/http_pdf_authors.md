This module downloads PDF documents and extracts the author's name from the document metadata.


## Verification Steps

  1. Start `msfconsole`
  2. Do: `use auxiliary/gather/http_pdf_authors`
  3. Do: `set URL [URL]`
  4. Do: `set URL_TYPE [pdf|html]`
  5. Do: `run`


## Options

**URL**

The target URL.

**URL_LIST**

File containing a list of URLs.

If both a `URL` and `URL_LIST` options are specified, the module will favor the URL. To use the `URL_LIST`, clear the `URL` with `unset URL`.

**URL_TYPE**

The type of URL(s) specified (Accepted: `pdf`, `html`)

By specifying `pdf` for the `URL_TYPE`, the module will treat the specified URL(s) as PDF documents. The module will download the documents and extract the author's name from the document metadata.

By specifying `html` for the `URL_TYPE`, the module will treat the specified URL(s) as HTML pages. The module will scrape the pages for links to PDF documents, download the PDF documents, and extract the author's name from the document metadata.

**OUTFILE**

File to store extracted author names.


## Scenarios

### Extracting author names from PDF URLs

  ```
  msf auxiliary(http_pdf_authors) > set url_type pdf
  url_type => pdf
  msf auxiliary(http_pdf_authors) > set url_list /root/urls
  url_list => /root/urls
  msf auxiliary(http_pdf_authors) > run

  [*] Processing 8 URLs...
  [*] Downloading 'http://127.0.0.1:80/test.pdf'
  [*] - HTTP 200 - 89283 bytes
  [*]  12.50% done (1/8 files)
  [*] Downloading 'http://127.0.0.1/test2.pdf'
  [*] - HTTP 200 - 636661 bytes
  [+] PDF Author: sqlmap developers
  [*]  25.00% done (2/8 files)
  [*] Downloading 'http://127.0.0.1/test3.pdf'
  [*] - HTTP 200 - 167478 bytes
  [+] PDF Author: Evil1
  [*]  37.50% done (3/8 files)
  [*] Downloading 'http://127.0.0.1/test4.pdf'
  [*] - HTTP 200 - 38867 bytes
  [+] PDF Author: Administrator
  [*]  50.00% done (4/8 files)
  [*] Downloading 'http://127.0.0.1/test5.pdf'
  [*] - HTTP 200 - 34312 bytes
  [+] PDF Author: ekama
  [*]  62.50% done (5/8 files)
  [*] Downloading 'http://127.0.0.1/doesnotexist.pdf'
  [*] - HTTP 404 - 289 bytes
  [-] Could not parse PDF: PDF is malformed
  [*]  75.00% done (6/8 files)
  [*] Downloading 'https://127.0.0.1/test.pdf'
  [-] Connection failed: Failed to open TCP connection to 127.0.0.1:443 (Connection refused - connect(2) for "127.0.0.1" port 443)
  [*] Downloading 'https://127.0.0.1:80/test.pdf'
  [-] Connection failed: SSL_connect returned=1 errno=0 state=unknown state: unknown protocol

  [+] Found 4 authors: sqlmap developers, Evil1, Administrator, ekama
  [*] Auxiliary module execution completed
  ```

### Extracting PDF links from HTML

  ```
  msf auxiliary(http_pdf_authors) > set url_type html
  url_type => html
  msf auxiliary(http_pdf_authors) > set url_list /root/urls2
  url_list => /root/urls2
  msf auxiliary(http_pdf_authors) > run

  [*] Processing 2 URLs...
  [*] Downloading 'http://127.0.0.1/test/links.html'
  [*] - HTTP 200 - 310 bytes
  [*]  50.00% done (1/2 files)
  [*] Downloading 'http://127.0.0.1/index.html'
  [*] - HTTP 200 - 177 bytes
  [*] 100.00% done (2/2 files)

  [+] Found links to 7 PDF files:
  http://127.0.0.1/test1.pdf
  http://127.0.0.1/test2.pdf
  http://127.0.0.1/test3.pdf
  http://127.0.0.1/test4.pdf
  http://127.0.0.1/test5.pdf
  http://127.0.0.1/test5.pdf?query=string&
  http://127.0.0.1/test/doesnotexist.pdf

  [*] Processing 7 URLs...
  [*] Downloading 'http://127.0.0.1/test1.pdf'
  [*] - HTTP 404 - 282 bytes
  [-] Could not parse PDF: PDF is malformed
  [*]  14.29% done (1/7 files)
  [*] Downloading 'http://127.0.0.1/test2.pdf'
  [*] - HTTP 200 - 636661 bytes
  [+] PDF Author: sqlmap developers
  [*]  28.57% done (2/7 files)
  [*] Downloading 'http://127.0.0.1/test3.pdf'
  [*] - HTTP 200 - 167478 bytes
  [+] PDF Author: Evil1
  [*]  42.86% done (3/7 files)
  [*] Downloading 'http://127.0.0.1/test4.pdf'
  [*] - HTTP 200 - 38867 bytes
  [+] PDF Author: Administrator
  [*]  57.14% done (4/7 files)
  [*] Downloading 'http://127.0.0.1/test5.pdf'
  [*] - HTTP 200 - 34312 bytes
  [+] PDF Author: ekama
  [*]  71.43% done (5/7 files)
  [*] Downloading 'http://127.0.0.1/test5.pdf?query=string&'
  [*] - HTTP 200 - 34312 bytes
  [+] PDF Author: ekama
  [*]  85.71% done (6/7 files)
  [*] Downloading 'http://127.0.0.1/test/doesnotexist.pdf'
  [*] - HTTP 404 - 294 bytes
  [-] Could not parse PDF: PDF is malformed
  [*] 100.00% done (7/7 files)

  [+] Found 4 authors: sqlmap developers, Evil1, Administrator, ekama
  [*] Auxiliary module execution completed
  ```

