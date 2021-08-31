## Vulnerable Application
This module uses the ZoomEye API to conduct either a host search or a web search (web servers only),
and output the information gathered into a table which can then be saved for later use.

## Note
You need to register for ZoomEye by creating an account with Telnet404. You can register for a temp email
at https://temp-mail.org and get a temp phone number to recieve the SMS's needed to sign up at https://smsreceivefree.com.

Then browse to https://www.zoomeye.org, click on the `Register` button, and follow the steps from there.

## Verification Steps

1. Start `msfconsole`
2. Do: `use/auxiliary/gather/zoomeye`
3. Do: `set USERNAME <your username>`
4. Do: `set PASSWORD <your password>`
5. Do: `set ZOOMEYE_DORK ''`
6. Do: `run`
7. If you see 'Logged in to zoomeye', despite an internal error coming from the null dork, it means that the creds are valid.

## Options

### RESOURCE
Can be set to either `host` or `web`. `host` looks for any kind of servers,
whilst `web` restricts the search to only web (http/https) servers.

### DATABASE
Records the output to the database if set. If using `host` search, the ip, hostname, and
OS are recorded within the `hosts` table. Additionally, the IP, port, protocol name,
service name and version, and any additional information received are recorded into
the `services` table.

### FACETS
Just show a summary of (all) the results concerning a particular facet.

For host searches, you can filter results by using the following facets:
  - app
  - device
  - service
  - os
  - port
  - country
  - city

For web searches you can filter results by using the following facets:
  - webapp
  - component
  - framework
  - frontend
  - server
  - waf
  - os
  - country
  - city

### MAXPAGE
The maximum number of pages to collect, expressed as an integer.

### OUTFILE
The file to save the output to, if specified.

### USERNAME
The username to log into ZoomEye as.

### PASSWORD
The password to log into ZoomEye as.

### ZOOMEYE_DORK
The query/dork to run on ZoomEye. This must be composed of keywords and search
filters from the list located [here](https://www.zoomeye.org/doc#search-filters).

The request must be enclosed with single quotes and any search terms that
you want to match explicitly on must be enclosed within double quotes. You
must put the filters before any keyword. An example would be: `'country:"FR"+decathlon'`.

Note that if you don't use double quotes to delimit your search filters, then the search filters will not
use the correct data from your query and likely won't end up finding anything. Additionally, putting keywords
first, as mentioned previously, will not return any results, so be wary of this.

## Scenarios
### Host Search with XXXXX and XXXX
### Web Search On XXXX With XXXX
