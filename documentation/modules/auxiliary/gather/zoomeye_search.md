## Introduction
This module uses the zoomeye API to retrieve multiple informations from either 'host' or 'web' source, the latter being a search based on web servers only.

## Note
You need to register for zoomeye credentials with an email and mobile phone at zoomeye.org.

## Verification Steps

1. Start `msfconsole`
2. Do: `use/auxiliary/gather/zoomeye`
3. Do: `set USERNAME <your username>`
4. Do: `set PASSWORD <your password>`
5. Do: `set ZOOMEYE_DORK ''`
6. Do: `run`
7. If you see 'Logged in to zoomeye', despite an internal error coming from the null dork, it means that the creds are valid.

## Options
 RESOURCE <host | web>
  Look for any kind of servers or only web (http/https) servers.
 DATABASE <true | false>
  Records the output to the database.
  If using 'host' search, the ip, hostname, and os are recorded within the hosts table.
  And the ip, port, protocol name, service+version, and additional infos are recorded into the services table.
 FACETS (host search) <app | device | service | os | port | country | city>
 FACETS (web search) <webapp | component | framework | frontend | server | waf | os | country | city>
  Just show a summary of (all) the results concerning a particular facet.
 MAXPAGE <integer>:
  The maximum number of pages to collect.
 OUTFILE <path>
  Save the output to a file.
 USERNAME <your username>
  The username.
 PASSWORD <your password>
  The password.
 ZOOMEYE_DORK <zoomeye query>
  This must be composed of keywords and search filters as listed here: "https://www.zoomeye.org/doc#search-filters"
  The request must be enclose with single quotes and splited with double quotes, you must put the filters before any keyword as in :'country:"FR"+decathlon'.
  Note that if you don't use double quotes to delimit your search filters, it will include the remining of the query and so probably wouldn't find anything, and puting the keyword first will just not return any results.

## Scenarios
 Host search:
  It is better for a broad search and usually returns a higher amount of results, better when looking for services vulnerability since it lists them.
 Web search:
  It works much like google dorks, targeting the web service and being able to search for http content via filters. The search will output the database application if any.
