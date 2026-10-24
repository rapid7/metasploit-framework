## Vulnerable Application

This module is not an exploit but rather a reconnaissance tool that integrates with the Shodan search engine API. Shodan is a search engine that indexes Internet-connected devices and services, making it useful for identifying potential targets during penetration testing engagements.

### Requirements

1. **Shodan Account**: A free or paid Shodan account is required
2. **API Key**: You need a Shodan API key, which can be obtained from your account page at https://account.shodan.io/

### Getting a Shodan API Key

1. Visit https://www.shodan.io/
2. Create a free account or log in to your existing account
3. Navigate to https://account.shodan.io/
4. Copy your API key from the account page

**Note**: Free API keys have limitations on the number of results and available filters. Paid accounts provide access to additional features and higher query limits.

## Verification Steps

1. Obtain a Shodan API key from https://account.shodan.io/
2. Start msfconsole
3. Do: `use auxiliary/gather/shodan_search`
4. Do: `set SHODAN_APIKEY [your API key]`
5. Do: `set QUERY [search query]`
6. Do: `run`
7. The module will display search results including IP addresses, ports, cities, countries, and hostnames

## Options

### SHODAN_APIKEY

Your Shodan API key obtained from https://account.shodan.io/. This is a 32-character alphanumeric string and is required for the module to function.

### QUERY

The search query to send to Shodan. This can include keywords, service names, product names, or any text you want to search for. Shodan filters (such as `port:`, `hostname:`, `os:`, `geo:`, `city:`) can be used in queries.

**Examples**:
- `apache` - Find Apache web servers
- `port:22 country:US` - Find SSH servers in the United States
- `product:MySQL` - Find MySQL database servers
- `org:"Target Company"` - Find systems belonging to a specific organization

**Note**: Some filters require a paid Shodan account.

For a complete list of filters, see: https://www.shodan.io/search/filters

### FACETS

List of facets to retrieve aggregated statistics about the search results. Facets provide summary information such as the most common countries, organizations, ports, etc. in the result set.

**Example facets**:
- `country` - Distribution of results by country
- `port` - Most common ports
- `org` - Top organizations
- `os` - Operating system distribution

Multiple facets can be specified, separated by commas. For available facets, see: https://www.shodan.io/search/facets

### OUTFILE

An optional filename to save the search results. Results are saved in a formatted table.

### DATABASE

When set to `true`, the module will add discovered hosts and services to the Metasploit database. This allows you to use the discovered information with other Metasploit modules. (Default: `false`)

### MAXPAGE

Maximum number of pages to retrieve from Shodan. Each page contains up to 100 results. Setting this to a higher value will retrieve more results but will consume more API credits. (Default: `1`)

For free accounts, the maximum number of pages may be limited by your API quota.

### REGEX

A regular expression to filter results. Only results where the IP address, city, country, hostname, or data fields match this pattern will be displayed. (Default: `.*` - matches everything)

**Examples**:
- `192\.168\..*` - Only show results from 192.168.x.x networks
- `New York` - Only show results from New York
- `admin` - Only show results containing "admin" in any field

## Scenarios

### Basic Search for Apache Servers

```
msf6 > use auxiliary/gather/shodan_search
msf6 auxiliary(gather/shodan_search) > set SHODAN_APIKEY 1234567890abcdef1234567890abcdef
SHODAN_APIKEY => 1234567890abcdef1234567890abcdef
msf6 auxiliary(gather/shodan_search) > set QUERY apache
QUERY => apache
msf6 auxiliary(gather/shodan_search) > run

[*] Total: 45678912 on 456790 pages. Showing: 1 page(s)
[*] Collecting data, please wait...

Search Results
==============

IP:Port              City           Country        Hostname
-------              ----           -------        --------
192.0.2.10:80        New York       United States  web1.example.com
192.0.2.15:443       Los Angeles    United States  secure.example.org
192.0.2.20:80        London         United Kingdom server.example.co.uk
192.0.2.25:8080      Tokyo          Japan          app.example.jp
192.0.2.30:80        Berlin         Germany        www.example.de

[*] Auxiliary module execution completed
```

### Search with Multiple Pages and Database Storage

```
msf6 auxiliary(gather/shodan_search) > set QUERY port:22 country:US
QUERY => port:22 country:US
msf6 auxiliary(gather/shodan_search) > set MAXPAGE 3
MAXPAGE => 3
msf6 auxiliary(gather/shodan_search) > set DATABASE true
DATABASE => true
msf6 auxiliary(gather/shodan_search) > run

[*] Total: 2547821 on 25479 pages. Showing: 3 page(s)
[*] Collecting data, please wait...

Search Results
==============

IP:Port              City           Country        Hostname
-------              ----           -------        --------
192.0.2.35:22        Seattle        United States  ssh1.example.com
192.0.2.40:22        Austin         United States  dev.example.com
192.0.2.45:22        Miami          United States  server01.example.net
[... additional results ...]

[*] Auxiliary module execution completed
msf6 auxiliary(gather/shodan_search) > hosts

Hosts
=====

address      mac  name               os_name  os_flavor  os_sp  purpose  info  comments
-------      ---  ----               -------  ---------  -----  -------  ----  --------
192.0.2.35        ssh1.example.com                             device         Added from Shodan
192.0.2.40        dev.example.com                              device         Added from Shodan
192.0.2.45        server01.example.net                         device         Added from Shodan

msf6 auxiliary(gather/shodan_search) > services

Services
========

host         port  proto  name  state  info
----         ----  -----  ----  -----  ----
192.0.2.35   22    tcp          open   Added from Shodan
192.0.2.40   22    tcp          open   Added from Shodan
192.0.2.45   22    tcp          open   Added from Shodan
```

### Search with Facets

```
msf6 auxiliary(gather/shodan_search) > set QUERY nginx
QUERY => nginx
msf6 auxiliary(gather/shodan_search) > set FACETS country,port,org
FACETS => country,port,org
msf6 auxiliary(gather/shodan_search) > run

[*] Total: 15234567 on 152346 pages. Showing facets

Facets
======

Facet    Name           Count
-----    ----           -----
country  US             3456789
country  CN             2345678
country  DE             1234567
port     443            8765432
port     80             6543210
port     8080           987654
org      Amazon.com     543210
org      Google         432109
org      Microsoft      321098

[*] Auxiliary module execution completed
```

### Search with Regex Filtering and Output File

```
msf6 auxiliary(gather/shodan_search) > set QUERY product:MySQL
QUERY => product:MySQL
msf6 auxiliary(gather/shodan_search) > set REGEX 192\.0\.2\..*
REGEX => 192\.0\.2\..*
msf6 auxiliary(gather/shodan_search) > set OUTFILE /tmp/mysql_targets.txt
OUTFILE => /tmp/mysql_targets.txt
msf6 auxiliary(gather/shodan_search) > run

[*] Total: 4567890 on 45679 pages. Showing: 1 page(s)
[*] Collecting data, please wait...

Search Results
==============

IP:Port              City           Country        Hostname
-------              ----           -------        --------
192.0.2.50:3306      Chicago        United States  db1.example.com
192.0.2.55:3306      Boston         United States  mysql.example.org

[*] Saved results in /tmp/mysql_targets.txt
[*] Auxiliary module execution completed
```

### Targeting a Specific Organization

```
msf6 auxiliary(gather/shodan_search) > set QUERY org:"Acme Corporation"
QUERY => org:"Acme Corporation"
msf6 auxiliary(gather/shodan_search) > set DATABASE true
DATABASE => true
msf6 auxiliary(gather/shodan_search) > run

[*] Total: 1234 on 13 pages. Showing: 1 page(s)
[*] Collecting data, please wait...

Search Results
==============

IP:Port              City           Country        Hostname
-------              ----           -------        --------
192.0.2.60:80        San Francisco  United States  www.acme.com
192.0.2.65:443       San Francisco  United States  portal.acme.com
192.0.2.70:22        San Francisco  United States  gateway.acme.com
192.0.2.75:3389      San Francisco  United States  rdp.acme.com

[*] Auxiliary module execution completed
```

## Notes

- **API Limitations**: Free Shodan accounts have limited API credits and may restrict certain filters. Consider upgrading to a paid account for full functionality.
- **Rate Limiting**: Shodan enforces rate limits on API requests. If you receive errors, wait a few moments before trying again.
- **Ethical Use**: This module should only be used for authorized penetration testing or security research. Scanning or accessing systems without permission is illegal.
- **Data Freshness**: Shodan's database is periodically updated, so results may not reflect the current state of all systems.

## References

- [Shodan Website](https://www.shodan.io/)
- [Shodan API Documentation](https://developer.shodan.io/api)
- [Shodan Search Filters](https://www.shodan.io/search/filters)
- [Shodan Search Facets](https://www.shodan.io/search/facet)
