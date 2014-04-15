# Description

# Checks
## File modes
This check ensures that modules are not marked executable. A module is only called by the framework and not directly. The correct file mode is `??`
## Shebang
A module should not have a [Shebang](http://en.wikipedia.org/wiki/Shebang_%28Unix%29) line.
## Nokogiri
Modules should not rely on the Nokogiri GEM. Please use REXML instead.
## Invalid Formats
### CVE
CVE references should be in the format `YYYY-NNNN`
### OSVDB
OSVDB references should only contain numbers
### BID
BID references should only contain numbers
### MSB
OSVDB references should be in the format `MSddd-ddd` (d = digit)
### MIL
Milw0rm references are no longer supported (site suspended)
### EDB
EDB references should only contain numbers
### WVE
BID references should be in the format `dd-dd` (d = digit)
### US-CERT-VU
US-CERT references should only contain numbers
### ZDI
ZDI references should be in the format `dd-ddd` (d = digit)
### URL
If you supply an URL where a short identifiert is available, please use the identifier.

## Old Keywords
Before Metasploit moved to Github the sources were stored in a SVN repository. SVN has support to replace custom variables with current values like the last revision. Since GIT does not support them, the references should be removed from code.