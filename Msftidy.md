## Description

# Checks
## File modes
This check ensures that modules are not marked executable. A module is only called by the framework and not directly. The correct file mode is `0644`, which will ensure that other users are only able to read the file, and that the current user is only able to read and write the file, not execute it.
## Shebang
A module should not have a [Shebang](http://en.wikipedia.org/wiki/Shebang_%28Unix%29) line.
## Nokogiri
Modules should not rely on the Nokogiri GEM. Please use REXML instead.
## Invalid Formats
### CVE
CVE references should be in the format `YYYY-NNNN`
### BID
BID references should only contain numbers
### MSB
OSVDB references should be in the format `MSddd-ddd` (d = digit)
### MIL
Milw0rm references are no longer supported (site suspended)
### EDB
EDB references should only contain numbers
### US-CERT-VU
US-CERT references should only contain numbers
### ZDI
ZDI references should be in the format `dd-ddd` or `dd-dddd` (d = digit)
### URL
If you supply an URL where a short identifier is available, please use the identifier.

## Old Keywords
Before Metasploit moved to Github the sources were stored in a SVN repository. SVN has support to replace custom variables with current values like the last revision. Since GIT does not support them, the references should be removed from code.

## Verbose
You should not define a VERBOSE option in your module. A VERBOSE option is already provided by the framework. To make use of the VERBOSE setting, you can use methods like `vprint_status` and `vprint_error`

## Badchars
This checks looks for bad characters in the module title. If you encounter this error, please replace the characters.

## File Extension
All modules should have a `.rb` file extension to be loaded by the framework.

## Old Rubies
This check checks the file for syntax errors with old Ruby versions. By default this check will not run. To execute this check you need to set the environment variable `MSF_CHECK_OLD_RUBIES`.

## Ranking
This check ensures you added the correct [[Exploit Ranking]] to your module.

## Disclosure Date
Date format needs to be `Month Day, YYYY`. Example: `Jan 01, 2014`

## Title Casing
This check ensures you used the correct case in your title.

## Bad Terms
This checks for the correct use of the terms `Stack Buffer overflow` and `Stack Exhaustion`. See ["Stack exhaustion" vs "Stack buffer overflow"](https://msrc-blog.microsoft.com/2009/01/28/stack-overflow-stack-exhaustion-not-the-same-as-stack-buffer-overflow/) for more information.

## Function Arguments
If you define a function which defines a lot of input arguments, the check ensures you use a hash instead.

## Line Check
### Unicode
Your module must not contain Unicode characters.

### Spaces at EOL
Your module must not contain spaces at the end of a line.

### Mixed Tab Spaces
Your module contains Tabs and Spaces in one line. Only spaces should be used

### Tabs
Your module should not use tabs for intending code. Please use spaces instead.

### Carriage return
The specified line only contains a carriage return (`\r`) at the end of line. Please change to a normal linebreak (`\n` or `\r\n`).

### File.open
You used a File.open call without specifying a binary mode???

### Load
You used the `load` command in your module. This is not required since the framework loads all necessary files for you.

### STDOUT
Modules should not write directly to stdout. Please use the `print_*` functions instead.

### Modified datastore
Datastore options (options set by the user) should not be modified in code. If you need to change some values use local variables instead.

### Set-Cookie
The Set-Cookie header should not be parsed by your code. You can use the API call `res.get_cookies` insteady which already handles some special cases and ensures a clean header.

### Auxiliary Rand
Auxiliary modules should have no Rank. Only Exploits and Payloads should have a Rank attribute.

## Snake Case
This check ensures your module filename is in [Snake Case](http://en.wikipedia.org/wiki/Snake_case)

## Old License
This check checks for the old Metasploit license in the module header. You can use the tool `ruby tools/dev/resplat.rb <filename>` to convert the file.

## VULN Codes
This check ensures only known CheckCodes are returned by the `check` function.

## vars_get
When using `send_request_cgi` or `send_request_raw` the URL supplied should not contain GET Parameter. Please provide the Parameter via the `vars_get` hash.

bad:
```ruby
res = send_request_raw({
  'uri' => uri_base + '/upload.php?type=file&folder=' + folder
})
```

good:
```ruby
res = send_request_raw({
  'uri' => uri_base + '/upload.php',
  'vars_get' => {
    'type' => 'file',
    'folder' => folder
  }
})
```
