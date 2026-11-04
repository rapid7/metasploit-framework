## Vulnerable Application

This module exploits an unauthenticated arbitrary file access vulnerability in Atlassian web-resource downloads being tracked as [CVE-2026-21589](https://confluence.atlassian.com/security/cve-2026-21589-arbitrary-file-access-vulnerability-impacts-multiple-products-1870495748.html).

The vulnerability allows for an unauthenticated attacker to retrieve files within the Atlassian web application directory through path traversal.

Detection and request paths are currently only implemented for:

* Jira Data Center
* Confluence Data Center
* Bitbucket Data Center

The detection paths and product signatures are based on [watchTowr labs poc](https://github.com/watchtowrlabs/watchTowr-vs-Atlassian-CVE-2026-21589).

Live testing against Atlassian product instances has not been yet performed for this module.

## Verification Steps

1. Start `msfconsole`.
2. Load the module:

   ```
   use auxiliary/scanner/http/atlassian_cve_2026_21589_file_read
   ```

3. Set the target:

   ```
   set RHOSTS <target>
   ```

4. If the application is installed under a context path, configure `TARGETURI`:

   ```
   set TARGETURI /jira/
   ```

5. Select a product, or leave the default `Auto` setting:

   ```
   set PRODUCT Auto
   ```

6. Run the vulnerability check:

   ```
   check
   ```

7. Retrieve the default product-specific marker file:

   ```
   run
   ```

8. To retrieve a different file relative to the application web root:

   ```
   set FILEPATH WEB-INF/classes/example.properties
   run
   ```

9. Retrieved non-empty HTTP 200 responses are saved as Metasploit loot.

## Options

### TARGETURI

The base path of the Atlassian application. Defaults to `/`.

### PRODUCT

The Atlassian product to target. Supported values are:

* `Auto` (default): tries Jira, Confluence, and Bitbucket.
* `Jira`
* `Confluence`
* `Bitbucket`

### FILEPATH

The file path relative to the Atlassian application web root.

When empty, the module retrieves the product-specific marker file used for detection:

* Jira: `WEB-INF/web.xml`
* Confluence: `WEB-INF/web.xml`
* Bitbucket: `WEB-INF/urlrewrite.xml`

When a custom path is supplied, the module first detects the product and then makes a separate request for the requested file.

A non-empty HTTP 200 response is saved as loot. The module does not independently verify the contents of custom-file responses; an HTTP 200 response may contain an application error page rather than the requested file.

## Scenarios

### Automatic product detection and marker retrieval

```
msf > use auxiliary/scanner/http/atlassian_cve_2026_21589_file_read
msf auxiliary(scanner/http/atlassian_cve_2026_21589_file_read) > set RHOSTS <target>
msf auxiliary(scanner/http/atlassian_cve_2026_21589_file_read) > check
msf auxiliary(scanner/http/atlassian_cve_2026_21589_file_read) > run
```

### Retrieving a custom file

```
msf auxiliary(scanner/http/atlassian_cve_2026_21589_file_read) > set PRODUCT Jira
msf auxiliary(scanner/http/atlassian_cve_2026_21589_file_read) > set FILEPATH WEB-INF/classes/example.properties
msf auxiliary(scanner/http/atlassian_cve_2026_21589_file_read) > run
```

Custom-file responses are saved as loot but are not independently verified.
