# Reference Modules for test_env

## Selection Criteria
- Cover different service types: Java message broker (ActiveMQ), web application (WordPress)
- Have clear, single-port (or well-defined multi-port) mappings
- Have existing Docker images with known vulnerable versions
- Demonstrate different health check patterns (API endpoint, login page, root page)
- Include both authenticated and unauthenticated exploit scenarios

---

## Module 1: Apache ActiveMQ Jolokia RCE (Mentor Suggested)
- **Path:** `exploit/multi/http/apache_activemq_jolokia_rce`
- **Type:** Java web application (JMX-over-HTTP)
- **Ports:** 8161 (web console / Jolokia API)
- **Profile:** `default`
- **Health Check:** HTTP GET `/api/jolokia/` expecting 200, or GET `/` expecting 200
- **Why:** h00die suggested PR #21497. Has a verified Docker one-liner. Real-world CVE-2026-34197.
- **VulnerableEnvironment Definition:** `activemq`
- **Docker Image:** `apache/activemq-classic:5.18.6`
- **Docker Run:** `docker run -d --name activemq -p 8161:8161 -p 61616:61616 apache/activemq-classic:5.18.6`
- **Credentials:** admin / admin
- **Exploit Context:** Requires authenticated Jolokia access; `TARGETURI` typically `/api/jolokia/`

---

## Module 2: WordPress Admin Shell Upload
- **Path:** `exploit/unix/webapp/wp_admin_shell_upload`
- **Type:** Web application / CMS
- **Port:** 80
- **Health Check:** Two-stage — see **Provisioning** below. Base `health_check` is HTTP GET `/` expecting **[200, 302]** (the container returns `302` to `/wp-admin/install.php` on first boot; this is a valid "server is up" signal, not a failure). A separate `verify` check confirms the app is actually usable after provisioning: HTTP GET `/wp-login.php` expecting `200` and containing `user_login`.
- **Why:** Pre-built vulnerable image exists (`eystsen/vulnerablewordpress`), widely used in security testing, self-contained (bundles its own MySQL, no external DB link required).
- **VulnerableEnvironment Definition:** `wordpress`
- **Docker Image:** `eystsen/vulnerablewordpress`
- **Credentials:** admin / admin
- **Exploit Context:** Authenticated admin access; uploads PHP shell via theme/plugin editor
- **Provisioning:** This image does **not** start ready-to-use. The Dockerfile configures `wp-config.php` to point at a `wordpress` database but never creates the schema or an admin account — WordPress boots straight into the install wizard (`/wp-admin/install.php`), and stays there indefinitely with no admin/admin login until the wizard is submitted. `wordpress.yml` now defines a `provision` step (`type: http_post`, submits `install.php?step=2` with the credentials from `credentials.default`) that runs once the base health check passes, followed by the `verify` check above before the environment is registered as ready. See `04-environment-schema.md` for the general `provision`/`verify` schema this relies on.

---

## Module 3: Apache ActiveMQ OpenWire RCE (CVE-2023-46604)
- **Path:** `exploit/multi/misc/apache_activemq_rce_cve_2023_46604`
- **Type:** Java message broker (raw OpenWire protocol, not HTTP)
- **Port:** 61616 (broker)
- **Profile:** `broker-only`
- **Health Check:** Uses activemq.yml's broker-only profile (tcp on 61616). The default HTTP check fails against this image due to AMQ-8018 (web console binds 127.0.0.1 since 5.16.0). Since the module only needs OpenWire, a TCP profile is accurate and matches the schema guidance to create a new profile when the health check type differs.
- **Why this module specifically:** it's the first real proof that `activemq.yml` works as a genuine shared definition across independent modules, not just independent files that happen to use the same schema. Two unrelated CVEs, two different attack surfaces (HTTP/Jolokia vs. raw OpenWire), one definition file.
- **VulnerableEnvironment Definition:** `activemq` (same file as Module 1 — nothing duplicated: image family, credentials, health check, and `ci.exploit`'s recommended payload are all inherited unchanged)
- **Docker Image:** `dinifarb/activemq:5.18.2`
- **Credentials:** none required — this CVE is unauthenticated
- **Exploit Context:** Unauthenticated; sends crafted OpenWire packet that loads attacker-hosted Spring XML config. Requires TARGET => 1 (Linux) override — default target is Windows.

---

## Module 4: HTTP Version Scanner (Auxiliary)
- **Path:** `auxiliary/scanner/http/http_version`
- **Type:** Auxiliary scanner (no session produced)
- **Port:** 80
- **Profile:** `default`
- **Health Check:** HTTP GET `/` expecting 200
- **Why:** Trivial scanner module suggested by mentor. Demonstrates that `test_env` works for auxiliary modules, not just exploits. Produces `[+]` output (server banner) without requiring a shell.
- **VulnerableEnvironment Definition:** `httpd` (shared with http_header and robots_txt)
- **Docker Image:** `docker.io/library/httpd:2.4.57`
- **Credentials:** none required
- **Scanner Context:** Detects HTTP server version from response headers. No payload, no session.

---

## Module 5: HTTP Header Scanner (Auxiliary)
- **Path:** `auxiliary/scanner/http/http_header`
- **Type:** Auxiliary scanner (no session produced)
- **Port:** 80
- **Profile:** `default`
- **Health Check:** HTTP GET `/` expecting 200
- **Why:** Reuses the same `httpd` definition as `http_version`, proving shared definitions work across multiple independent auxiliary modules.
- **VulnerableEnvironment Definition:** `httpd`
- **Docker Image:** `docker.io/library/httpd:2.4.57`
- **Credentials:** none required
- **Scanner Context:** Displays HTTP response headers. Uses `IGN_HEADER`, `HTTP_METHOD`, and `TARGETURI` options.

---

## Module 6: HTTP Robots.txt Scanner (Auxiliary)
- **Path:** `auxiliary/scanner/http/robots_txt`
- **Type:** Auxiliary scanner (no session produced)
- **Port:** 80
- **Profile:** `default`
- **Health Check:** HTTP GET `/` expecting 200
- **Why:** Third auxiliary module reusing `httpd`. Demonstrates that shared definitions scale to many modules without duplication.
- **VulnerableEnvironment Definition:** `httpd`
- **Docker Image:** `docker.io/library/httpd:2.4.57`
- **Credentials:** none required
- **Scanner Context:** Detects and analyzes `robots.txt` content. Uses `PATH` option.

---

## Module 7: SSH Version Scanner (Auxiliary)
- **Path:** `auxiliary/scanner/ssh/ssh_version`
- **Type:** Auxiliary scanner (no session produced)
- **Port:** 22
- **Profile:** `default`
- **Health Check:** TCP connect on port 22 (SSH daemon accepts connections immediately)
- **Why:** Demonstrates non-HTTP auxiliary scanner with a different health check type (`tcp` instead of `http`). Produces `[+]` output with SSH banner and encryption details.
- **VulnerableEnvironment Definition:** `openssh`
- **Docker Image:** `docker.io/rastasheep/ubuntu-sshd:16.04`
- **Credentials:** root / root (defined in YAML for completeness, but scanner does not use them)
- **Scanner Context:** Detects SSH version and supported ciphers. No payload, no session.


