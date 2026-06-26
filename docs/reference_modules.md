# Reference Modules for test_env

## Selection Criteria
- Cover different service types: Java message broker (ActiveMQ), CI server (Jenkins), CMS (Drupal)
- Have clear, single-port (or well-defined multi-port) mappings
- Have existing Docker images with known vulnerable versions
- Demonstrate different health check patterns (API endpoint, login page, root page)
- Include both authenticated and unauthenticated exploit scenarios

---

## Module 1: Apache ActiveMQ Jolokia RCE (Mentor Suggested)
- **Path:** `exploit/multi/http/apache_activemq_jolokia_rce`
- **Type:** Java web application (JMX-over-HTTP)
- **Ports:** 8161 (web console / Jolokia API), 61616 (OpenWire broker)
- **Health Check:** HTTP GET `/api/jolokia/` expecting 200, or GET `/` expecting 200
- **Why:** h00die suggested PR #21497. Has a verified Docker one-liner. Real-world CVE-2026-34197.
- **VulnEnv Definition:** `activemq`
- **Docker Image:** `apache/activemq-classic:5.18.6`
- **Docker Run:** `docker run -d --name activemq -p 8161:8161 -p 61616:61616 apache/activemq-classic:5.18.6`
- **Credentials:** admin / admin
- **Exploit Context:** Requires authenticated Jolokia access; `TARGETURI` typically `/api/jolokia/`

---

## Module 2: Jenkins Script Console
- **Path:** `exploit/multi/http/jenkins_script_console`
- **Type:** Web application / CI server
- **Port:** 8080
- **Health Check:** HTTP GET `/login` expecting 200
- **Why:** Well-documented, multiple versions exist, clear RPORT→8080 mapping, widely used in exploit development tutorials
- **VulnEnv Definition:** `jenkins`
- **Docker Image:** `vulnhub/jenkins:2.361`
- **Credentials:** admin / admin
- **Exploit Context:** Script Console at `/script` allows Groovy execution; `TARGETURI` typically `/script`

---

## Module 3: Drupal Drupalgeddon2
- **Path:** `exploit/unix/webapp/drupal_drupalgeddon2`
- **Type:** Web application / CMS
- **Port:** 80
- **Health Check:** HTTP GET `/` expecting 200
- **Why:** Simple single-port setup, unauthenticated exploit, different architecture from ActiveMQ/Jenkins, large community interest
- **VulnEnv Definition:** `drupal`
- **Docker Image:** `vulnhub/drupal:CVE-2018-7600`
- **Credentials:** None required (unauthenticated)
- **Exploit Context:** SA-CORE-2018-002 (CVE-2018-7600); remote code execution via form API
