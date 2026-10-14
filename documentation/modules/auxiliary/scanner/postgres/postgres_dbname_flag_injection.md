## Vulnerable Application

This module identifies PostgreSQL 9.0, 9.1, and 9.2 servers that are vulnerable to command-line flag injection through CVE-2013-1899. The vulnerability allows an attacker to inject command-line flags through the database name parameter during connection, potentially leading to denial of service, privilege escalation, or arbitrary code execution.

The vulnerability was fixed in PostgreSQL 9.2.4, 9.1.9, 9.0.13, and 8.4.17.

### Installation

You can set up a vulnerable PostgreSQL server using Docker:

```bash
# Run vulnerable PostgreSQL 9.2.3
docker run -d \
  --name postgres-vuln \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_HOST_AUTH_METHOD=trust \
  -p 5432:5432 \
  postgres:9.2.3

# Verify it's running
docker ps | grep postgres-vuln

# Configure to allow connections from any IP
docker exec -it postgres-vuln bash -c "echo 'host all all 0.0.0.0/0 trust' >> /var/lib/postgresql/data/pg_hba.conf"
docker restart postgres-vuln
```

Alternatively, for PostgreSQL 9.1:

```bash
docker run -d \
  --name postgres91-vuln \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_HOST_AUTH_METHOD=trust \
  -p 5432:5432 \
  postgres:9.1.8
```

## Verification Steps

1. Install and configure the vulnerable PostgreSQL server as described above
2. Start msfconsole
3. Do: `use auxiliary/scanner/postgres/postgres_dbname_flag_injection`
4. Do: `set RHOSTS [IP]`
5. Do: `run`
6. You should see output indicating whether the server is vulnerable to CVE-2013-1899

## Options

**RHOSTS**

The target address range or CIDR identifier

**RPORT**

The target port (default: 5432)

**THREADS**

The number of concurrent threads (default: 1)

## Scenarios

### Scanning a Vulnerable PostgreSQL 9.2.3 Server

```
msf6 > use auxiliary/scanner/postgres/postgres_dbname_flag_injection
msf6 auxiliary(scanner/postgres/postgres_dbname_flag_injection) > set RHOSTS 192.0.2.10
RHOSTS => 192.0.2.10
msf6 auxiliary(scanner/postgres/postgres_dbname_flag_injection) > run

[+] 192.0.2.10:5432 is vulnerable to CVE-2013-1899: E FATAL C0A000 Mpostgres: invalid argument: "--help" F postmaster.c L1123 Rprocess_postgres_switches
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Scanning a Patched PostgreSQL Server

```
msf6 auxiliary(scanner/postgres/postgres_dbname_flag_injection) > set RHOSTS 192.0.2.20
RHOSTS => 192.0.2.20
msf6 auxiliary(scanner/postgres/postgres_dbname_flag_injection) > run

[*] 192.0.2.20:5432 does not appear to be vulnerable to CVE-2013-1899
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Scanning Multiple PostgreSQL Servers

```
msf6 auxiliary(scanner/postgres/postgres_dbname_flag_injection) > set RHOSTS 192.0.2.0/24
RHOSTS => 192.0.2.0/24
msf6 auxiliary(scanner/postgres/postgres_dbname_flag_injection) > set THREADS 20
THREADS => 20
msf6 auxiliary(scanner/postgres/postgres_dbname_flag_injection) > run

[+] 192.0.2.10:5432 is vulnerable to CVE-2013-1899: E FATAL C0A000 Mpostgres: invalid argument: "--help" F postmaster.c L1123 Rprocess_postgres_switches
[*] 192.0.2.15:5432 does not appear to be vulnerable to CVE-2013-1899
[-] 192.0.2.20:5432 does not allow connections from us
[+] 192.0.2.25:5432 is vulnerable to CVE-2013-1899: E FATAL C0A000 Mpostgres: invalid argument: "--help" F postmaster.c L1123 Rprocess_postgres_switches
[*] Scanned 256 of 256 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Connection Refused Scenario

```
msf6 auxiliary(scanner/postgres/postgres_dbname_flag_injection) > set RHOSTS 192.0.2.100
RHOSTS => 192.0.2.100
msf6 auxiliary(scanner/postgres/postgres_dbname_flag_injection) > run

[-] 192.0.2.100:5432 does not allow connections from us
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
