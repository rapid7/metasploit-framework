## Description

The lotusdomino_hashes.py module attempts to retrieve user password hashes from Lotus Domino servers that have an exposed `/names.nsf` page.

## Vulnerable Application

Misconfigured Lotus Domino servers could leak user password hashes available in user documents accessible from a `/names.nsf` page. Multiple variables in document sources could contain users' password hashes.

## Verification Steps

- [ ] `./msfconsole`
- [ ] `use auxiliary/scanner/lotus/lotusdomino_hashes`
- [ ] `set rhosts <host>`
- [ ] `run`
- [ ] Verify hashes are retrieved

## Scenarios

### Application on Test System

```

```
