## Vulnerable Application
This module allows users to query an LDAP server using either a custom LDAP query, or
a set of LDAP queries under a specific category. The custom query is controlled via
the `LDAPQUERY` parameter, which will be used when the `ACTION` value is set to `CUSTOM_QUERY`.

Alternatively one can run one of several predefined queries by setting `ACTION` to the
appropriate value.

All results will be returned to the user in table format, with `||` as the delimeter
seperating multiple items within one column.

## Verification Steps

1. Do: `use auxiliary/gather/query_ldap`
2. Do: `set ACTION <target action>`
3. Do: `set RHOSTS <target IP(s)>`
4. Optional: `set RPORT <target port>` if target port is nondefault.
5: Optional: `set SSL true` if the target port is SSL enabled.
6: Do: `run`

## Scenarios

### ENUM_ALL_OBJECTCLASS

```
```
