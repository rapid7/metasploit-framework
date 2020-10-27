SQL Injection library support was added in 2020 by @red0xff during the Google Summer of Code.

# Supported Databases
* MySQL/MariaDB ([#13596](https://github.com/rapid7/metasploit-framework/pull/13596))
* SQLite ([#13847](https://github.com/rapid7/metasploit-framework/pull/13847))
* PostgreSQL ([#14067](https://github.com/rapid7/metasploit-framework/pull/14067))

# Supported Techniques
* Boolean Based Blind
* Time Based Blind

|                     | MySQL/MariaDB | SQLite | Postgres |
|---------------------|---------------|--------|----------|
| Boolean Based Blind | X             | X      |          |
| Time Based Blind    | X             | X      |          |
|                     |               |        |          |

## How to use in a module

You'll need to start off by including the library.

```
include Msf::Exploit::SQLi
```

Next we create our SQLi object:

```
sqli = create_sqli(dbms: MySQLi::Common, opts: sqli_opts) do |payload|
  # Here is where we write in what to do each request using #{payload} as the spot to inject
end
```

`dbms` can be set to either `Common` if the DB isn't know, or one of the other databases and methods if it is known ahead of time such as `SQLitei::BooleanBasedBlind`
`sqli_opts` is a hash containing all of the options: https://github.com/red0xff/metasploit-framework/blob/master/lib/msf/core/exploit/sqli/common.rb#L10

## Notes

`run_sql` can only return 1 column.