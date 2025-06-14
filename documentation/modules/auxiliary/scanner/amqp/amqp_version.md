## Description

This module displays the version information about Advanced Message Queuing Protocol (AMQP) 0-9-1 servers. Per the
specification, the "server-properties":

> ... SHOULD contain at least these fields: "host", specifying the server host name or address, "product", giving the
> name of the server product, "version", giving the name of the server version, "platform", giving the name of the
> operating system, "copyright", if appropriate, and "information", giving other general information.

*See: https://www.rabbitmq.com/amqp-0-9-1-reference.html#connection.start.server-properties*

## Verification Steps

1. Do: `use auxiliary/scanner/amqp/amqp_version`
2. Do: `set RHOSTS [IP]`
3. Do: `set RPORT [PORT]`
4. Do: `run`

## Scenarios

**Running the scanner**

```
msf6 > use auxiliary/scanner/amqp/amqp_version
msf6 auxiliary(scanner/amqp/amqp_version) > set RHOSTS 192.168.159.0/24
RHOSTS => 192.168.159.0/24
msf6 auxiliary(scanner/amqp/amqp_version) > run

[*] 192.168.159.17:5671 - AMQP Detected (version:RabbitMQ 3.8.16) (cluster:rabbit@WIN-KHPRSGSRF30) (platform:Erlang/OTP 23.3) (authentication:AMQPLAIN, PLAIN)
[*] 192.168.159.0/24:5671 - Scanned  51 of 256 hosts (19% complete)
[*] 192.168.159.0/24:5671 - Scanned  53 of 256 hosts (20% complete)
[*] 192.168.159.0/24:5671 - Scanned  98 of 256 hosts (38% complete)
[*] 192.168.159.128:5671 - AMQP Detected (version:RabbitMQ 3.11.10) (cluster:rabbit@my-rabbit) (platform:Erlang/OTP 25.3) (authentication:PLAIN, AMQPLAIN)
[*] 192.168.159.0/24:5671 - Scanned 104 of 256 hosts (40% complete)
[*] 192.168.159.0/24:5671 - Scanned 150 of 256 hosts (58% complete)
[*] 192.168.159.0/24:5671 - Scanned 154 of 256 hosts (60% complete)
[*] 192.168.159.0/24:5671 - Scanned 199 of 256 hosts (77% complete)
[*] 192.168.159.0/24:5671 - Scanned 216 of 256 hosts (84% complete)
[*] 192.168.159.0/24:5671 - Scanned 233 of 256 hosts (91% complete)
[*] 192.168.159.0/24:5671 - Scanned 256 of 256 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/amqp/amqp_version) > services 
Services
========

host             port  proto  name   state  info
----             ----  -----  ----   -----  ----
192.168.159.17   5671  tcp    amqps  open   AMQP Detected (version:RabbitMQ 3.8.16) (cluster:rabbit@WIN-KHPRSGSRF30) (platform:Erlang/OTP 23.3) (authentication:AMQPLAIN, PL
                                            AIN)
192.168.159.128  5671  tcp    amqps  open   AMQP Detected (version:RabbitMQ 3.11.10) (cluster:rabbit@my-rabbit) (platform:Erlang/OTP 25.3) (authentication:PLAIN, AMQPLAIN)

msf6 auxiliary(scanner/amqp/amqp_version) 
```

[1]: https://www.rabbitmq.com/amqp-0-9-1-reference.html#connection.start.server-properties
