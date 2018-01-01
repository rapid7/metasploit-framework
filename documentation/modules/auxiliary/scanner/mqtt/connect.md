## Vulnerable Application

Most any MQTT instance will work.  Instructions for testing against a Dockerized endpoint are provided below.

### Docker Install

A dockerized version of [mosquitto](https://mosquitto.org/) is available
[here](https://github.com/toke/docker-mosquitto).  There are two basic
scenarios worth discussing -- mosquitto with anonymous authentication allowed
and disallowed.  The method for running both is similar.

#### Docker MQTT Server With Anonymous Authentication

By default, mosquitto does not require credentials and allows anonymous authentication.  To run in this way:

```
$  docker run -i -p 1883:1883  toke/mosquitto
1513822879: mosquitto version 1.4.14 (build date Mon, 10 Jul 2017 23:48:43 +0100) starting
1513822879: Config loaded from /mqtt/config/mosquitto.conf.
1513822879: Opening websockets listen socket on port 9001.
1513822879: Opening ipv4 listen socket on port 1883.
1513822879: Opening ipv6 listen socket on port 1883.
```

#### Docker MQTT Server Without Anonymous Authenticaiton

Msquitto can be configured to require credentials.  To run in this way:

  1. Create a simple configuration file:

  ```
  $  mkdir -p config && cat > config/mosquitto.conf
  password_file /mqtt/config/passwd
  allow_anonymous false
  ```

  2. Create a password file for mosquitto (this example creates a user admin wtth password admin)

  ```
  $  touch config/passwd && mosquitto_passwd -b config/passwd admin admin
  ```

  3. Now run the dockerized mosquitto instance, mounting the configuration files from above for use at runtime:

  ```
  $  docker run -ti -p 1883:1883 -v `pwd`/config/:/mqtt/config:ro  toke/mosquitto
  1513823564: mosquitto version 1.4.14 (build date Mon, 10 Jul 2017 23:48:43 +0100) starting
  1513823564: Config loaded from /mqtt/config/mosquitto.conf.
  1513823564: Opening ipv4 listen socket on port 1883.
  1513823564: Opening ipv6 listen socket on port 1883.
  ```

## Verification Steps


  1. Install the application without credentials
  2. Start msfconsole
  3. Do: `use auxiliary/scanner/mqtt/connect`
  4. Do: `set rhosts [IPs]`
  5. Do: `run`
  6. Confirm that the default or non-default credentials are discovered as configured

## Options

  **CLIENT_ID**

  When specified, this will set the ID of the client when connecting to the MQTT endpoint.  While
  not all MQTT implementation support this, some, like mosquitto, support filtering by client ID and
  this option can be used in those scenarios.  By default, a random ID is selected.

  **READ_TIMEOUT**

  The amount of time, in seconds, to wait for responses from the MQTT endpoint.

## Scenarios

### Docker MQTT Server With Anonymous Authentication

Configure MQTT in a Docker container without credentials as described above.

```
> use auxiliary/scanner/mqtt/connect
> set VERBOSE false
VERBOSE => false
> set RHOSTS localhost
RHOSTS => localhost
> run
[+] 127.0.0.1:1883        - Does not require authentication
[*] Scanned 1 of 1 hosts (100% complete)
```

### Docker MQTT Server Without Anonymous Authentication

Configure MQTT in a Docker container with credentials as described above.

```
> use auxiliary/scanner/mqtt/connect
> set VERBOSE false
FALSE => false
resource (mqtt.rc)> set RHOSTS localhost
RHOSTS => localhost
resource (mqtt.rc)> run
...
[+] 127.0.0.1:1883        - MQTT Login Successful: admin/admin

```
