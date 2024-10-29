## Acceptance Tests

A slower test suite that ensures high level functionality works as expected,
such as verifying msfconsole opens successfully, and can generate Meterpreter payloads,
create handlers, etc.

The test suite runs on the current host, so the Meterpreter runtimes should be available.
There is no remote host support currently.

### Meterpreter

Useful environment variables:
- `METERPRETER` - Filter the test suite for specific Meterpreter instances, example: `METERPRETER=java`
- `METERPRETER_MODULE_TEST` - Filter the post modules to run, example: `METERPRETER_MODULE_TEST=test/meterpreter`
- `SPEC_HELPER_LOAD_METASPLOIT` - Skip RSpec from loading Metasploit framework and requiring a connected msfdb instance, example: `SPEC_HELPER_LOAD_METASPLOIT=false`

Running Meterpreter test suite:

```
SPEC_OPTS='--tag acceptance' bundle exec rspec './spec/acceptance/meterpreter_spec.rb'
```

Skip loading of Rails/Metasploit with:

```
SPEC_OPTS='--tag acceptance' SPEC_HELPER_LOAD_METASPLOIT=false bundle exec rspec ./spec/acceptance
```

Run a specific Meterpreter/module test Unix / Windows:

Bash command:
```
SPEC_OPTS='--tag acceptance' METERPRETER=php METERPRETER_MODULE_TEST=post/test/unix bundle exec rspec './spec/acceptance/meterpreter_spec.rb'
```

Powershell command:
```
$env:SPEC_OPTS='--tag acceptance'; $env:SPEC_HELPER_LOAD_METASPLOIT=$false; $env:METERPRETER = 'php'; bundle exec rspec './spec/acceptance/meterpreter_spec.rb'
```

### Postgres

Run a target:

```
docker run -it --rm --publish 127.0.0.1:9000:5432 -e POSTGRES_PASSWORD=password postgres:14
```

Run the test suite:

```
POSTGRES_RPORT=9000 SPEC_OPTS='--tag acceptance' SPEC_HELPER_LOAD_METASPLOIT=false bundle exec rspec ./spec/acceptance/postgres_spec.rb
```

### MySQL

Run a target:

```
docker run -it --rm --publish 127.0.0.1:9001:3306 -e MYSQL_ROOT_PASSWORD=password mariadb:11.2.2
```

Run the test suite:

```
MYSQL_RPORT=9000 SPEC_OPTS='--tag acceptance' SPEC_HELPER_LOAD_METASPLOIT=false bundle exec rspec ./spec/acceptance/mysql_spec.rb
```

### MSSQL

Run a target:

```
docker run -e "ACCEPT_EULA=Y" -e 'MSSQL_SA_PASSWORD=yourStrong(!)Password' -p 1433:1433 -d mcr.microsoft.com/mssql/server:2019-latest
```

Run the test suite:

```
MSSQL_RPORT=1433 SPEC_OPTS='--tag acceptance' SPEC_HELPER_LOAD_METASPLOIT=false bundle exec rspec ./spec/acceptance/mssql_spec.rb
```

### SMB

Build the Docker image:

```
docker compose build
```

Run a target:

```
docker compose up -d --wait
```

Run the test suite:

```
SMB_USERNAME=acceptance_tests_user SMB_PASSWORD=acceptance_tests_password SPEC_OPTS='--tag acceptance' SPEC_HELPER_LOAD_METASPLOIT=false bundle exec rspec ./spec/acceptance/smb_spec.rb
```

Shut down the container:
```
docker compose down
```

#### Allure reports

Generate allure reports locally:

```
# 1) Run the test suite with the allure formatter
rm -rf tmp/allure-raw-data
bundle exec rspec --require acceptance_spec_helper.rb --format documentation --format AllureRspec::RSpecFormatter './spec/acceptance/meterpreter_spec.rb'

# 2) Generate allure report
cd metasploit-framework/tmp
docker run -it -w $(pwd) -v $(pwd):$(pwd) ubuntu:20.04 /bin/bash

# In the container
export VERSION=2.22.1

apt update
apt install -y curl openjdk-11-jdk-headless

curl -o allure-$VERSION.tgz -Ls https://github.com/allure-framework/allure2/releases/download/$VERSION/allure-$VERSION.tgz
tar -zxvf allure-$VERSION.tgz -C .

./allure-$VERSION/bin/allure generate --clean allure-raw-data/ -o ./allure-report

# Serve the assets from the host machine, available at http://127.0.0.1:8000
cd allure-report
ruby -run -e httpd . -p 8000
```

#### Support Matrix generation

You can download the data from an existing Github job run:

```
ids=(6099944525); for id in $ids; do echo $id; gh run download $id --repo rapid7/metasploit-framework --dir gh-actions-$id ; done
```

Then generate the report using the allure data:

```
bundle exec ruby tools/dev/report_generation/support_matrix/generate.rb --allure-data /path/to/gh-actions-$id > ./support_matrix.html
```

### Debugging

If a test has failed you can enter into an interactive breakpoint with:

```
require 'pry'; binding.pry
```

To interact with a console instance, forwarding the current stdin to the console's stdin,
and writing the console's output to stdout:

```
console.interact
```

Once inside the console, the following 'commands' can be used within the context of
the interactive msfconsole:

- `!continue` - Continue, similar to Pry's continue functionality
- `!exit` - Exit the Ruby process entirely, similar to Pry's exit functionality
- `!pry` - Enter into a pry session within the calling Ruby process
