## Vulnerable Application

This module identifies Ruby on Rails applications vulnerable to CVE-2013-0333, an arbitrary object instantiation vulnerability in the JSON request processor. The vulnerability allows YAML deserialization through JSON endpoints, potentially leading to remote code execution.

### Vulnerable Versions

Ruby on Rails versions prior to:
- 3.2.11
- 3.1.10
- 3.0.19
- 2.3.15

### Installation

#### Docker Installation (Vulnerable Rails 3.2.10)

```dockerfile
FROM ruby:2.7

RUN gem install rails -v 3.2.10
RUN gem install sqlite3 -v '~> 1.3.6'

WORKDIR /app

# Create a simple Rails app
RUN rails new testapp --skip-bundle
WORKDIR /app/testapp

# Create a simple controller that accepts JSON
RUN echo "class TestController < ApplicationController\n  def create\n    render json: { status: 'ok' }\n  end\nend" > app/controllers/test_controller.rb

# Add route
RUN echo "Testapp::Application.routes.draw do\n  post 'test' => 'test#create'\nend" > config/routes.rb

EXPOSE 3000

CMD ["rails", "server", "-b", "0.0.0.0"]
```

Build and run:

```bash
docker build -t vulnerable-rails .
docker run -p 3000:3000 vulnerable-rails
```

#### Manual Installation

```bash
# Install Ruby and Rails
gem install rails -v 3.2.10

# Create test application
rails new testapp
cd testapp

# Create a controller
cat > app/controllers/test_controller.rb << 'EOF'
class TestController < ApplicationController
  def create
    render json: { status: 'ok' }
  end
end
EOF

# Add route
echo "Testapp::Application.routes.draw do
  post 'test' => 'test#create'
end" > config/routes.rb

# Start server
rails server
```

## Verification Steps

1. Start msfconsole
2. Use the scanner: `use auxiliary/scanner/http/rails_json_yaml_scanner`
3. Set target: `set RHOSTS <target-ip>`
4. Set target URI: `set TARGETURI /test`
5. Set HTTP method: `set HTTP_METHOD POST`
6. Run the scanner: `run`

## Options

### TARGETURI

The URI path to test. Must be an endpoint that accepts JSON input. Default: `/`

Example: `/api/users`, `/test`, `/admin/login`

### HTTP_METHOD

The HTTP method to use for testing. Options: `GET`, `POST`, `PUT`

Default: `POST`

Most Rails applications accept POST or PUT for JSON data.

### RHOSTS

Target address range or CIDR identifier.

### RPORT

Target port (default: 80 or 443 for SSL).

### SSL

Enable SSL/TLS for HTTPS endpoints.

## Scenarios

### Rails 3.2.10 Application on Docker

```
msf6 > use auxiliary/scanner/http/rails_json_yaml_scanner
msf6 auxiliary(scanner/http/rails_json_yaml_scanner) > set RHOSTS 172.17.0.3
RHOSTS => 172.17.0.3
msf6 auxiliary(scanner/http/rails_json_yaml_scanner) > set RPORT 3000
RPORT => 3000
msf6 auxiliary(scanner/http/rails_json_yaml_scanner) > set TARGETURI /test
TARGETURI => /test
msf6 auxiliary(scanner/http/rails_json_yaml_scanner) > set HTTP_METHOD POST
HTTP_METHOD => POST
msf6 auxiliary(scanner/http/rails_json_yaml_scanner) > run

[+] 172.17.0.3:3000 is likely vulnerable due to a 500 reply for invalid YAML
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Rails 3.1.8 Application with Custom Endpoint

```
msf6 auxiliary(scanner/http/rails_json_yaml_scanner) > set RHOSTS 192.168.1.100
RHOSTS => 192.168.1.100
msf6 auxiliary(scanner/http/rails_json_yaml_scanner) > set RPORT 443
RPORT => 443
msf6 auxiliary(scanner/http/rails_json_yaml_scanner) > set SSL true
SSL => true
msf6 auxiliary(scanner/http/rails_json_yaml_scanner) > set TARGETURI /api/v1/users
TARGETURI => /api/v1/users
msf6 auxiliary(scanner/http/rails_json_yaml_scanner) > set HTTP_METHOD POST
HTTP_METHOD => POST
msf6 auxiliary(scanner/http/rails_json_yaml_scanner) > run

[+] 192.168.1.100:443 is likely vulnerable due to a 422 reply for invalid YAML
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Patched Rails 3.2.11 Application

```
msf6 auxiliary(scanner/http/rails_json_yaml_scanner) > set RHOSTS 10.0.0.50
RHOSTS => 10.0.0.50
msf6 auxiliary(scanner/http/rails_json_yaml_scanner) > set RPORT 3000
RPORT => 3000
msf6 auxiliary(scanner/http/rails_json_yaml_scanner) > set TARGETURI /api/data
TARGETURI => /api/data
msf6 auxiliary(scanner/http/rails_json_yaml_scanner) > set VERBOSE true
VERBOSE => true
msf6 auxiliary(scanner/http/rails_json_yaml_scanner) > run

[*] 10.0.0.50:3000 Probe response codes: 200 / 200 / 200
[*] 10.0.0.50:3000 is not likely to be vulnerable or TARGETURI & HTTP_METHOD must be set
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Scanning Multiple Rails Endpoints

```
msf6 auxiliary(scanner/http/rails_json_yaml_scanner) > set RHOSTS 192.168.1.0/24
RHOSTS => 192.168.1.0/24
msf6 auxiliary(scanner/http/rails_json_yaml_scanner) > set THREADS 10
THREADS => 10
msf6 auxiliary(scanner/http/rails_json_yaml_scanner) > set TARGETURI /api/data
TARGETURI => /api/data
msf6 auxiliary(scanner/http/rails_json_yaml_scanner) > run

[*] 192.168.1.50:80 Probe response codes: 404 / 404 / 404
[+] 192.168.1.100:80 is likely vulnerable due to a 500 reply for invalid YAML
[*] 192.168.1.150:80 Probe response codes: 200 / 200 / 200
[*] Scanned 254 of 254 hosts (100% complete)
[*] Auxiliary module execution completed
```
