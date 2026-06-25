# Environment Definition YAML Schema

## What I Verified

I created `data/vuln_envs/jenkins.yml` and validated it with Ruby:

```bash
ruby -e "
require 'yaml'
data = YAML.safe_load(File.read('data/vuln_envs/jenkins.yml'), permitted_classes: [Symbol])
puts 'Name: ' + data['name']
puts 'Versions: ' + data['versions'].keys.inspect
puts 'Ports: ' + data['shared']['ports'].inspect
puts 'Health check type: ' + data['shared']['health_check']['type']
"
```

Output:
```
Name: jenkins
Versions: ["2.361", "2.375"]
Ports: {"http"=>8080}
Health check type: http
```

## Directory Structure

```
data/
  vuln_envs/
    README.md          # Schema documentation
    jenkins.yml        # Jenkins environments (reference implementation)
```

## File Location
`data/vuln_envs/{name}.yml`

The `{name}` must match the `name` field inside the file.

## Schema

### Top-Level Keys

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `name` | String | Yes | Machine-friendly identifier (matches filename) |
| `description` | String | Yes | Human-readable description |
| `versions` | Hash | Yes | Map of version strings to configurations |
| `shared` | Hash | Yes | Configuration shared across all versions |

### versions Section

Each version is a key-value pair:
- **Key**: Version string (e.g., `"2.361"`)
- **Value**: Hash with version-specific configuration

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `image` | String | Yes | OCI image reference |
| `build_args` | Hash | No | Docker build arguments |

Example:
```yaml
versions:
  "2.361":
    image: vulnhub/jenkins:2.361
    build_args:
      JENKINS_VERSION: "2.361"
```

### shared Section

#### ports (Required)
```yaml
shared:
  ports:
    http: 8080
```

#### health_check (Required)
```yaml
shared:
  health_check:
    type: http
    path: /login
    expected_status: 200
    interval: 5
    timeout: 2
    retries: 12
```

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `type` | String | Yes | `http`, `tcp`, or `command` |
| `path` | String | If type=http | HTTP path to check |
| `expected_status` | Integer | No | Default: 200 |
| `command` | String | If type=command | Command to execute |
| `expected_output` | String | If type=command | Substring to match |
| `interval` | Integer | No | Seconds between checks. Default: 5 |
| `timeout` | Integer | No | Seconds to wait. Default: 2 |
| `retries` | Integer | No | Max attempts. Default: 12 |

#### credentials (Optional)
```yaml
shared:
  credentials:
    default:
      username: admin
      password: admin
```

#### datastore_defaults (Optional)
```yaml
shared:
  datastore_defaults:
    TARGETURI: /script
```

#### ci (Optional)
```yaml
shared:
  ci:
    exploit:
      payload: java/meterpreter/reverse_tcp
      options:
        LHOST: 127.0.0.1
        LPORT: 4444
    validation:
      expected_session: true
      session_type: meterpreter
      expected_output: "uid="
      timeout: 120
```

## Validation Rules

1. `name` must match filename (without `.yml`)
2. `versions` must have at least one entry
3. Each version must have an `image`
4. `shared.ports` must have at least one entry
5. `shared.health_check` must have valid `type`
6. If `type` is `http`, `path` is required
7. If `type` is `command`, `command` and `expected_output` are required

## Loader Implementation (Week 3)

```ruby
class EnvironmentDefinitionLoader
  DEFINITIONS_PATH = File.join(Msf::Config.data_directory, 'vuln_envs')
  
  def self.load(name)
    require 'yaml'
    path = File.join(DEFINITIONS_PATH, "#{name}.yml")
    raise "Definition not found: #{path}" unless File.exist?(path)
    
    begin
      YAML.safe_load(File.read(path), permitted_classes: [Symbol])
    rescue Psych::SyntaxError => e
      raise "Invalid YAML in #{path}: #{e.message}"
    end
  end
  
  def self.available_definitions
    Dir.glob(File.join(DEFINITIONS_PATH, '*.yml')).map do |f|
      File.basename(f, '.yml')
    end.sort
  end
end
```

## Integration With Registry

Environment definitions are loaded by the plugin and used to:
1. Build/pull container images
2. Map container ports to host ports
3. Configure health checks
4. Set module datastore defaults

See [03-database-schema.md](https://github.com/Nayeraneru/metasploit-framework/blob/vulnenv-week1/docs/architecture/03-database-schema.md) for registry design.

## Reference: jenkins.yml

```yaml
name: jenkins
description: Jenkins CI server with Groovy Script Console enabled

versions:
  "2.361":
    image: vulnhub/jenkins:2.361
    build_args:
      JENKINS_VERSION: "2.361"
  "2.375":
    image: vulnhub/jenkins:2.375
    build_args:
      JENKINS_VERSION: "2.375"

shared:
  ports:
    http: 8080

  volumes:
    jenkins_home:
      container_path: /var/jenkins_home
      persist: false

  health_check:
    type: http
    path: /login
    expected_status: 200
    interval: 5
    timeout: 2
    retries: 12

  credentials:
    default:
      username: admin
      password: admin

  datastore_defaults:
    TARGETURI: /script

  ci:
    exploit:
      payload: java/meterpreter/reverse_tcp
      options:
        LHOST: 127.0.0.1
        LPORT: 4444
    validation:
      expected_session: true
      session_type: meterpreter
      expected_output: "uid="
      timeout: 120
```
