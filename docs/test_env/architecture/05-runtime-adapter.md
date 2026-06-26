# Runtime Adapter & Port Allocation

## What I Verified on My Machine

### Docker and Podman Availability

**Both runtimes are installed.** Docker will be primary, Podman fallback.

### Docker Inspect Test

I ran a test container (port binding failed due to conflict, but inspect worked):

```bash
$ docker run -d --name test-nginx --label msf.test=1 -p 127.0.0.1:8080:80 nginx
# Port 8080 was in use — container created but not started
# This proves: FIXED PORTS FAIL, dynamic allocation is required

$ docker inspect test-nginx > /tmp/docker-inspect.json
```

Key fields from `docker inspect` output:

```json
{
  "Id": "59721d248c4ff4be689ae3fedf8dc947f53d06c657ac0b1418205621a1ee6f44",
  "State": {
    "Status": "created",
    "Running": false
  },
  "Config": {
    "Labels": {
      "msf.test": "1"
    }
  },
  "HostConfig": {
    "PortBindings": {
      "80/tcp": [
        {
          "HostIp": "127.0.0.1",
          "HostPort": "8080"
        }
      ]
    }
  }
}
```

**Important findings:**
- Labels are stored in `Config.Labels`, not top-level
- `State.Status` shows "created" when container fails to start
- `HostConfig.PortBindings` shows the requested mapping
- **Port 8080 was already in use — fixed ports are unreliable**

### Port Allocation Test

I wrote and ran `test_port.rb`:

```ruby
#!/usr/bin/env ruby

require 'socket'

def port_available?(port)
  server = TCPServer.new('127.0.0.1', port)
  server.close
  true
rescue Errno::EADDRINUSE
  false
end

def find_port(preferred = nil, used = [])
  if preferred
    return preferred if port_available?(preferred) && !used.include?(preferred)
    puts "Port #{preferred} unavailable, finding alternative..."
  end

  (49152..65535).each do |p|
    next if used.include?(p)
    return p if port_available?(p)
  end

  raise "No available ports"
end

# Test
puts "Port 8080 available? #{port_available?(8080)}"
puts "Found port: #{find_port}"
puts "Found port (prefer 9999): #{find_port(9999)}"
```

Output:
```
Port 8080 available? true
Found port: 49152
Found port (prefer 9999): 9999
```

**Port allocation works.** `TCPServer.new('127.0.0.1', port)` correctly tests availability.

## Critical Design Decision: Dynamic Port Allocation

From the Docker test failure:
- **Never assume a port is available**
- **Always test before binding**
- **Fallback to ephemeral range (49152-65535)**
- **Inform user when fallback occurs**

## Runtime Adapter Design

### Interface

```ruby
module RuntimeAdapter
  def self.detect
    return DockerRuntime.new if DockerRuntime.available?
    return PodmanRuntime.new if PodmanRuntime.available?
    nil
  end
end

class BaseRuntime
  def available?; raise NotImplementedError; end
  def name; raise NotImplementedError; end
  
  def pull(image); raise NotImplementedError; end
  def run(image:, ports:, labels:, volumes: [], env: {}, name: nil)
    raise NotImplementedError
  end
  def stop(container_id); raise NotImplementedError; end
  def start(container_id); raise NotImplementedError; end
  def remove(container_id); raise NotImplementedError; end
  def inspect(container_id); raise NotImplementedError; end
  def exec(container_id, command); raise NotImplementedError; end
  def list(filters: {}); raise NotImplementedError; end
end
```

### Docker Implementation

```ruby
class DockerRuntime < BaseRuntime
  def available?
    system('docker version > /dev/null 2>&1')
  end
  
  def name; 'docker'; end
  
  def pull(image)
    system("docker pull #{image}")
    $? == 0
  end
  
  def run(image:, ports:, labels:, volumes: [], env: {}, name: nil)
    cmd = ['docker', 'run', '-d']
    
    # Port mappings: -p 127.0.0.1:HOST:CONTAINER
    ports.each do |host_port, container_port|
      cmd += ['-p', "127.0.0.1:#{host_port}:#{container_port}"]
    end
    
    # Labels: --label key=value
    labels.each do |k, v|
      cmd += ['--label', "#{k}=#{v}"]
    end
    
    # Volumes: -v HOST:CONTAINER
    volumes.each do |host_path, container_path|
      cmd += ['-v', "#{host_path}:#{container_path}"]
    end
    
    # Environment: -e KEY=VALUE
    env.each do |k, v|
      cmd += ['-e', "#{k}=#{v}"]
    end
    
    # Name: --name
    cmd += ['--name', name] if name
    
    cmd << image
    
    output = `#{cmd.join(' ')} 2>&1`
    if $? == 0
      output.strip  # container ID
    else
      raise "Docker run failed: #{output}"
    end
  end
  
  def inspect(container_id)
    json = `docker inspect #{container_id} 2>/dev/null`
    return nil if json.empty?
    
    data = JSON.parse(json)
    data.first
  rescue JSON::ParserError
    nil
  end
  
  def stop(container_id)
    system("docker stop #{container_id} > /dev/null 2>&1")
  end
  
  def start(container_id)
    system("docker start #{container_id} > /dev/null 2>&1")
  end
  
  def remove(container_id)
    system("docker rm #{container_id} > /dev/null 2>&1")
  end
  
  def exec(container_id, command)
    output = `docker exec #{container_id} #{command} 2>&1`
    [output, $?.exitstatus]
  end
  
  def list(filters: {})
    cmd = ['docker', 'ps', '-a', '--format', '{{json .}}']
    
    filters.each do |k, v|
      cmd += ['--filter', "#{k}=#{v}"]
    end
    
    output = `#{cmd.join(' ')} 2>/dev/null`
    output.lines.map { |l| JSON.parse(l) }
  rescue JSON::ParserError
    []
  end
end
```

### Podman Implementation

```ruby
class PodmanRuntime < BaseRuntime
  def available?
    system('podman version > /dev/null 2>&1')
  end
  
  def name; 'podman'; end
  
  # Identical to DockerRuntime except 'podman' instead of 'docker'
  # All CLI flags are the same for the operations we need
  def run(image:, ports:, labels:, volumes: [], env: {}, name: nil)
    cmd = ['podman', 'run', '-d']
    
    ports.each do |host_port, container_port|
      cmd += ['-p', "127.0.0.1:#{host_port}:#{container_port}"]
    end
    
    labels.each do |k, v|
      cmd += ['--label', "#{k}=#{v}"]
    end
    
    volumes.each do |host_path, container_path|
      cmd += ['-v', "#{host_path}:#{container_path}"]
    end
    
    env.each do |k, v|
      cmd += ['-e', "#{k}=#{v}"]
    end
    
    cmd += ['--name', name] if name
    cmd << image
    
    output = `#{cmd.join(' ')} 2>&1`
    if $? == 0
      output.strip
    else
      raise "Podman run failed: #{output}"
    end
  end
  
  # inspect, stop, start, remove, exec, list identical to DockerRuntime
  # with 'podman' instead of 'docker'
end
```

## Port Allocation

```ruby
class PortAllocator
  EPHEMERAL_START = 49152
  EPHEMERAL_END   = 65535
  
  def initialize(used_ports = [])
    @used_ports = Set.new(used_ports)
  end
  
  def allocate(preferred = nil)
    # 1. Try user-requested port first
    if preferred && available?(preferred)
      @used_ports.add(preferred)
      return preferred
    end
    
    # 2. Fall back to ephemeral range
    (EPHEMERAL_START..EPHEMERAL_END).each do |port|
      next if @used_ports.include?(port)
      if available?(port)
        @used_ports.add(port)
        return port
      end
    end
    
    raise "No available ports in range #{EPHEMERAL_START}-#{EPHEMERAL_END}"
  end
  
  def release(port)
    @used_ports.delete(port)
  end
  
  private
  
  def available?(port)
    return false if @used_ports.include?(port)
    
    server = TCPServer.new('127.0.0.1', port)
    server.close
    true
  rescue Errno::EADDRINUSE
    false
  end
end
```

## Container Label Schema

All containers created by test_env receive these labels:

| Label | Value | Purpose |
|-------|-------|---------|
| `msf.vulnenv.instance_id` | `msf-{hostname}-{pid}` | Isolate msfconsole instances |
| `msf.vulnenv.module` | Module fullname | Link to exploit module |
| `msf.vulnenv.version` | Environment version | Track which version |
| `msf.vulnenv.env_id` | Internal registry ID | Cross-reference |
| `msf.vulnenv.created_at` | ISO8601 timestamp | Audit trail |
| `msf.vulnenv.managed_by` | `test_env` | Identify framework-managed |

## Docker vs Podman Differences

| Feature | Docker | Podman | Impact on Design |
|---------|--------|--------|----------------|
| Daemon | Required (`dockerd`) | Daemonless | Podman simpler for rootless |
| Rootless | Complex setup | Default | Podman more secure |
| CLI syntax | `docker ...` | `podman ...` | Simple binary substitution |
| Networking | Bridge by default | `slirp4netns` for rootless | Slight performance difference |
| Image storage | Central (`/var/lib/docker`) | Per-user (`~/.local/share/containers`) | Not shared between users |

## Auto-Detection Strategy

```ruby
def self.detect
  return DockerRuntime.new if DockerRuntime.available?
  return PodmanRuntime.new if PodmanRuntime.available?
  nil
end
```

## How test_env build Handles Port Conflicts

### Problem

From my test:
```bash
docker run -d -p 127.0.0.1:8080:80 nginx
# Error: ports are not available: exposing port TCP 127.0.0.1:8080
```

Port 8080 was already in use. Fixed ports fail.

### Solution: Dynamic Port Allocation with Automatic Fallback

The `PortAllocator` class above handles this by:
1. Testing if preferred port is available via `TCPServer.new`
2. If not, scanning ephemeral range for available port
3. Tracking used ports to avoid duplicates

### Integration in test_env build

```ruby
def cmd_test_env_build(args)
  # ... get module, VulnEnv config, definition ...
  
  shared = definition['shared']
  port_mapping = vuln_env['port_mapping']  # {8080 => 'RPORT'}
  
  # Get used ports from registry
  used = registry.used_ports
  
  # Allocate ports
  allocator = PortAllocator.new(used)
  allocated_ports = {}
  
  shared['ports'].each do |name, container_port|
    # Check if user specified a port override: RPORT=8081
    preferred = nil
    if datastore_option = port_mapping[container_port]
      preferred = args.find { |a| a.start_with?("#{datastore_option}=") }&.split('=')&.last&.to_i
    end
    
    # Allocate (falls back automatically if preferred is taken)
    host_port = allocator.allocate(preferred)
    allocated_ports[container_port] = host_port
  end
  
  # Start container with allocated ports
  container_id = runtime.run(
    image: env_config['image'],
    ports: allocated_ports  # {80 => 49152}
  )
  
  # Report actual ports to user
  allocated_ports.each do |container_port, host_port|
    if datastore_option = port_mapping[container_port]
      if host_port != (preferred || container_port)
        print_status("Port #{preferred || container_port} unavailable, using #{host_port}")
      end
      print_status("Mapped container:#{container_port} -> host:#{host_port} (#{datastore_option})")
    end
  end
  
  # Auto-set datastore options
  allocated_ports.each do |container_port, host_port|
    if datastore_option = port_mapping[container_port]
      mod.datastore[datastore_option] = host_port
      print_status("Set #{datastore_option} = #{host_port}")
    end
  end
end
```

### Key Design Principles

| Principle | Implementation |
|-----------|---------------|
| Never assume a port is available | `TCPServer.new` test before binding |
| Always provide fallback | Ephemeral range scan |
| Respect user preference | Try requested port first |
| Inform user of changes | Print status when fallback occurs |
| Auto-configure module | Set datastore options automatically |

## Error Handling

| Error Condition | Message |
|-----------------|---------|
| No runtime available | "No container runtime found. Install Docker or Podman." |
| Image pull failed | "Failed to pull image: {image}" |
| Container start failed (port conflict) | "Failed to start container: {error}. Try without RPORT override." |
| No available ports | "No available ports in range 49152-65535" |
| Container not found | "Container {id} not found" |
