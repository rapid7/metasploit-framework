# Database Schema & Persistence

## What I Learned From Metasploit Source

I investigated the database architecture and found:

### Migration System
- `db/migrate/` exists but is **empty** in the framework repo
- Migrations are gathered from **Rails engines** via `gather_engine_migration_paths`
- `lib/msf/core/db_manager/migration.rb` uses `ActiveRecord::MigrationContext`
- `schema.rb` is auto-generated, not edited directly

### Key Code From `lib/msf/core/db_manager/migration.rb`

```ruby
def gather_engine_migration_paths
  paths = ActiveRecord::Migrator.migrations_paths
  ::Rails::Engine.subclasses.map(&:instance).each do |engine|
    migrations_paths = engine.paths['db/migrate'].existent_directories
    migrations_paths.each do |migrations_path|
      unless paths.include? migrations_path
        paths << migrations_path
      end
    end
  end
  paths
end
```

### Database Configuration
- `config/database.yml` does not exist in the framework
- Database config is passed via `DatabaseYAML` option
- `framework.db.active` checks if database is connected

## Phase 1: Plugin-Only (Weeks 1-6) — In-Memory Registry

**Decision:** For the initial plugin implementation, use **in-memory storage only**.
No database migrations, no schema changes.

### Why In-Memory First?
1. No framework modifications required
2. Plugin loads/unloads cleanly
3. Container labels provide cross-session identification
4. Database integration is Phase 2 (Week 6)

### In-Memory Registry Design

```ruby
class BuiltEnvironmentRegistry
  attr_reader :environments, :framework
  
  def initialize(framework)
    @framework = framework
    @environments = {}  # local_id => Hash
    @next_id = 1
  end
  
  def register(container_id:, module_fullname:, rhost:, rport:,
               version: nil, runtime: 'docker', image_ref:,
               exploit_command:, datastore: {})
    id = @next_id
    @next_id += 1
    
    @environments[id] = {
      local_id: id,
      container_id: container_id,
      module_fullname: module_fullname,
      env_version: version,
      rhost: rhost,
      rport: rport,
      runtime: runtime,
      image_ref: image_ref,
      status: 'running',
      exploit_command: exploit_command,
      datastore: datastore,
      created_at: Time.now,
      started_at: Time.now
    }
    
    id
  end
  
  def get(id)
    @environments[id]
  end
  
  def list
    @environments.values.sort_by { |e| e[:local_id] }
  end
  
  def update_status(id, status)
    return unless @environments[id]
    @environments[id][:status] = status
    @environments[id][:updated_at] = Time.now
    @environments[id][:stopped_at] = Time.now if status == 'stopped'
    @environments[id][:started_at] = Time.now if status == 'running'
  end
  
  def remove(id)
    return unless @environments[id]
    @environments[id][:status] = 'removed'
    @environments[id][:removed_at] = Time.now
    @environments.delete(id)
  end
  
  def remove_all
    @environments.each_value do |env|
      env[:status] = 'removed'
      env[:removed_at] = Time.now
    end
    @environments.clear
    @next_id = 1
  end
  
  def find_by_container(container_id)
    @environments.values.find { |e| e[:container_id] == container_id }
  end
  
  def find_by_module(module_fullname)
    @environments.values.select { |e| e[:module_fullname] == module_fullname }
  end
  
  def used_ports
    @environments.values.map { |e| e[:rport] }
  end
  
  def running?
    @environments.values.any? { |e| e[:status] == 'running' }
  end
end
```

### Container Labels (Cross-Session Identification)

Since in-memory data is lost on msfconsole restart, use **OCI container labels**
to identify and reconstruct environments.

**Design Decision:** Use only lightweight individual labels for the minimal
dynamic data needed. All static metadata (credentials, datastore defaults,
health checks, exploit commands) is reconstructible from the module's
`VulnerableEnvironment` definition and the environment YAML file.

**Rationale:** The second mentor correctly observed that if we can identify
the container by `managed_by` + `instance_id` + `module` labels, we can look
up the module's `VulnerableEnvironment` definition from `module_info`. The
definition contains `port_mapping`, `datastore_defaults`, `credentials`, and
`health_check`. The only truly dynamic data that cannot be reconstructed is:

1. **Allocated port(s)** — dynamically assigned at runtime
2. **Environment version** — which image tag was provisioned
3. **Container runtime ID** — the actual Docker/Podman container ID

**Label Schema:**

| Label | Type | Value | Purpose |
|-------|------|-------|---------|
| `msf.vulnenv.managed_by` | String | `test_env` | Discovery filter — find all framework-managed containers |
| `msf.vulnenv.instance_id` | String | `msf-{hostname}-{pid}` | Session isolation — identify which msfconsole created it |
| `msf.vulnenv.module` | String | Module fullname | Module linkage — filter by target module |
| `msf.vulnenv.env_id` | String | `1` | Registry cross-reference — map to in-memory ID |
| `msf.vulnenv.version` | String | `2.361` | **Version used** — not reliably in image tag |
| `msf.vulnenv.ports` | String | `8081:8080` | **Allocated port mapping** — host:container, comma-separated |

**Example:**

```bash
docker run -d \
  --label "msf.vulnenv.managed_by=test_env" \
  --label "msf.vulnenv.instance_id=msf-hostname-12345" \
  --label "msf.vulnenv.module=exploit/multi/http/jenkins_script_console" \
  --label "msf.vulnenv.env_id=1" \
  --label "msf.vulnenv.version=2.361" \
  --label "msf.vulnenv.ports=8081:8080" \
  vulnhub/jenkins:2.361
```

**Why no Base64 JSON payload?**

| Concern | Resolution |
|---------|-----------|
| Docker label size limit (~2KB total) | Lightweight labels stay well under limit |
| Schema evolution | Adding a new label is simpler than versioning a JSON schema |
| No encoding/decoding complexity | No Base64, no JSON parsing errors |



## Phase 2: YAML Persistence with ActiveModel (Week 6+)

Phase 2 replaces purely in-memory storage with **ActiveModel-backed YAML persistence** in `~/.msf4/test_env_registry.yml`. This provides cross-session state sharing without requiring any framework database changes.

### Why ActiveModel + YAML?

| Concern | Resolution |
|---------|-----------|
| **Framework coupling** | No dependency on `framework.db.active` or PostgreSQL |
| **Upstream friction** | No migration files, no `metasploit-data-models` coordination |
| **Portability** | Works in any msfconsole session, even without `msfdb` |
| **Concurrency** | `flock` file locking enables safe multi-process access |
| **Security** | `Psych.safe_load` with permitted classes prevents arbitrary code execution |

### Design Overview

- **`VulnTarget`** — `ActiveModel::Model` representing a single provisioned container
- **`VulnEnvironment`** — `ActiveModel::Validations` collection of all targets
- **`VulnEnvironmentStore`** — Atomic load/save via `File::LOCK_SH` / `File::LOCK_EX`

### Cross-Session Behavior

The YAML file acts as a **single shared registry** across all msfconsole instances:

- **Sparse monotonic IDs**: IDs are allocated sequentially but never renumbered. Removing environment 2 from `[1, 2, 3]` yields `[1, 3]`, not `[1, 2]`. This matches the Metasploit `sessions` table behavior and prevents identity-shift bugs during batch operations.
- **Pruning on startup**: Dead entries (containers that no longer exist) are automatically removed. IDs are **not** compacted after pruning — sparse IDs remain stable.

### State Reconstruction

On startup, the plugin:

1. Loads the shared YAML registry
2. Queries the runtime for all containers with `label=msf.vulnenv.managed_by=test_env`
3. Prunes registry entries whose `container_id` no longer exists
4. Reconstructs any running containers missing from the registry by reading their labels and assigning the next monotonic ID

**Important:** Reconstruction uses `container_id` as the ground truth for matching, not the `env_id` label. Because IDs are never compacted, `env_id` labels remain stable references, but `container_id` is still the authoritative identifier.