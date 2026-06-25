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
to identify and reconstruct environments:

```bash
docker run -d \
  --label "msf.vulnenv.instance_id=msf-$(hostname)-$$" \
  --label "msf.vulnenv.module=exploit/multi/http/jenkins_script_console" \
  --label "msf.vulnenv.version=2.361" \
  --label "msf.vulnenv.env_id=1" \
  --label "msf.vulnenv.created_at=2024-06-25T17:37:00Z" \
  vulnhub/jenkins:2.361
```

**Label Schema:**
| Label | Value | Purpose |
|-------|-------|---------|
| `msf.vulnenv.instance_id` | `msf-{hostname}-{pid}` | Identify msfconsole instance |
| `msf.vulnenv.module` | Module fullname | Link to exploit module |
| `msf.vulnenv.version` | Environment version | Track which version |
| `msf.vulnenv.env_id` | Internal registry ID | Cross-reference |
| `msf.vulnenv.created_at` | ISO8601 timestamp | Audit trail |
| `msf.vulnenv.managed_by` | `test_env` | Identify framework-managed |

### State Reconstruction From Labels (Future Enhancement)

```ruby
def reconstruct_from_labels(runtime)
  containers = runtime.list(filters: { 'label' => 'msf.vulnenv.managed_by=test_env' })
  containers.each do |container|
    labels = container['Labels']
    # Rebuild registry entry from labels
    # (Week 6 enhancement)
  end
end
```

## Phase 2: Database Integration (Week 6+)

When adding PostgreSQL persistence:

### Migration File
```ruby
# db/migrate/20240624000001_create_vuln_environments.rb
class CreateVulnEnvironments < ActiveRecord::Migration[8.0]
  def change
    create_table :vuln_environments, id: :serial do |t|
      t.string  :container_id,    null: false
      t.string  :image_ref,       null: false
      t.string  :module_fullname, null: false
      t.string  :env_version
      t.string  :rhost,           default: '127.0.0.1'
      t.integer :rport,           null: false
      t.text    :datastore
      t.string  :runtime,         default: 'docker', null: false
      t.string  :msf_instance_id
      t.string  :status,          null: false, default: 'running'
      t.text    :exploit_command
      t.timestamps
      t.datetime :started_at
      t.datetime :stopped_at
      t.datetime :removed_at
    end
    
    add_index :vuln_environments, :module_fullname
    add_index :vuln_environments, :status
    add_index :vuln_environments, :container_id, unique: true
    add_index :vuln_environments, :msf_instance_id
    add_index :vuln_environments, [:status, :module_fullname]
  end
end
```

### ActiveRecord Model
```ruby
class VulnEnvironment < ActiveRecord::Base
  self.table_name = 'vuln_environments'
  serialize :datastore, JSON
  
  scope :active, -> { where(status: ['running', 'stopped']) }
  scope :running, -> { where(status: 'running') }
  scope :by_module, ->(name) { where(module_fullname: name) }
  
  validates :container_id, presence: true, uniqueness: true
  validates :module_fullname, presence: true
  validates :rport, presence: true, numericality: { only_integer: true }
  validates :status, inclusion: { in: %w[running stopped removed orphaned error] }
end
```

### Integration With In-Memory Registry

```ruby
class BuiltEnvironmentRegistry
  def initialize(framework)
    @framework = framework
    @environments = {}
    @next_id = 1
    load_from_database if database_available?
  end
  
  private
  
  def database_available?
    framework.db.active && defined?(VulnEnvironment)
  end
  
  def load_from_database
    VulnEnvironment.active.each do |db_env|
      @environments[@next_id] = {
        local_id: @next_id,
        db_id: db_env.id,
        container_id: db_env.container_id,
        # ... map all fields ...
      }
      @next_id += 1
    end
  end
  
  def persist_to_database(record)
    VulnEnvironment.create!(...)
  end
end
```

## Reference: sessions Table Pattern

From `db/schema.rb`:
```ruby
create_table "sessions", id: :serial, force: :cascade do |t|
  t.integer "host_id"
  t.string "stype"
  t.string "via_exploit"      # Module association
  t.string "via_payload"
  t.string "desc"
  t.integer "port"
  t.string "platform"
  t.text "datastore"          # Serialized hash
  t.datetime "opened_at", precision: nil, null: false
  t.datetime "closed_at", precision: nil
  t.string "close_reason"
  t.integer "local_id"        # In-memory mapping
  t.datetime "last_seen", precision: nil
  t.integer "module_run_id"
  t.index ["module_run_id"], name: "index_sessions_on_module_run_id"
end
```

My `vuln_environments` table follows this exact pattern:
- `id: :serial` primary key
- `module_fullname` like `via_exploit`
- `datastore` serialized text
- `local_id` equivalent via `env_id` label
- Lifecycle timestamps (`created_at`, `started_at`, `stopped_at`, `removed_at`)
