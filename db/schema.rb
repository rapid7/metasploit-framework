# encoding: UTF-8
# This file is auto-generated from the current state of the database. Instead
# of editing this file, please use the migrations feature of Active Record to
# incrementally modify your database, and then regenerate this schema definition.
#
# Note that this schema.rb definition is the authoritative source for your
# database schema. If you need to create the application database on another
# system, you should be using db:schema:load, not running all the migrations
# from scratch. The latter is a flawed and unsustainable approach (the more migrations
# you'll amass, the slower it'll run and the greater likelihood for issues).
#
# It's strongly recommended to check this file into your version control system.

ActiveRecord::Schema.define(:version => 20130717150737) do

  create_table "api_keys", :force => true do |t|
    t.text     "token"
    t.datetime "created_at", :null => false
    t.datetime "updated_at", :null => false
  end

  create_table "clients", :force => true do |t|
    t.integer  "host_id"
    t.datetime "created_at"
    t.string   "ua_string",  :limit => 1024, :null => false
    t.string   "ua_name",    :limit => 64
    t.string   "ua_ver",     :limit => 32
    t.datetime "updated_at"
  end

  create_table "creds", :force => true do |t|
    t.integer  "service_id",                                    :null => false
    t.datetime "created_at",                                    :null => false
    t.datetime "updated_at",                                    :null => false
    t.string   "user",        :limit => 2048
    t.string   "pass",        :limit => 4096
    t.boolean  "active",                      :default => true
    t.string   "proof",       :limit => 4096
    t.string   "ptype",       :limit => 256
    t.integer  "source_id"
    t.string   "source_type"
  end

  create_table "events", :force => true do |t|
    t.integer  "workspace_id"
    t.integer  "host_id"
    t.datetime "created_at"
    t.string   "name"
    t.datetime "updated_at"
    t.boolean  "critical"
    t.boolean  "seen"
    t.string   "username"
    t.text     "info"
  end

  create_table "exploit_attempts", :force => true do |t|
    t.integer  "host_id"
    t.integer  "service_id"
    t.integer  "vuln_id"
    t.datetime "attempted_at"
    t.boolean  "exploited"
    t.string   "fail_reason"
    t.string   "username"
    t.text     "module"
    t.integer  "session_id"
    t.integer  "loot_id"
    t.integer  "port"
    t.string   "proto"
    t.text     "fail_detail"
  end

  create_table "exploited_hosts", :force => true do |t|
    t.integer  "host_id",                      :null => false
    t.integer  "service_id"
    t.string   "session_uuid", :limit => 8
    t.string   "name",         :limit => 2048
    t.string   "payload",      :limit => 2048
    t.datetime "created_at",                   :null => false
    t.datetime "updated_at",                   :null => false
  end

  create_table "host_details", :force => true do |t|
    t.integer "host_id"
    t.integer "nx_console_id"
    t.integer "nx_device_id"
    t.string  "src"
    t.string  "nx_site_name"
    t.string  "nx_site_importance"
    t.string  "nx_scan_template"
    t.float   "nx_risk_score"
  end

  create_table "hosts", :force => true do |t|
    t.datetime "created_at"
    t.string   "address",               :limit => nil,                  :null => false
    t.string   "mac"
    t.string   "comm"
    t.string   "name"
    t.string   "state"
    t.string   "os_name"
    t.string   "os_flavor"
    t.string   "os_sp"
    t.string   "os_lang"
    t.string   "arch"
    t.integer  "workspace_id",                                          :null => false
    t.datetime "updated_at"
    t.text     "purpose"
    t.string   "info",                  :limit => 65536
    t.text     "comments"
    t.text     "scope"
    t.text     "virtual_host"
    t.integer  "note_count",                             :default => 0
    t.integer  "vuln_count",                             :default => 0
    t.integer  "service_count",                          :default => 0
    t.integer  "host_detail_count",                      :default => 0
    t.integer  "exploit_attempt_count",                  :default => 0
    t.integer  "cred_count",                             :default => 0
  end

  add_index "hosts", ["name"], :name => "index_hosts_on_name"
  add_index "hosts", ["os_flavor"], :name => "index_hosts_on_os_flavor"
  add_index "hosts", ["os_name"], :name => "index_hosts_on_os_name"
  add_index "hosts", ["purpose"], :name => "index_hosts_on_purpose"
  add_index "hosts", ["state"], :name => "index_hosts_on_state"
  add_index "hosts", ["workspace_id", "address"], :name => "index_hosts_on_workspace_id_and_address", :unique => true

  create_table "hosts_tags", :force => true do |t|
    t.integer "host_id"
    t.integer "tag_id"
  end

  create_table "listeners", :force => true do |t|
    t.datetime "created_at",                     :null => false
    t.datetime "updated_at",                     :null => false
    t.integer  "workspace_id", :default => 1,    :null => false
    t.integer  "task_id"
    t.boolean  "enabled",      :default => true
    t.text     "owner"
    t.text     "payload"
    t.text     "address"
    t.integer  "port"
    t.binary   "options"
    t.text     "macro"
  end

  create_table "loots", :force => true do |t|
    t.integer  "workspace_id",                 :default => 1, :null => false
    t.integer  "host_id"
    t.integer  "service_id"
    t.string   "ltype",        :limit => 512
    t.string   "path",         :limit => 1024
    t.text     "data"
    t.datetime "created_at",                                  :null => false
    t.datetime "updated_at",                                  :null => false
    t.string   "content_type"
    t.text     "name"
    t.text     "info"
  end

  create_table "macros", :force => true do |t|
    t.datetime "created_at",  :null => false
    t.datetime "updated_at",  :null => false
    t.text     "owner"
    t.text     "name"
    t.text     "description"
    t.binary   "actions"
    t.binary   "prefs"
  end

  create_table "mod_refs", :force => true do |t|
    t.string "module", :limit => 1024
    t.string "mtype",  :limit => 128
    t.text   "ref"
  end

  create_table "module_actions", :force => true do |t|
    t.integer "detail_id"
    t.text    "name"
  end

  add_index "module_actions", ["detail_id"], :name => "index_module_actions_on_module_detail_id"

  create_table "module_archs", :force => true do |t|
    t.integer "detail_id"
    t.text    "name"
  end

  add_index "module_archs", ["detail_id"], :name => "index_module_archs_on_module_detail_id"

  create_table "module_authors", :force => true do |t|
    t.integer "detail_id"
    t.text    "name"
    t.text    "email"
  end

  add_index "module_authors", ["detail_id"], :name => "index_module_authors_on_module_detail_id"

  create_table "module_details", :force => true do |t|
    t.datetime "mtime"
    t.text     "file"
    t.string   "mtype"
    t.text     "refname"
    t.text     "fullname"
    t.text     "name"
    t.integer  "rank"
    t.text     "description"
    t.string   "license"
    t.boolean  "privileged"
    t.datetime "disclosure_date"
    t.integer  "default_target"
    t.text     "default_action"
    t.string   "stance"
    t.boolean  "ready"
  end

  add_index "module_details", ["description"], :name => "index_module_details_on_description"
  add_index "module_details", ["mtype"], :name => "index_module_details_on_mtype"
  add_index "module_details", ["name"], :name => "index_module_details_on_name"
  add_index "module_details", ["refname"], :name => "index_module_details_on_refname"

  create_table "module_mixins", :force => true do |t|
    t.integer "detail_id"
    t.text    "name"
  end

  add_index "module_mixins", ["detail_id"], :name => "index_module_mixins_on_module_detail_id"

  create_table "module_platforms", :force => true do |t|
    t.integer "detail_id"
    t.text    "name"
  end

  add_index "module_platforms", ["detail_id"], :name => "index_module_platforms_on_module_detail_id"

  create_table "module_refs", :force => true do |t|
    t.integer "detail_id"
    t.text    "name"
  end

  add_index "module_refs", ["detail_id"], :name => "index_module_refs_on_module_detail_id"
  add_index "module_refs", ["name"], :name => "index_module_refs_on_name"

  create_table "module_targets", :force => true do |t|
    t.integer "detail_id"
    t.integer "index"
    t.text    "name"
  end

  add_index "module_targets", ["detail_id"], :name => "index_module_targets_on_module_detail_id"

  create_table "nexpose_consoles", :force => true do |t|
    t.datetime "created_at",                     :null => false
    t.datetime "updated_at",                     :null => false
    t.boolean  "enabled",      :default => true
    t.text     "owner"
    t.text     "address"
    t.integer  "port",         :default => 3780
    t.text     "username"
    t.text     "password"
    t.text     "status"
    t.text     "version"
    t.text     "cert"
    t.binary   "cached_sites"
    t.text     "name"
  end

  create_table "notes", :force => true do |t|
    t.datetime "created_at"
    t.string   "ntype",        :limit => 512
    t.integer  "workspace_id",                :default => 1, :null => false
    t.integer  "service_id"
    t.integer  "host_id"
    t.datetime "updated_at"
    t.boolean  "critical"
    t.boolean  "seen"
    t.text     "data"
  end

  add_index "notes", ["ntype"], :name => "index_notes_on_ntype"

  create_table "profiles", :force => true do |t|
    t.datetime "created_at",                   :null => false
    t.datetime "updated_at",                   :null => false
    t.boolean  "active",     :default => true
    t.text     "name"
    t.text     "owner"
    t.binary   "settings"
  end

  create_table "refs", :force => true do |t|
    t.integer  "ref_id"
    t.datetime "created_at"
    t.string   "name",       :limit => 512
    t.datetime "updated_at"
  end

  add_index "refs", ["name"], :name => "index_refs_on_name"

  create_table "report_templates", :force => true do |t|
    t.integer  "workspace_id",                 :default => 1, :null => false
    t.string   "created_by"
    t.string   "path",         :limit => 1024
    t.text     "name"
    t.datetime "created_at",                                  :null => false
    t.datetime "updated_at",                                  :null => false
  end

  create_table "reports", :force => true do |t|
    t.integer  "workspace_id",                  :default => 1, :null => false
    t.string   "created_by"
    t.string   "rtype"
    t.string   "path",          :limit => 1024
    t.text     "options"
    t.datetime "created_at",                                   :null => false
    t.datetime "updated_at",                                   :null => false
    t.datetime "downloaded_at"
    t.integer  "task_id"
    t.string   "name",          :limit => 63
  end

  create_table "routes", :force => true do |t|
    t.integer "session_id"
    t.string  "subnet"
    t.string  "netmask"
  end

  create_table "services", :force => true do |t|
    t.integer  "host_id"
    t.datetime "created_at"
    t.integer  "port",                     :null => false
    t.string   "proto",      :limit => 16, :null => false
    t.string   "state"
    t.string   "name"
    t.datetime "updated_at"
    t.text     "info"
  end

  add_index "services", ["name"], :name => "index_services_on_name"
  add_index "services", ["port"], :name => "index_services_on_port"
  add_index "services", ["proto"], :name => "index_services_on_proto"
  add_index "services", ["state"], :name => "index_services_on_state"

  create_table "session_events", :force => true do |t|
    t.integer  "session_id"
    t.string   "etype"
    t.binary   "command"
    t.binary   "output"
    t.string   "remote_path"
    t.string   "local_path"
    t.datetime "created_at"
  end

  create_table "sessions", :force => true do |t|
    t.integer  "host_id"
    t.string   "stype"
    t.string   "via_exploit"
    t.string   "via_payload"
    t.string   "desc"
    t.integer  "port"
    t.string   "platform"
    t.text     "datastore"
    t.datetime "opened_at",    :null => false
    t.datetime "closed_at"
    t.string   "close_reason"
    t.integer  "local_id"
    t.datetime "last_seen"
  end

  create_table "tags", :force => true do |t|
    t.integer  "user_id"
    t.string   "name",           :limit => 1024
    t.text     "desc"
    t.boolean  "report_summary",                 :default => false, :null => false
    t.boolean  "report_detail",                  :default => false, :null => false
    t.boolean  "critical",                       :default => false, :null => false
    t.datetime "created_at",                                        :null => false
    t.datetime "updated_at",                                        :null => false
  end

  create_table "task_creds", :force => true do |t|
    t.integer  "task_id",    :null => false
    t.integer  "cred_id",    :null => false
    t.datetime "created_at", :null => false
    t.datetime "updated_at", :null => false
  end

  create_table "task_hosts", :force => true do |t|
    t.integer  "task_id",    :null => false
    t.integer  "host_id",    :null => false
    t.datetime "created_at", :null => false
    t.datetime "updated_at", :null => false
  end

  create_table "task_services", :force => true do |t|
    t.integer  "task_id",    :null => false
    t.integer  "service_id", :null => false
    t.datetime "created_at", :null => false
    t.datetime "updated_at", :null => false
  end

  create_table "task_sessions", :force => true do |t|
    t.integer  "task_id",    :null => false
    t.integer  "session_id", :null => false
    t.datetime "created_at", :null => false
    t.datetime "updated_at", :null => false
  end

  create_table "tasks", :force => true do |t|
    t.integer  "workspace_id",                 :default => 1, :null => false
    t.string   "created_by"
    t.string   "module"
    t.datetime "completed_at"
    t.string   "path",         :limit => 1024
    t.string   "info"
    t.string   "description"
    t.integer  "progress"
    t.text     "options"
    t.text     "error"
    t.datetime "created_at",                                  :null => false
    t.datetime "updated_at",                                  :null => false
    t.text     "result"
    t.string   "module_uuid",  :limit => 8
    t.binary   "settings"
  end

  create_table "users", :force => true do |t|
    t.string   "username"
    t.string   "crypted_password"
    t.string   "password_salt"
    t.string   "persistence_token"
    t.datetime "created_at",                                            :null => false
    t.datetime "updated_at",                                            :null => false
    t.string   "fullname"
    t.string   "email"
    t.string   "phone"
    t.string   "company"
    t.string   "prefs",             :limit => 524288
    t.boolean  "admin",                               :default => true, :null => false
  end

  create_table "vuln_attempts", :force => true do |t|
    t.integer  "vuln_id"
    t.datetime "attempted_at"
    t.boolean  "exploited"
    t.string   "fail_reason"
    t.string   "username"
    t.text     "module"
    t.integer  "session_id"
    t.integer  "loot_id"
    t.text     "fail_detail"
  end

  create_table "vuln_details", :force => true do |t|
    t.integer  "vuln_id"
    t.float    "cvss_score"
    t.string   "cvss_vector"
    t.string   "title"
    t.text     "description"
    t.text     "solution"
    t.binary   "proof"
    t.integer  "nx_console_id"
    t.integer  "nx_device_id"
    t.string   "nx_vuln_id"
    t.float    "nx_severity"
    t.float    "nx_pci_severity"
    t.datetime "nx_published"
    t.datetime "nx_added"
    t.datetime "nx_modified"
    t.text     "nx_tags"
    t.text     "nx_vuln_status"
    t.text     "nx_proof_key"
    t.string   "src"
    t.integer  "nx_scan_id"
    t.datetime "nx_vulnerable_since"
    t.string   "nx_pci_compliance_status"
  end

  create_table "vulns", :force => true do |t|
    t.integer  "host_id"
    t.integer  "service_id"
    t.datetime "created_at"
    t.string   "name"
    t.datetime "updated_at"
    t.string   "info",               :limit => 65536
    t.datetime "exploited_at"
    t.integer  "vuln_detail_count",                   :default => 0
    t.integer  "vuln_attempt_count",                  :default => 0
  end

  add_index "vulns", ["name"], :name => "index_vulns_on_name"

  create_table "vulns_refs", :force => true do |t|
    t.integer "ref_id"
    t.integer "vuln_id"
  end

  create_table "web_forms", :force => true do |t|
    t.integer  "web_site_id",                 :null => false
    t.datetime "created_at",                  :null => false
    t.datetime "updated_at",                  :null => false
    t.text     "path"
    t.string   "method",      :limit => 1024
    t.text     "params"
    t.text     "query"
  end

  add_index "web_forms", ["path"], :name => "index_web_forms_on_path"

  create_table "web_pages", :force => true do |t|
    t.integer  "web_site_id", :null => false
    t.datetime "created_at",  :null => false
    t.datetime "updated_at",  :null => false
    t.text     "path"
    t.text     "query"
    t.integer  "code",        :null => false
    t.text     "cookie"
    t.text     "auth"
    t.text     "ctype"
    t.datetime "mtime"
    t.text     "location"
    t.text     "headers"
    t.binary   "body"
    t.binary   "request"
  end

  add_index "web_pages", ["path"], :name => "index_web_pages_on_path"
  add_index "web_pages", ["query"], :name => "index_web_pages_on_query"

  create_table "web_sites", :force => true do |t|
    t.integer  "service_id",                 :null => false
    t.datetime "created_at",                 :null => false
    t.datetime "updated_at",                 :null => false
    t.string   "vhost",      :limit => 2048
    t.text     "comments"
    t.text     "options"
  end

  add_index "web_sites", ["comments"], :name => "index_web_sites_on_comments"
  add_index "web_sites", ["options"], :name => "index_web_sites_on_options"
  add_index "web_sites", ["vhost"], :name => "index_web_sites_on_vhost"

  create_table "web_vulns", :force => true do |t|
    t.integer  "web_site_id",                 :null => false
    t.datetime "created_at",                  :null => false
    t.datetime "updated_at",                  :null => false
    t.text     "path",                        :null => false
    t.string   "method",      :limit => 1024, :null => false
    t.text     "params",                      :null => false
    t.text     "pname"
    t.integer  "risk",                        :null => false
    t.string   "name",        :limit => 1024, :null => false
    t.text     "query"
    t.text     "category",                    :null => false
    t.integer  "confidence",                  :null => false
    t.text     "description"
    t.text     "blame"
    t.binary   "request"
    t.binary   "proof",                       :null => false
    t.string   "owner"
    t.text     "payload"
  end

  add_index "web_vulns", ["method"], :name => "index_web_vulns_on_method"
  add_index "web_vulns", ["name"], :name => "index_web_vulns_on_name"
  add_index "web_vulns", ["path"], :name => "index_web_vulns_on_path"

  create_table "wmap_requests", :force => true do |t|
    t.string   "host"
    t.string   "address",    :limit => nil
    t.integer  "port"
    t.integer  "ssl"
    t.string   "meth",       :limit => 32
    t.text     "path"
    t.text     "headers"
    t.text     "query"
    t.text     "body"
    t.string   "respcode",   :limit => 16
    t.text     "resphead"
    t.text     "response"
    t.datetime "created_at"
    t.datetime "updated_at"
  end

  create_table "wmap_targets", :force => true do |t|
    t.string   "host"
    t.string   "address",    :limit => nil
    t.integer  "port"
    t.integer  "ssl"
    t.integer  "selected"
    t.datetime "created_at"
    t.datetime "updated_at"
  end

  create_table "workspace_members", :id => false, :force => true do |t|
    t.integer "workspace_id", :null => false
    t.integer "user_id",      :null => false
  end

  create_table "workspaces", :force => true do |t|
    t.string   "name"
    t.datetime "created_at",                                          :null => false
    t.datetime "updated_at",                                          :null => false
    t.string   "boundary",         :limit => 4096
    t.string   "description",      :limit => 4096
    t.integer  "owner_id"
    t.boolean  "limit_to_network",                 :default => false, :null => false
  end

end
