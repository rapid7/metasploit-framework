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
# It's strongly recommended that you check this file into your version control system.

ActiveRecord::Schema.define(version: 20190507120211) do

  # These are extensions that must be enabled in order to support this database
  enable_extension "plpgsql"

  create_table "api_keys", force: :cascade do |t|
    t.text     "token"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "async_callbacks", force: :cascade do |t|
    t.string   "uuid",           null: false
    t.integer  "timestamp",      null: false
    t.string   "listener_uri"
    t.string   "target_host"
    t.string   "target_port"
    t.datetime "created_at",     null: false
    t.datetime "updated_at",     null: false
    t.uuid     "{:null=>false}"
  end

  create_table "automatic_exploitation_match_results", force: :cascade do |t|
    t.integer  "match_id"
    t.integer  "run_id"
    t.string   "state",      null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  add_index "automatic_exploitation_match_results", ["match_id"], name: "index_automatic_exploitation_match_results_on_match_id", using: :btree
  add_index "automatic_exploitation_match_results", ["run_id"], name: "index_automatic_exploitation_match_results_on_run_id", using: :btree

  create_table "automatic_exploitation_match_sets", force: :cascade do |t|
    t.integer  "workspace_id"
    t.integer  "user_id"
    t.datetime "created_at",   null: false
    t.datetime "updated_at",   null: false
  end

  add_index "automatic_exploitation_match_sets", ["user_id"], name: "index_automatic_exploitation_match_sets_on_user_id", using: :btree
  add_index "automatic_exploitation_match_sets", ["workspace_id"], name: "index_automatic_exploitation_match_sets_on_workspace_id", using: :btree

  create_table "automatic_exploitation_matches", force: :cascade do |t|
    t.integer  "module_detail_id"
    t.string   "state"
    t.integer  "nexpose_data_vulnerability_definition_id"
    t.datetime "created_at",                               null: false
    t.datetime "updated_at",                               null: false
    t.integer  "match_set_id"
    t.string   "matchable_type"
    t.integer  "matchable_id"
    t.text     "module_fullname"
  end

  add_index "automatic_exploitation_matches", ["module_detail_id"], name: "index_automatic_exploitation_matches_on_module_detail_id", using: :btree
  add_index "automatic_exploitation_matches", ["module_fullname"], name: "index_automatic_exploitation_matches_on_module_fullname", using: :btree

  create_table "automatic_exploitation_runs", force: :cascade do |t|
    t.integer  "workspace_id"
    t.integer  "user_id"
    t.integer  "match_set_id"
    t.datetime "created_at",   null: false
    t.datetime "updated_at",   null: false
  end

  add_index "automatic_exploitation_runs", ["match_set_id"], name: "index_automatic_exploitation_runs_on_match_set_id", using: :btree
  add_index "automatic_exploitation_runs", ["user_id"], name: "index_automatic_exploitation_runs_on_user_id", using: :btree
  add_index "automatic_exploitation_runs", ["workspace_id"], name: "index_automatic_exploitation_runs_on_workspace_id", using: :btree

  create_table "clients", force: :cascade do |t|
    t.integer  "host_id"
    t.datetime "created_at"
    t.string   "ua_string",  limit: 1024, null: false
    t.string   "ua_name",    limit: 64
    t.string   "ua_ver",     limit: 32
    t.datetime "updated_at"
  end

  create_table "credential_cores_tasks", id: false, force: :cascade do |t|
    t.integer "core_id"
    t.integer "task_id"
  end

  create_table "credential_logins_tasks", id: false, force: :cascade do |t|
    t.integer "login_id"
    t.integer "task_id"
  end

  create_table "creds", force: :cascade do |t|
    t.integer  "service_id",                              null: false
    t.datetime "created_at",                              null: false
    t.datetime "updated_at",                              null: false
    t.string   "user",        limit: 2048
    t.string   "pass",        limit: 4096
    t.boolean  "active",                   default: true
    t.string   "proof",       limit: 4096
    t.string   "ptype",       limit: 256
    t.integer  "source_id"
    t.string   "source_type"
  end

  create_table "events", force: :cascade do |t|
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

  create_table "exploit_attempts", force: :cascade do |t|
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

  create_table "exploited_hosts", force: :cascade do |t|
    t.integer  "host_id",                   null: false
    t.integer  "service_id"
    t.string   "session_uuid", limit: 8
    t.string   "name",         limit: 2048
    t.string   "payload",      limit: 2048
    t.datetime "created_at",                null: false
    t.datetime "updated_at",                null: false
  end

  create_table "host_details", force: :cascade do |t|
    t.integer "host_id"
    t.integer "nx_console_id"
    t.integer "nx_device_id"
    t.string  "src"
    t.string  "nx_site_name"
    t.string  "nx_site_importance"
    t.string  "nx_scan_template"
    t.float   "nx_risk_score"
  end

  create_table "hosts", force: :cascade do |t|
    t.datetime "created_at"
    t.inet     "address",                                         null: false
    t.string   "mac"
    t.string   "comm"
    t.string   "name"
    t.string   "state"
    t.string   "os_name"
    t.string   "os_flavor"
    t.string   "os_sp"
    t.string   "os_lang"
    t.string   "arch"
    t.integer  "workspace_id",                                    null: false
    t.datetime "updated_at"
    t.text     "purpose"
    t.string   "info",                  limit: 65536
    t.text     "comments"
    t.text     "scope"
    t.text     "virtual_host"
    t.integer  "note_count",                          default: 0
    t.integer  "vuln_count",                          default: 0
    t.integer  "service_count",                       default: 0
    t.integer  "host_detail_count",                   default: 0
    t.integer  "exploit_attempt_count",               default: 0
    t.integer  "cred_count",                          default: 0
    t.string   "detected_arch"
    t.string   "os_family"
  end

  add_index "hosts", ["name"], name: "index_hosts_on_name", using: :btree
  add_index "hosts", ["os_flavor"], name: "index_hosts_on_os_flavor", using: :btree
  add_index "hosts", ["os_name"], name: "index_hosts_on_os_name", using: :btree
  add_index "hosts", ["purpose"], name: "index_hosts_on_purpose", using: :btree
  add_index "hosts", ["state"], name: "index_hosts_on_state", using: :btree
  add_index "hosts", ["workspace_id", "address"], name: "index_hosts_on_workspace_id_and_address", unique: true, using: :btree

  create_table "hosts_tags", force: :cascade do |t|
    t.integer "host_id"
    t.integer "tag_id"
  end

  create_table "listeners", force: :cascade do |t|
    t.datetime "created_at",                  null: false
    t.datetime "updated_at",                  null: false
    t.integer  "workspace_id", default: 1,    null: false
    t.integer  "task_id"
    t.boolean  "enabled",      default: true
    t.text     "owner"
    t.text     "payload"
    t.text     "address"
    t.integer  "port"
    t.binary   "options"
    t.text     "macro"
  end

  create_table "loots", force: :cascade do |t|
    t.integer  "workspace_id",               default: 1, null: false
    t.integer  "host_id"
    t.integer  "service_id"
    t.string   "ltype",         limit: 512
    t.string   "path",          limit: 1024
    t.text     "data"
    t.datetime "created_at",                             null: false
    t.datetime "updated_at",                             null: false
    t.string   "content_type"
    t.text     "name"
    t.text     "info"
    t.integer  "module_run_id"
  end

  add_index "loots", ["module_run_id"], name: "index_loots_on_module_run_id", using: :btree

  create_table "macros", force: :cascade do |t|
    t.datetime "created_at",  null: false
    t.datetime "updated_at",  null: false
    t.text     "owner"
    t.text     "name"
    t.text     "description"
    t.binary   "actions"
    t.binary   "prefs"
  end

  create_table "metasploit_credential_cores", force: :cascade do |t|
    t.integer  "origin_id",                null: false
    t.string   "origin_type",              null: false
    t.integer  "private_id"
    t.integer  "public_id"
    t.integer  "realm_id"
    t.integer  "workspace_id",             null: false
    t.datetime "created_at",               null: false
    t.datetime "updated_at",               null: false
    t.integer  "logins_count", default: 0
  end

  add_index "metasploit_credential_cores", ["origin_type", "origin_id"], name: "index_metasploit_credential_cores_on_origin_type_and_origin_id", using: :btree
  add_index "metasploit_credential_cores", ["private_id"], name: "index_metasploit_credential_cores_on_private_id", using: :btree
  add_index "metasploit_credential_cores", ["public_id"], name: "index_metasploit_credential_cores_on_public_id", using: :btree
  add_index "metasploit_credential_cores", ["realm_id"], name: "index_metasploit_credential_cores_on_realm_id", using: :btree
  add_index "metasploit_credential_cores", ["workspace_id", "private_id"], name: "unique_private_metasploit_credential_cores", unique: true, where: "((realm_id IS NULL) AND (public_id IS NULL) AND (private_id IS NOT NULL))", using: :btree
  add_index "metasploit_credential_cores", ["workspace_id", "public_id", "private_id"], name: "unique_realmless_metasploit_credential_cores", unique: true, where: "((realm_id IS NULL) AND (public_id IS NOT NULL) AND (private_id IS NOT NULL))", using: :btree
  add_index "metasploit_credential_cores", ["workspace_id", "public_id"], name: "unique_public_metasploit_credential_cores", unique: true, where: "((realm_id IS NULL) AND (public_id IS NOT NULL) AND (private_id IS NULL))", using: :btree
  add_index "metasploit_credential_cores", ["workspace_id", "realm_id", "private_id"], name: "unique_publicless_metasploit_credential_cores", unique: true, where: "((realm_id IS NOT NULL) AND (public_id IS NULL) AND (private_id IS NOT NULL))", using: :btree
  add_index "metasploit_credential_cores", ["workspace_id", "realm_id", "public_id", "private_id"], name: "unique_complete_metasploit_credential_cores", unique: true, where: "((realm_id IS NOT NULL) AND (public_id IS NOT NULL) AND (private_id IS NOT NULL))", using: :btree
  add_index "metasploit_credential_cores", ["workspace_id", "realm_id", "public_id"], name: "unique_privateless_metasploit_credential_cores", unique: true, where: "((realm_id IS NOT NULL) AND (public_id IS NOT NULL) AND (private_id IS NULL))", using: :btree
  add_index "metasploit_credential_cores", ["workspace_id"], name: "index_metasploit_credential_cores_on_workspace_id", using: :btree

  create_table "metasploit_credential_logins", force: :cascade do |t|
    t.integer  "core_id",           null: false
    t.integer  "service_id",        null: false
    t.string   "access_level"
    t.string   "status",            null: false
    t.datetime "last_attempted_at"
    t.datetime "created_at",        null: false
    t.datetime "updated_at",        null: false
  end

  add_index "metasploit_credential_logins", ["core_id", "service_id"], name: "index_metasploit_credential_logins_on_core_id_and_service_id", unique: true, using: :btree
  add_index "metasploit_credential_logins", ["service_id", "core_id"], name: "index_metasploit_credential_logins_on_service_id_and_core_id", unique: true, using: :btree

  create_table "metasploit_credential_origin_cracked_passwords", force: :cascade do |t|
    t.integer  "metasploit_credential_core_id", null: false
    t.datetime "created_at",                    null: false
    t.datetime "updated_at",                    null: false
  end

  add_index "metasploit_credential_origin_cracked_passwords", ["metasploit_credential_core_id"], name: "originating_credential_cores", using: :btree

  create_table "metasploit_credential_origin_imports", force: :cascade do |t|
    t.text     "filename",   null: false
    t.integer  "task_id"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  add_index "metasploit_credential_origin_imports", ["task_id"], name: "index_metasploit_credential_origin_imports_on_task_id", using: :btree

  create_table "metasploit_credential_origin_manuals", force: :cascade do |t|
    t.integer  "user_id",    null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  add_index "metasploit_credential_origin_manuals", ["user_id"], name: "index_metasploit_credential_origin_manuals_on_user_id", using: :btree

  create_table "metasploit_credential_origin_services", force: :cascade do |t|
    t.integer  "service_id",       null: false
    t.text     "module_full_name", null: false
    t.datetime "created_at",       null: false
    t.datetime "updated_at",       null: false
  end

  add_index "metasploit_credential_origin_services", ["service_id", "module_full_name"], name: "unique_metasploit_credential_origin_services", unique: true, using: :btree

  create_table "metasploit_credential_origin_sessions", force: :cascade do |t|
    t.text     "post_reference_name", null: false
    t.integer  "session_id",          null: false
    t.datetime "created_at",          null: false
    t.datetime "updated_at",          null: false
  end

  add_index "metasploit_credential_origin_sessions", ["session_id", "post_reference_name"], name: "unique_metasploit_credential_origin_sessions", unique: true, using: :btree

  create_table "metasploit_credential_privates", force: :cascade do |t|
    t.string   "type",       null: false
    t.text     "data",       null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.string   "jtr_format"
  end

  add_index "metasploit_credential_privates", ["type", "data"], name: "index_metasploit_credential_privates_on_type_and_data", unique: true, where: "(NOT ((type)::text = 'Metasploit::Credential::SSHKey'::text))", using: :btree
  add_index "metasploit_credential_privates", ["type"], name: "index_metasploit_credential_privates_on_type_and_data_sshkey", unique: true, where: "((type)::text = 'Metasploit::Credential::SSHKey'::text)", using: :btree

  create_table "metasploit_credential_publics", force: :cascade do |t|
    t.string   "username",   null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.string   "type",       null: false
  end

  add_index "metasploit_credential_publics", ["username"], name: "index_metasploit_credential_publics_on_username", unique: true, using: :btree

  create_table "metasploit_credential_realms", force: :cascade do |t|
    t.string   "key",        null: false
    t.string   "value",      null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  add_index "metasploit_credential_realms", ["key", "value"], name: "index_metasploit_credential_realms_on_key_and_value", unique: true, using: :btree

  create_table "mod_refs", force: :cascade do |t|
    t.string "module", limit: 1024
    t.string "mtype",  limit: 128
    t.text   "ref"
  end

  create_table "module_actions", force: :cascade do |t|
    t.integer "detail_id"
    t.text    "name"
  end

  add_index "module_actions", ["detail_id"], name: "index_module_actions_on_detail_id", using: :btree

  create_table "module_archs", force: :cascade do |t|
    t.integer "detail_id"
    t.text    "name"
  end

  add_index "module_archs", ["detail_id"], name: "index_module_archs_on_detail_id", using: :btree

  create_table "module_authors", force: :cascade do |t|
    t.integer "detail_id"
    t.text    "name"
    t.text    "email"
  end

  add_index "module_authors", ["detail_id"], name: "index_module_authors_on_detail_id", using: :btree

  create_table "module_details", force: :cascade do |t|
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

  add_index "module_details", ["description"], name: "index_module_details_on_description", using: :btree
  add_index "module_details", ["mtype"], name: "index_module_details_on_mtype", using: :btree
  add_index "module_details", ["name"], name: "index_module_details_on_name", using: :btree
  add_index "module_details", ["refname"], name: "index_module_details_on_refname", using: :btree

  create_table "module_mixins", force: :cascade do |t|
    t.integer "detail_id"
    t.text    "name"
  end

  add_index "module_mixins", ["detail_id"], name: "index_module_mixins_on_detail_id", using: :btree

  create_table "module_platforms", force: :cascade do |t|
    t.integer "detail_id"
    t.text    "name"
  end

  add_index "module_platforms", ["detail_id"], name: "index_module_platforms_on_detail_id", using: :btree

  create_table "module_refs", force: :cascade do |t|
    t.integer "detail_id"
    t.text    "name"
  end

  add_index "module_refs", ["detail_id"], name: "index_module_refs_on_detail_id", using: :btree
  add_index "module_refs", ["name"], name: "index_module_refs_on_name", using: :btree

  create_table "module_runs", force: :cascade do |t|
    t.datetime "attempted_at"
    t.text     "fail_detail"
    t.string   "fail_reason"
    t.text     "module_fullname"
    t.integer  "port"
    t.string   "proto"
    t.integer  "session_id"
    t.string   "status"
    t.integer  "trackable_id"
    t.string   "trackable_type"
    t.integer  "user_id"
    t.string   "username"
    t.datetime "created_at",      null: false
    t.datetime "updated_at",      null: false
  end

  add_index "module_runs", ["session_id"], name: "index_module_runs_on_session_id", using: :btree
  add_index "module_runs", ["user_id"], name: "index_module_runs_on_user_id", using: :btree

  create_table "module_targets", force: :cascade do |t|
    t.integer "detail_id"
    t.integer "index"
    t.text    "name"
  end

  add_index "module_targets", ["detail_id"], name: "index_module_targets_on_detail_id", using: :btree

  create_table "nexpose_consoles", force: :cascade do |t|
    t.datetime "created_at",                  null: false
    t.datetime "updated_at",                  null: false
    t.boolean  "enabled",      default: true
    t.text     "owner"
    t.text     "address"
    t.integer  "port",         default: 3780
    t.text     "username"
    t.text     "password"
    t.text     "status"
    t.text     "version"
    t.text     "cert"
    t.binary   "cached_sites"
    t.text     "name"
  end

  create_table "notes", force: :cascade do |t|
    t.datetime "created_at"
    t.string   "ntype",        limit: 512
    t.integer  "workspace_id",             default: 1, null: false
    t.integer  "service_id"
    t.integer  "host_id"
    t.datetime "updated_at"
    t.boolean  "critical"
    t.boolean  "seen"
    t.text     "data"
    t.integer  "vuln_id"
  end

  add_index "notes", ["ntype"], name: "index_notes_on_ntype", using: :btree
  add_index "notes", ["vuln_id"], name: "index_notes_on_vuln_id", using: :btree

  create_table "payloads", force: :cascade do |t|
    t.string   "name"
    t.string   "uuid"
    t.integer  "uuid_mask"
    t.integer  "timestamp"
    t.string   "arch"
    t.string   "platform"
    t.string   "urls"
    t.string   "description"
    t.string   "raw_payload"
    t.string   "raw_payload_hash"
    t.string   "build_status"
    t.string   "build_opts"
    t.datetime "created_at",       null: false
    t.datetime "updated_at",       null: false
  end

  create_table "profiles", force: :cascade do |t|
    t.datetime "created_at",                null: false
    t.datetime "updated_at",                null: false
    t.boolean  "active",     default: true
    t.text     "name"
    t.text     "owner"
    t.binary   "settings"
  end

  create_table "refs", force: :cascade do |t|
    t.integer  "ref_id"
    t.datetime "created_at"
    t.string   "name",       limit: 512
    t.datetime "updated_at"
  end

  add_index "refs", ["name"], name: "index_refs_on_name", using: :btree

  create_table "report_templates", force: :cascade do |t|
    t.integer  "workspace_id",              default: 1, null: false
    t.string   "created_by"
    t.string   "path",         limit: 1024
    t.text     "name"
    t.datetime "created_at",                            null: false
    t.datetime "updated_at",                            null: false
  end

  create_table "reports", force: :cascade do |t|
    t.integer  "workspace_id",               default: 1, null: false
    t.string   "created_by"
    t.string   "rtype"
    t.string   "path",          limit: 1024
    t.text     "options"
    t.datetime "created_at",                             null: false
    t.datetime "updated_at",                             null: false
    t.datetime "downloaded_at"
    t.integer  "task_id"
    t.string   "name",          limit: 63
  end

  create_table "routes", force: :cascade do |t|
    t.integer "session_id"
    t.string  "subnet"
    t.string  "netmask"
  end

  create_table "services", force: :cascade do |t|
    t.integer  "host_id"
    t.datetime "created_at"
    t.integer  "port",                  null: false
    t.string   "proto",      limit: 16, null: false
    t.string   "state"
    t.string   "name"
    t.datetime "updated_at"
    t.text     "info"
  end

  add_index "services", ["host_id", "port", "proto"], name: "index_services_on_host_id_and_port_and_proto", unique: true, using: :btree
  add_index "services", ["name"], name: "index_services_on_name", using: :btree
  add_index "services", ["port"], name: "index_services_on_port", using: :btree
  add_index "services", ["proto"], name: "index_services_on_proto", using: :btree
  add_index "services", ["state"], name: "index_services_on_state", using: :btree

  create_table "session_events", force: :cascade do |t|
    t.integer  "session_id"
    t.string   "etype"
    t.binary   "command"
    t.binary   "output"
    t.string   "remote_path"
    t.string   "local_path"
    t.datetime "created_at"
  end

  create_table "sessions", force: :cascade do |t|
    t.integer  "host_id"
    t.string   "stype"
    t.string   "via_exploit"
    t.string   "via_payload"
    t.string   "desc"
    t.integer  "port"
    t.string   "platform"
    t.text     "datastore"
    t.datetime "opened_at",     null: false
    t.datetime "closed_at"
    t.string   "close_reason"
    t.integer  "local_id"
    t.datetime "last_seen"
    t.integer  "module_run_id"
  end

  add_index "sessions", ["module_run_id"], name: "index_sessions_on_module_run_id", using: :btree

  create_table "tags", force: :cascade do |t|
    t.integer  "user_id"
    t.string   "name",           limit: 1024
    t.text     "desc"
    t.boolean  "report_summary",              default: false, null: false
    t.boolean  "report_detail",               default: false, null: false
    t.boolean  "critical",                    default: false, null: false
    t.datetime "created_at",                                  null: false
    t.datetime "updated_at",                                  null: false
  end

  create_table "task_creds", force: :cascade do |t|
    t.integer  "task_id",    null: false
    t.integer  "cred_id",    null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "task_hosts", force: :cascade do |t|
    t.integer  "task_id",    null: false
    t.integer  "host_id",    null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "task_services", force: :cascade do |t|
    t.integer  "task_id",    null: false
    t.integer  "service_id", null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "task_sessions", force: :cascade do |t|
    t.integer  "task_id",    null: false
    t.integer  "session_id", null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "tasks", force: :cascade do |t|
    t.integer  "workspace_id",              default: 1, null: false
    t.string   "created_by"
    t.string   "module"
    t.datetime "completed_at"
    t.string   "path",         limit: 1024
    t.string   "info"
    t.string   "description"
    t.integer  "progress"
    t.text     "options"
    t.text     "error"
    t.datetime "created_at",                            null: false
    t.datetime "updated_at",                            null: false
    t.text     "result"
    t.string   "module_uuid",  limit: 8
    t.binary   "settings"
  end

  create_table "users", force: :cascade do |t|
    t.string   "username"
    t.string   "crypted_password"
    t.string   "password_salt"
    t.string   "persistence_token"
    t.datetime "created_at",                                      null: false
    t.datetime "updated_at",                                      null: false
    t.string   "fullname"
    t.string   "email"
    t.string   "phone"
    t.string   "company"
    t.string   "prefs",             limit: 524288
    t.boolean  "admin",                            default: true, null: false
  end

  create_table "vuln_attempts", force: :cascade do |t|
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

  create_table "vuln_details", force: :cascade do |t|
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

  create_table "vulns", force: :cascade do |t|
    t.integer  "host_id"
    t.integer  "service_id"
    t.datetime "created_at"
    t.string   "name"
    t.datetime "updated_at"
    t.string   "info",               limit: 65536
    t.datetime "exploited_at"
    t.integer  "vuln_detail_count",                default: 0
    t.integer  "vuln_attempt_count",               default: 0
    t.integer  "origin_id"
    t.string   "origin_type"
  end

  add_index "vulns", ["name"], name: "index_vulns_on_name", using: :btree
  add_index "vulns", ["origin_id"], name: "index_vulns_on_origin_id", using: :btree

  create_table "vulns_refs", force: :cascade do |t|
    t.integer "ref_id"
    t.integer "vuln_id"
  end

  create_table "web_forms", force: :cascade do |t|
    t.integer  "web_site_id",              null: false
    t.datetime "created_at",               null: false
    t.datetime "updated_at",               null: false
    t.text     "path"
    t.string   "method",      limit: 1024
    t.text     "params"
    t.text     "query"
  end

  add_index "web_forms", ["path"], name: "index_web_forms_on_path", using: :btree

  create_table "web_pages", force: :cascade do |t|
    t.integer  "web_site_id", null: false
    t.datetime "created_at",  null: false
    t.datetime "updated_at",  null: false
    t.text     "path"
    t.text     "query"
    t.integer  "code",        null: false
    t.text     "cookie"
    t.text     "auth"
    t.text     "ctype"
    t.datetime "mtime"
    t.text     "location"
    t.text     "headers"
    t.binary   "body"
    t.binary   "request"
  end

  add_index "web_pages", ["path"], name: "index_web_pages_on_path", using: :btree
  add_index "web_pages", ["query"], name: "index_web_pages_on_query", using: :btree

  create_table "web_sites", force: :cascade do |t|
    t.integer  "service_id",              null: false
    t.datetime "created_at",              null: false
    t.datetime "updated_at",              null: false
    t.string   "vhost",      limit: 2048
    t.text     "comments"
    t.text     "options"
  end

  add_index "web_sites", ["comments"], name: "index_web_sites_on_comments", using: :btree
  add_index "web_sites", ["options"], name: "index_web_sites_on_options", using: :btree
  add_index "web_sites", ["vhost"], name: "index_web_sites_on_vhost", using: :btree

  create_table "web_vulns", force: :cascade do |t|
    t.integer  "web_site_id",              null: false
    t.datetime "created_at",               null: false
    t.datetime "updated_at",               null: false
    t.text     "path",                     null: false
    t.string   "method",      limit: 1024, null: false
    t.text     "params"
    t.text     "pname"
    t.integer  "risk",                     null: false
    t.string   "name",        limit: 1024, null: false
    t.text     "query"
    t.text     "category",                 null: false
    t.integer  "confidence",               null: false
    t.text     "description"
    t.text     "blame"
    t.binary   "request"
    t.binary   "proof",                    null: false
    t.string   "owner"
    t.text     "payload"
  end

  add_index "web_vulns", ["method"], name: "index_web_vulns_on_method", using: :btree
  add_index "web_vulns", ["name"], name: "index_web_vulns_on_name", using: :btree
  add_index "web_vulns", ["path"], name: "index_web_vulns_on_path", using: :btree

  create_table "wmap_requests", force: :cascade do |t|
    t.string   "host"
    t.inet     "address"
    t.integer  "port"
    t.integer  "ssl"
    t.string   "meth",       limit: 32
    t.text     "path"
    t.text     "headers"
    t.text     "query"
    t.text     "body"
    t.string   "respcode",   limit: 16
    t.text     "resphead"
    t.text     "response"
    t.datetime "created_at"
    t.datetime "updated_at"
  end

  create_table "wmap_targets", force: :cascade do |t|
    t.string   "host"
    t.inet     "address"
    t.integer  "port"
    t.integer  "ssl"
    t.integer  "selected"
    t.datetime "created_at"
    t.datetime "updated_at"
  end

  create_table "workspace_members", id: false, force: :cascade do |t|
    t.integer "workspace_id", null: false
    t.integer "user_id",      null: false
  end

  create_table "workspaces", force: :cascade do |t|
    t.string   "name"
    t.datetime "created_at",                                      null: false
    t.datetime "updated_at",                                      null: false
    t.string   "boundary",           limit: 4096
    t.string   "description",        limit: 4096
    t.integer  "owner_id"
    t.boolean  "limit_to_network",                default: false, null: false
    t.boolean  "import_fingerprint",              default: false
  end

end
