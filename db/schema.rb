# This file is auto-generated from the current state of the database. Instead
# of editing this file, please use the migrations feature of Active Record to
# incrementally modify your database, and then regenerate this schema definition.
#
# This file is the source Rails uses to define your schema when running `bin/rails
# db:schema:load`. When creating a new database, `bin/rails db:schema:load` tends to
# be faster and is potentially less error prone than running all of your
# migrations from scratch. Old migrations may fail to apply correctly if those
# migrations use external dependencies or application code.
#
# It's strongly recommended that you check this file into your version control system.

ActiveRecord::Schema[7.1].define(version: 2025_02_04_172657) do
  # These are extensions that must be enabled in order to support this database
  enable_extension "plpgsql"

  create_table "api_keys", id: :serial, force: :cascade do |t|
    t.text "token"
    t.datetime "created_at", precision: nil, null: false
    t.datetime "updated_at", precision: nil, null: false
  end

  create_table "async_callbacks", id: :serial, force: :cascade do |t|
    t.string "uuid", null: false
    t.integer "timestamp", null: false
    t.string "listener_uri"
    t.string "target_host"
    t.string "target_port"
    t.datetime "created_at", precision: nil, null: false
    t.datetime "updated_at", precision: nil, null: false
  end

  create_table "automatic_exploitation_match_results", id: :serial, force: :cascade do |t|
    t.integer "match_id"
    t.integer "run_id"
    t.string "state", null: false
    t.datetime "created_at", precision: nil, null: false
    t.datetime "updated_at", precision: nil, null: false
    t.index ["match_id"], name: "index_automatic_exploitation_match_results_on_match_id"
    t.index ["run_id"], name: "index_automatic_exploitation_match_results_on_run_id"
  end

  create_table "automatic_exploitation_match_sets", id: :serial, force: :cascade do |t|
    t.integer "workspace_id"
    t.integer "user_id"
    t.datetime "created_at", precision: nil, null: false
    t.datetime "updated_at", precision: nil, null: false
    t.index ["user_id"], name: "index_automatic_exploitation_match_sets_on_user_id"
    t.index ["workspace_id"], name: "index_automatic_exploitation_match_sets_on_workspace_id"
  end

  create_table "automatic_exploitation_matches", id: :serial, force: :cascade do |t|
    t.integer "module_detail_id"
    t.string "state"
    t.integer "nexpose_data_vulnerability_definition_id"
    t.datetime "created_at", precision: nil, null: false
    t.datetime "updated_at", precision: nil, null: false
    t.integer "match_set_id"
    t.string "matchable_type"
    t.integer "matchable_id"
    t.text "module_fullname"
    t.index ["module_detail_id"], name: "index_automatic_exploitation_matches_on_module_detail_id"
    t.index ["module_fullname"], name: "index_automatic_exploitation_matches_on_module_fullname"
  end

  create_table "automatic_exploitation_runs", id: :serial, force: :cascade do |t|
    t.integer "workspace_id"
    t.integer "user_id"
    t.integer "match_set_id"
    t.datetime "created_at", precision: nil, null: false
    t.datetime "updated_at", precision: nil, null: false
    t.index ["match_set_id"], name: "index_automatic_exploitation_runs_on_match_set_id"
    t.index ["user_id"], name: "index_automatic_exploitation_runs_on_user_id"
    t.index ["workspace_id"], name: "index_automatic_exploitation_runs_on_workspace_id"
  end

  create_table "clients", id: :serial, force: :cascade do |t|
    t.integer "host_id"
    t.datetime "created_at", precision: nil
    t.string "ua_string", limit: 1024, null: false
    t.string "ua_name", limit: 64
    t.string "ua_ver", limit: 32
    t.datetime "updated_at", precision: nil
  end

  create_table "credential_cores_tasks", id: false, force: :cascade do |t|
    t.integer "core_id"
    t.integer "task_id"
  end

  create_table "credential_logins_tasks", id: false, force: :cascade do |t|
    t.integer "login_id"
    t.integer "task_id"
  end

  create_table "creds", id: :serial, force: :cascade do |t|
    t.integer "service_id", null: false
    t.datetime "created_at", precision: nil, null: false
    t.datetime "updated_at", precision: nil, null: false
    t.string "user", limit: 2048
    t.string "pass", limit: 4096
    t.boolean "active", default: true
    t.string "proof", limit: 4096
    t.string "ptype", limit: 256
    t.integer "source_id"
    t.string "source_type"
  end

  create_table "events", id: :serial, force: :cascade do |t|
    t.integer "workspace_id"
    t.integer "host_id"
    t.datetime "created_at", precision: nil
    t.string "name"
    t.datetime "updated_at", precision: nil
    t.boolean "critical"
    t.boolean "seen"
    t.string "username"
    t.text "info"
  end

  create_table "exploit_attempts", id: :serial, force: :cascade do |t|
    t.integer "host_id"
    t.integer "service_id"
    t.integer "vuln_id"
    t.datetime "attempted_at", precision: nil
    t.boolean "exploited"
    t.string "fail_reason"
    t.string "username"
    t.text "module"
    t.integer "session_id"
    t.integer "loot_id"
    t.integer "port"
    t.string "proto"
    t.text "fail_detail"
  end

  create_table "exploited_hosts", id: :serial, force: :cascade do |t|
    t.integer "host_id", null: false
    t.integer "service_id"
    t.string "session_uuid", limit: 8
    t.string "name", limit: 2048
    t.string "payload", limit: 2048
    t.datetime "created_at", precision: nil, null: false
    t.datetime "updated_at", precision: nil, null: false
  end

  create_table "host_details", id: :serial, force: :cascade do |t|
    t.integer "host_id"
    t.integer "nx_console_id"
    t.integer "nx_device_id"
    t.string "src"
    t.string "nx_site_name"
    t.string "nx_site_importance"
    t.string "nx_scan_template"
    t.float "nx_risk_score"
  end

  create_table "hosts", id: :serial, force: :cascade do |t|
    t.datetime "created_at", precision: nil
    t.inet "address", null: false
    t.string "mac"
    t.string "comm"
    t.string "name"
    t.string "state"
    t.string "os_name"
    t.string "os_flavor"
    t.string "os_sp"
    t.string "os_lang"
    t.string "arch"
    t.integer "workspace_id", null: false
    t.datetime "updated_at", precision: nil
    t.text "purpose"
    t.string "info", limit: 65536
    t.text "comments"
    t.text "scope"
    t.text "virtual_host"
    t.integer "note_count", default: 0
    t.integer "vuln_count", default: 0
    t.integer "service_count", default: 0
    t.integer "host_detail_count", default: 0
    t.integer "exploit_attempt_count", default: 0
    t.integer "cred_count", default: 0
    t.string "detected_arch"
    t.string "os_family"
    t.index ["name"], name: "index_hosts_on_name"
    t.index ["os_flavor"], name: "index_hosts_on_os_flavor"
    t.index ["os_name"], name: "index_hosts_on_os_name"
    t.index ["purpose"], name: "index_hosts_on_purpose"
    t.index ["state"], name: "index_hosts_on_state"
    t.index ["workspace_id", "address"], name: "index_hosts_on_workspace_id_and_address", unique: true
  end

  create_table "hosts_tags", id: :serial, force: :cascade do |t|
    t.integer "host_id"
    t.integer "tag_id"
  end

  create_table "listeners", id: :serial, force: :cascade do |t|
    t.datetime "created_at", precision: nil, null: false
    t.datetime "updated_at", precision: nil, null: false
    t.integer "workspace_id", default: 1, null: false
    t.integer "task_id"
    t.boolean "enabled", default: true
    t.text "owner"
    t.text "payload"
    t.text "address"
    t.integer "port"
    t.binary "options"
    t.text "macro"
  end

  create_table "loots", id: :serial, force: :cascade do |t|
    t.integer "workspace_id", default: 1, null: false
    t.integer "host_id"
    t.integer "service_id"
    t.string "ltype", limit: 512
    t.string "path", limit: 1024
    t.text "data"
    t.datetime "created_at", precision: nil, null: false
    t.datetime "updated_at", precision: nil, null: false
    t.string "content_type"
    t.text "name"
    t.text "info"
    t.integer "module_run_id"
    t.index ["module_run_id"], name: "index_loots_on_module_run_id"
  end

  create_table "macros", id: :serial, force: :cascade do |t|
    t.datetime "created_at", precision: nil, null: false
    t.datetime "updated_at", precision: nil, null: false
    t.text "owner"
    t.text "name"
    t.text "description"
    t.binary "actions"
    t.binary "prefs"
  end

  create_table "metasploit_credential_cores", id: :serial, force: :cascade do |t|
    t.string "origin_type", null: false
    t.integer "origin_id", null: false
    t.integer "private_id"
    t.integer "public_id"
    t.integer "realm_id"
    t.integer "workspace_id", null: false
    t.datetime "created_at", precision: nil, null: false
    t.datetime "updated_at", precision: nil, null: false
    t.integer "logins_count", default: 0
    t.index ["origin_type", "origin_id"], name: "index_metasploit_credential_cores_on_origin_type_and_origin_id"
    t.index ["private_id"], name: "index_metasploit_credential_cores_on_private_id"
    t.index ["public_id"], name: "index_metasploit_credential_cores_on_public_id"
    t.index ["realm_id"], name: "index_metasploit_credential_cores_on_realm_id"
    t.index ["workspace_id", "private_id"], name: "unique_private_metasploit_credential_cores", unique: true, where: "((realm_id IS NULL) AND (public_id IS NULL) AND (private_id IS NOT NULL))"
    t.index ["workspace_id", "public_id", "private_id"], name: "unique_realmless_metasploit_credential_cores", unique: true, where: "((realm_id IS NULL) AND (public_id IS NOT NULL) AND (private_id IS NOT NULL))"
    t.index ["workspace_id", "public_id"], name: "unique_public_metasploit_credential_cores", unique: true, where: "((realm_id IS NULL) AND (public_id IS NOT NULL) AND (private_id IS NULL))"
    t.index ["workspace_id", "realm_id", "private_id"], name: "unique_publicless_metasploit_credential_cores", unique: true, where: "((realm_id IS NOT NULL) AND (public_id IS NULL) AND (private_id IS NOT NULL))"
    t.index ["workspace_id", "realm_id", "public_id", "private_id"], name: "unique_complete_metasploit_credential_cores", unique: true, where: "((realm_id IS NOT NULL) AND (public_id IS NOT NULL) AND (private_id IS NOT NULL))"
    t.index ["workspace_id", "realm_id", "public_id"], name: "unique_privateless_metasploit_credential_cores", unique: true, where: "((realm_id IS NOT NULL) AND (public_id IS NOT NULL) AND (private_id IS NULL))"
    t.index ["workspace_id"], name: "index_metasploit_credential_cores_on_workspace_id"
  end

  create_table "metasploit_credential_logins", id: :serial, force: :cascade do |t|
    t.integer "core_id", null: false
    t.integer "service_id", null: false
    t.string "access_level"
    t.string "status", null: false
    t.datetime "last_attempted_at", precision: nil
    t.datetime "created_at", precision: nil, null: false
    t.datetime "updated_at", precision: nil, null: false
    t.index ["core_id", "service_id"], name: "index_metasploit_credential_logins_on_core_id_and_service_id", unique: true
    t.index ["service_id", "core_id"], name: "index_metasploit_credential_logins_on_service_id_and_core_id", unique: true
  end

  create_table "metasploit_credential_origin_cracked_passwords", id: :serial, force: :cascade do |t|
    t.integer "metasploit_credential_core_id", null: false
    t.datetime "created_at", precision: nil, null: false
    t.datetime "updated_at", precision: nil, null: false
    t.index ["metasploit_credential_core_id"], name: "originating_credential_cores"
  end

  create_table "metasploit_credential_origin_imports", id: :serial, force: :cascade do |t|
    t.text "filename", null: false
    t.integer "task_id"
    t.datetime "created_at", precision: nil, null: false
    t.datetime "updated_at", precision: nil, null: false
    t.index ["task_id"], name: "index_metasploit_credential_origin_imports_on_task_id"
  end

  create_table "metasploit_credential_origin_manuals", id: :serial, force: :cascade do |t|
    t.integer "user_id", null: false
    t.datetime "created_at", precision: nil, null: false
    t.datetime "updated_at", precision: nil, null: false
    t.index ["user_id"], name: "index_metasploit_credential_origin_manuals_on_user_id"
  end

  create_table "metasploit_credential_origin_services", id: :serial, force: :cascade do |t|
    t.integer "service_id", null: false
    t.text "module_full_name", null: false
    t.datetime "created_at", precision: nil, null: false
    t.datetime "updated_at", precision: nil, null: false
    t.index ["service_id", "module_full_name"], name: "unique_metasploit_credential_origin_services", unique: true
  end

  create_table "metasploit_credential_origin_sessions", id: :serial, force: :cascade do |t|
    t.text "post_reference_name", null: false
    t.integer "session_id", null: false
    t.datetime "created_at", precision: nil, null: false
    t.datetime "updated_at", precision: nil, null: false
    t.index ["session_id", "post_reference_name"], name: "unique_metasploit_credential_origin_sessions", unique: true
  end

  create_table "metasploit_credential_privates", id: :serial, force: :cascade do |t|
    t.string "type", null: false
    t.text "data", null: false
    t.datetime "created_at", precision: nil, null: false
    t.datetime "updated_at", precision: nil, null: false
    t.string "jtr_format"
    t.jsonb "metadata", default: {}, null: false
    t.index "type, decode(md5(data), 'hex'::text)", name: "index_metasploit_credential_privates_on_type_and_data_pkcs12", unique: true, where: "((type)::text = 'Metasploit::Credential::Pkcs12'::text)"
    t.index "type, decode(md5(data), 'hex'::text)", name: "index_metasploit_credential_privates_on_type_and_data_sshkey", unique: true, where: "((type)::text = 'Metasploit::Credential::SSHKey'::text)"
    t.index ["type", "data"], name: "index_metasploit_credential_privates_on_type_and_data", unique: true, where: "(NOT (((type)::text = 'Metasploit::Credential::SSHKey'::text) OR ((type)::text = 'Metasploit::Credential::Pkcs12'::text)))"
  end

  create_table "metasploit_credential_publics", id: :serial, force: :cascade do |t|
    t.string "username", null: false
    t.datetime "created_at", precision: nil, null: false
    t.datetime "updated_at", precision: nil, null: false
    t.string "type", null: false
    t.index ["username"], name: "index_metasploit_credential_publics_on_username", unique: true
  end

  create_table "metasploit_credential_realms", id: :serial, force: :cascade do |t|
    t.string "key", null: false
    t.string "value", null: false
    t.datetime "created_at", precision: nil, null: false
    t.datetime "updated_at", precision: nil, null: false
    t.index ["key", "value"], name: "index_metasploit_credential_realms_on_key_and_value", unique: true
  end

  create_table "mod_refs", id: :serial, force: :cascade do |t|
    t.string "module", limit: 1024
    t.string "mtype", limit: 128
    t.text "ref"
  end

  create_table "module_actions", id: :serial, force: :cascade do |t|
    t.integer "detail_id"
    t.text "name"
    t.index ["detail_id"], name: "index_module_actions_on_detail_id"
  end

  create_table "module_archs", id: :serial, force: :cascade do |t|
    t.integer "detail_id"
    t.text "name"
    t.index ["detail_id"], name: "index_module_archs_on_detail_id"
  end

  create_table "module_authors", id: :serial, force: :cascade do |t|
    t.integer "detail_id"
    t.text "name"
    t.text "email"
    t.index ["detail_id"], name: "index_module_authors_on_detail_id"
  end

  create_table "module_details", id: :serial, force: :cascade do |t|
    t.datetime "mtime", precision: nil
    t.text "file"
    t.string "mtype"
    t.text "refname"
    t.text "fullname"
    t.text "name"
    t.integer "rank"
    t.text "description"
    t.string "license"
    t.boolean "privileged"
    t.datetime "disclosure_date", precision: nil
    t.integer "default_target"
    t.text "default_action"
    t.string "stance"
    t.boolean "ready"
    t.index ["description"], name: "index_module_details_on_description"
    t.index ["mtype"], name: "index_module_details_on_mtype"
    t.index ["name"], name: "index_module_details_on_name"
    t.index ["refname"], name: "index_module_details_on_refname"
  end

  create_table "module_mixins", id: :serial, force: :cascade do |t|
    t.integer "detail_id"
    t.text "name"
    t.index ["detail_id"], name: "index_module_mixins_on_detail_id"
  end

  create_table "module_platforms", id: :serial, force: :cascade do |t|
    t.integer "detail_id"
    t.text "name"
    t.index ["detail_id"], name: "index_module_platforms_on_detail_id"
  end

  create_table "module_refs", id: :serial, force: :cascade do |t|
    t.integer "detail_id"
    t.text "name"
    t.index ["detail_id"], name: "index_module_refs_on_detail_id"
    t.index ["name"], name: "index_module_refs_on_name"
  end

  create_table "module_runs", id: :serial, force: :cascade do |t|
    t.datetime "attempted_at", precision: nil
    t.text "fail_detail"
    t.string "fail_reason"
    t.text "module_fullname"
    t.integer "port"
    t.string "proto"
    t.integer "session_id"
    t.string "status"
    t.integer "trackable_id"
    t.string "trackable_type"
    t.integer "user_id"
    t.string "username"
    t.datetime "created_at", precision: nil, null: false
    t.datetime "updated_at", precision: nil, null: false
    t.index ["session_id"], name: "index_module_runs_on_session_id"
    t.index ["user_id"], name: "index_module_runs_on_user_id"
  end

  create_table "module_targets", id: :serial, force: :cascade do |t|
    t.integer "detail_id"
    t.integer "index"
    t.text "name"
    t.index ["detail_id"], name: "index_module_targets_on_detail_id"
  end

  create_table "nexpose_consoles", id: :serial, force: :cascade do |t|
    t.datetime "created_at", precision: nil, null: false
    t.datetime "updated_at", precision: nil, null: false
    t.boolean "enabled", default: true
    t.text "owner"
    t.text "address"
    t.integer "port", default: 3780
    t.text "username"
    t.text "password"
    t.text "status"
    t.text "version"
    t.text "cert"
    t.binary "cached_sites"
    t.text "name"
  end

  create_table "notes", id: :serial, force: :cascade do |t|
    t.datetime "created_at", precision: nil
    t.string "ntype", limit: 512
    t.integer "workspace_id", default: 1, null: false
    t.integer "service_id"
    t.integer "host_id"
    t.datetime "updated_at", precision: nil
    t.boolean "critical"
    t.boolean "seen"
    t.text "data"
    t.integer "vuln_id"
    t.index ["ntype"], name: "index_notes_on_ntype"
    t.index ["vuln_id"], name: "index_notes_on_vuln_id"
  end

  create_table "payloads", id: :serial, force: :cascade do |t|
    t.string "name"
    t.string "uuid"
    t.integer "uuid_mask"
    t.integer "timestamp"
    t.string "arch"
    t.string "platform"
    t.string "urls"
    t.string "description"
    t.string "raw_payload"
    t.string "raw_payload_hash"
    t.string "build_status"
    t.string "build_opts"
    t.datetime "created_at", precision: nil, null: false
    t.datetime "updated_at", precision: nil, null: false
  end

  create_table "profiles", id: :serial, force: :cascade do |t|
    t.datetime "created_at", precision: nil, null: false
    t.datetime "updated_at", precision: nil, null: false
    t.boolean "active", default: true
    t.text "name"
    t.text "owner"
    t.binary "settings"
  end

  create_table "refs", id: :serial, force: :cascade do |t|
    t.integer "ref_id"
    t.datetime "created_at", precision: nil
    t.string "name", limit: 512
    t.datetime "updated_at", precision: nil
    t.index ["name"], name: "index_refs_on_name"
  end

  create_table "report_templates", id: :serial, force: :cascade do |t|
    t.integer "workspace_id", default: 1, null: false
    t.string "created_by"
    t.string "path", limit: 1024
    t.text "name"
    t.datetime "created_at", precision: nil, null: false
    t.datetime "updated_at", precision: nil, null: false
  end

  create_table "reports", id: :serial, force: :cascade do |t|
    t.integer "workspace_id", default: 1, null: false
    t.string "created_by"
    t.string "rtype"
    t.string "path", limit: 1024
    t.text "options"
    t.datetime "created_at", precision: nil, null: false
    t.datetime "updated_at", precision: nil, null: false
    t.datetime "downloaded_at", precision: nil
    t.integer "task_id"
    t.string "name", limit: 63
  end

  create_table "routes", id: :serial, force: :cascade do |t|
    t.integer "session_id"
    t.string "subnet"
    t.string "netmask"
  end

  create_table "services", id: :serial, force: :cascade do |t|
    t.integer "host_id"
    t.datetime "created_at", precision: nil
    t.integer "port", null: false
    t.string "proto", limit: 16, null: false
    t.string "state"
    t.string "name"
    t.datetime "updated_at", precision: nil
    t.text "info"
    t.index ["host_id", "port", "proto"], name: "index_services_on_host_id_and_port_and_proto", unique: true
    t.index ["name"], name: "index_services_on_name"
    t.index ["port"], name: "index_services_on_port"
    t.index ["proto"], name: "index_services_on_proto"
    t.index ["state"], name: "index_services_on_state"
  end

  create_table "session_events", id: :serial, force: :cascade do |t|
    t.integer "session_id"
    t.string "etype"
    t.binary "command"
    t.binary "output"
    t.string "remote_path"
    t.string "local_path"
    t.datetime "created_at", precision: nil
  end

  create_table "sessions", id: :serial, force: :cascade do |t|
    t.integer "host_id"
    t.string "stype"
    t.string "via_exploit"
    t.string "via_payload"
    t.string "desc"
    t.integer "port"
    t.string "platform"
    t.text "datastore"
    t.datetime "opened_at", precision: nil, null: false
    t.datetime "closed_at", precision: nil
    t.string "close_reason"
    t.integer "local_id"
    t.datetime "last_seen", precision: nil
    t.integer "module_run_id"
    t.index ["module_run_id"], name: "index_sessions_on_module_run_id"
  end

  create_table "tags", id: :serial, force: :cascade do |t|
    t.integer "user_id"
    t.string "name", limit: 1024
    t.text "desc"
    t.boolean "report_summary", default: false, null: false
    t.boolean "report_detail", default: false, null: false
    t.boolean "critical", default: false, null: false
    t.datetime "created_at", precision: nil, null: false
    t.datetime "updated_at", precision: nil, null: false
  end

  create_table "task_creds", id: :serial, force: :cascade do |t|
    t.integer "task_id", null: false
    t.integer "cred_id", null: false
    t.datetime "created_at", precision: nil, null: false
    t.datetime "updated_at", precision: nil, null: false
  end

  create_table "task_hosts", id: :serial, force: :cascade do |t|
    t.integer "task_id", null: false
    t.integer "host_id", null: false
    t.datetime "created_at", precision: nil, null: false
    t.datetime "updated_at", precision: nil, null: false
  end

  create_table "task_services", id: :serial, force: :cascade do |t|
    t.integer "task_id", null: false
    t.integer "service_id", null: false
    t.datetime "created_at", precision: nil, null: false
    t.datetime "updated_at", precision: nil, null: false
  end

  create_table "task_sessions", id: :serial, force: :cascade do |t|
    t.integer "task_id", null: false
    t.integer "session_id", null: false
    t.datetime "created_at", precision: nil, null: false
    t.datetime "updated_at", precision: nil, null: false
  end

  create_table "tasks", id: :serial, force: :cascade do |t|
    t.integer "workspace_id", default: 1, null: false
    t.string "created_by"
    t.string "module"
    t.datetime "completed_at", precision: nil
    t.string "path", limit: 1024
    t.string "info"
    t.string "description"
    t.integer "progress"
    t.text "options"
    t.text "error"
    t.datetime "created_at", precision: nil, null: false
    t.datetime "updated_at", precision: nil, null: false
    t.text "result"
    t.string "module_uuid", limit: 8
    t.binary "settings"
  end

  create_table "users", id: :serial, force: :cascade do |t|
    t.string "username"
    t.string "crypted_password"
    t.string "password_salt"
    t.string "persistence_token"
    t.datetime "created_at", precision: nil, null: false
    t.datetime "updated_at", precision: nil, null: false
    t.string "fullname"
    t.string "email"
    t.string "phone"
    t.string "company"
    t.string "prefs", limit: 524288
    t.boolean "admin", default: true, null: false
  end

  create_table "vuln_attempts", id: :serial, force: :cascade do |t|
    t.integer "vuln_id"
    t.datetime "attempted_at", precision: nil
    t.boolean "exploited"
    t.string "fail_reason"
    t.string "username"
    t.text "module"
    t.integer "session_id"
    t.integer "loot_id"
    t.text "fail_detail"
  end

  create_table "vuln_details", id: :serial, force: :cascade do |t|
    t.integer "vuln_id"
    t.float "cvss_score"
    t.string "cvss_vector"
    t.string "title"
    t.text "description"
    t.text "solution"
    t.binary "proof"
    t.integer "nx_console_id"
    t.integer "nx_device_id"
    t.string "nx_vuln_id"
    t.float "nx_severity"
    t.float "nx_pci_severity"
    t.datetime "nx_published", precision: nil
    t.datetime "nx_added", precision: nil
    t.datetime "nx_modified", precision: nil
    t.text "nx_tags"
    t.text "nx_vuln_status"
    t.text "nx_proof_key"
    t.string "src"
    t.integer "nx_scan_id"
    t.datetime "nx_vulnerable_since", precision: nil
    t.string "nx_pci_compliance_status"
  end

  create_table "vulns", id: :serial, force: :cascade do |t|
    t.integer "host_id"
    t.integer "service_id"
    t.datetime "created_at", precision: nil
    t.string "name"
    t.datetime "updated_at", precision: nil
    t.string "info", limit: 65536
    t.datetime "exploited_at", precision: nil
    t.integer "vuln_detail_count", default: 0
    t.integer "vuln_attempt_count", default: 0
    t.integer "origin_id"
    t.string "origin_type"
    t.index ["name"], name: "index_vulns_on_name"
    t.index ["origin_id"], name: "index_vulns_on_origin_id"
  end

  create_table "vulns_refs", id: :serial, force: :cascade do |t|
    t.integer "ref_id"
    t.integer "vuln_id"
  end

  create_table "web_forms", id: :serial, force: :cascade do |t|
    t.integer "web_site_id", null: false
    t.datetime "created_at", precision: nil, null: false
    t.datetime "updated_at", precision: nil, null: false
    t.text "path"
    t.string "method", limit: 1024
    t.text "params"
    t.text "query"
    t.index ["path"], name: "index_web_forms_on_path"
  end

  create_table "web_pages", id: :serial, force: :cascade do |t|
    t.integer "web_site_id", null: false
    t.datetime "created_at", precision: nil, null: false
    t.datetime "updated_at", precision: nil, null: false
    t.text "path"
    t.text "query"
    t.integer "code", null: false
    t.text "cookie"
    t.text "auth"
    t.text "ctype"
    t.datetime "mtime", precision: nil
    t.text "location"
    t.text "headers"
    t.binary "body"
    t.binary "request"
    t.index ["path"], name: "index_web_pages_on_path"
    t.index ["query"], name: "index_web_pages_on_query"
  end

  create_table "web_sites", id: :serial, force: :cascade do |t|
    t.integer "service_id", null: false
    t.datetime "created_at", precision: nil, null: false
    t.datetime "updated_at", precision: nil, null: false
    t.string "vhost", limit: 2048
    t.text "comments"
    t.text "options"
    t.index ["comments"], name: "index_web_sites_on_comments"
    t.index ["options"], name: "index_web_sites_on_options"
    t.index ["vhost"], name: "index_web_sites_on_vhost"
  end

  create_table "web_vulns", id: :serial, force: :cascade do |t|
    t.integer "web_site_id", null: false
    t.datetime "created_at", precision: nil, null: false
    t.datetime "updated_at", precision: nil, null: false
    t.text "path", null: false
    t.string "method", limit: 1024, null: false
    t.text "params"
    t.text "pname"
    t.integer "risk", null: false
    t.string "name", limit: 1024, null: false
    t.text "query"
    t.text "category", null: false
    t.integer "confidence", null: false
    t.text "description"
    t.text "blame"
    t.binary "request"
    t.binary "proof", null: false
    t.string "owner"
    t.text "payload"
    t.index ["method"], name: "index_web_vulns_on_method"
    t.index ["name"], name: "index_web_vulns_on_name"
    t.index ["path"], name: "index_web_vulns_on_path"
  end

  create_table "wmap_requests", id: :serial, force: :cascade do |t|
    t.string "host"
    t.inet "address"
    t.integer "port"
    t.integer "ssl"
    t.string "meth", limit: 32
    t.text "path"
    t.text "headers"
    t.text "query"
    t.text "body"
    t.string "respcode", limit: 16
    t.text "resphead"
    t.text "response"
    t.datetime "created_at", precision: nil
    t.datetime "updated_at", precision: nil
  end

  create_table "wmap_targets", id: :serial, force: :cascade do |t|
    t.string "host"
    t.inet "address"
    t.integer "port"
    t.integer "ssl"
    t.integer "selected"
    t.datetime "created_at", precision: nil
    t.datetime "updated_at", precision: nil
  end

  create_table "workspace_members", id: false, force: :cascade do |t|
    t.integer "workspace_id", null: false
    t.integer "user_id", null: false
  end

  create_table "workspaces", id: :serial, force: :cascade do |t|
    t.string "name"
    t.datetime "created_at", precision: nil, null: false
    t.datetime "updated_at", precision: nil, null: false
    t.string "boundary", limit: 4096
    t.string "description", limit: 4096
    t.integer "owner_id"
    t.boolean "limit_to_network", default: false, null: false
    t.boolean "import_fingerprint", default: false
  end

end
