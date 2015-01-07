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

ActiveRecord::Schema.define(:version => 20150106201450) do

  create_table "api_keys", :force => true do |t|
    t.text     "token"
    t.datetime "created_at", :null => false
    t.datetime "updated_at", :null => false
    t.string   "name"
  end

  create_table "app_categories", :force => true do |t|
    t.string "name"
  end

  create_table "app_categories_apps", :force => true do |t|
    t.integer "app_id"
    t.integer "app_category_id"
    t.string  "name"
  end

  add_index "app_categories_apps", ["app_category_id"], :name => "index_app_categories_apps_on_app_category_id"
  add_index "app_categories_apps", ["app_id"], :name => "index_app_categories_apps_on_app_id"

  create_table "app_runs", :force => true do |t|
    t.datetime "started_at"
    t.datetime "stopped_at"
    t.integer  "app_id"
    t.text     "config"
    t.datetime "created_at",                      :null => false
    t.datetime "updated_at",                      :null => false
    t.string   "state"
    t.integer  "workspace_id"
    t.boolean  "hidden",       :default => false
  end

  add_index "app_runs", ["app_id"], :name => "index_app_runs_on_app_id"
  add_index "app_runs", ["workspace_id"], :name => "index_app_runs_on_workspace_id"

  create_table "apps", :force => true do |t|
    t.string  "name"
    t.text    "description"
    t.float   "rating"
    t.string  "symbol"
    t.boolean "hidden",      :default => false
  end

  create_table "automatic_exploitation_match_results", :force => true do |t|
    t.integer  "match_id"
    t.integer  "run_id"
    t.string   "state",      :null => false
    t.datetime "created_at", :null => false
    t.datetime "updated_at", :null => false
  end

  create_table "automatic_exploitation_match_sets", :force => true do |t|
    t.integer  "workspace_id"
    t.integer  "user_id"
    t.datetime "created_at",   :null => false
    t.datetime "updated_at",   :null => false
  end

  add_index "automatic_exploitation_match_sets", ["user_id"], :name => "index_automatic_exploitation_match_sets_on_user_id"
  add_index "automatic_exploitation_match_sets", ["workspace_id"], :name => "index_automatic_exploitation_match_sets_on_workspace_id"

  create_table "automatic_exploitation_matches", :force => true do |t|
    t.integer  "vuln_id"
    t.integer  "module_detail_id"
    t.datetime "created_at",              :null => false
    t.datetime "updated_at",              :null => false
    t.integer  "match_set_id"
    t.integer  "nexpose_data_exploit_id"
    t.string   "matchable_type"
    t.integer  "matchable_id"
  end

  add_index "automatic_exploitation_matches", ["module_detail_id"], :name => "index_automatic_exploitation_matches_on_ref_id"
  add_index "automatic_exploitation_matches", ["nexpose_data_exploit_id"], :name => "index_automatic_exploitation_matches_on_nexpose_data_exploit_id"
  add_index "automatic_exploitation_matches", ["vuln_id"], :name => "index_automatic_exploitation_matches_on_vuln_id"

  create_table "automatic_exploitation_runs", :force => true do |t|
    t.integer  "workspace_id"
    t.integer  "user_id"
    t.integer  "match_set_id"
    t.datetime "created_at",   :null => false
    t.datetime "updated_at",   :null => false
    t.string   "state"
  end

  create_table "brute_force_guess_attempts", :force => true do |t|
    t.integer  "brute_force_run_id",                               :null => false
    t.integer  "brute_force_guess_core_id",                        :null => false
    t.integer  "service_id",                                       :null => false
    t.datetime "attempted_at"
    t.datetime "created_at",                                       :null => false
    t.datetime "updated_at",                                       :null => false
    t.string   "status",                    :default => "Untried"
    t.integer  "session_id"
    t.integer  "login_id"
  end

  add_index "brute_force_guess_attempts", ["brute_force_guess_core_id"], :name => "brute_force_guess_attempts_brute_force_guess_core_ids"
  add_index "brute_force_guess_attempts", ["brute_force_run_id", "brute_force_guess_core_id", "service_id"], :name => "unique_brute_force_guess_attempts", :unique => true
  add_index "brute_force_guess_attempts", ["service_id"], :name => "index_brute_force_guess_attempts_on_service_id"

  create_table "brute_force_guess_cores", :force => true do |t|
    t.integer  "private_id"
    t.integer  "public_id"
    t.integer  "realm_id"
    t.integer  "workspace_id", :null => false
    t.datetime "created_at",   :null => false
    t.datetime "updated_at",   :null => false
  end

  add_index "brute_force_guess_cores", ["private_id"], :name => "index_brute_force_guess_cores_on_private_id"
  add_index "brute_force_guess_cores", ["public_id"], :name => "index_brute_force_guess_cores_on_public_id"
  add_index "brute_force_guess_cores", ["realm_id"], :name => "index_brute_force_guess_cores_on_realm_id"
  add_index "brute_force_guess_cores", ["workspace_id"], :name => "index_brute_force_guess_cores_on_workspace_id"

  create_table "brute_force_reuse_attempts", :force => true do |t|
    t.integer  "brute_force_run_id",                                   :null => false
    t.integer  "metasploit_credential_core_id",                        :null => false
    t.integer  "service_id",                                           :null => false
    t.datetime "attempted_at"
    t.datetime "created_at",                                           :null => false
    t.datetime "updated_at",                                           :null => false
    t.string   "status",                        :default => "Untried"
  end

  add_index "brute_force_reuse_attempts", ["brute_force_run_id", "metasploit_credential_core_id", "service_id"], :name => "unique_brute_force_reuse_attempts", :unique => true
  add_index "brute_force_reuse_attempts", ["metasploit_credential_core_id"], :name => "brute_force_reuse_attempts_metasploit_credential_core_ids"
  add_index "brute_force_reuse_attempts", ["service_id"], :name => "index_brute_force_reuse_attempts_on_service_id"

  create_table "brute_force_reuse_groups", :force => true do |t|
    t.string   "name",         :null => false
    t.integer  "workspace_id", :null => false
    t.datetime "created_at",   :null => false
    t.datetime "updated_at",   :null => false
  end

  add_index "brute_force_reuse_groups", ["workspace_id", "name"], :name => "index_brute_force_reuse_groups_on_workspace_id_and_name", :unique => true

  create_table "brute_force_reuse_groups_metasploit_credential_cores", :id => false, :force => true do |t|
    t.integer "brute_force_reuse_group_id",    :null => false
    t.integer "metasploit_credential_core_id", :null => false
  end

  add_index "brute_force_reuse_groups_metasploit_credential_cores", ["brute_force_reuse_group_id", "metasploit_credential_core_id"], :name => "unique_brute_force_reuse_groups_metasploit_credential_cores", :unique => true

  create_table "brute_force_runs", :force => true do |t|
    t.text     "config",     :null => false
    t.datetime "created_at", :null => false
    t.datetime "updated_at", :null => false
    t.integer  "task_id"
  end

  create_table "clients", :force => true do |t|
    t.integer  "host_id"
    t.datetime "created_at"
    t.string   "ua_string",  :limit => 1024, :null => false
    t.string   "ua_name",    :limit => 64
    t.string   "ua_ver",     :limit => 32
    t.datetime "updated_at"
  end

  create_table "cred_files", :force => true do |t|
    t.integer  "workspace_id",                 :default => 1, :null => false
    t.string   "path",         :limit => 1024
    t.string   "ftype",        :limit => 16
    t.string   "created_by"
    t.string   "name",         :limit => 512
    t.string   "desc",         :limit => 1024
    t.datetime "created_at",                                  :null => false
    t.datetime "updated_at",                                  :null => false
  end

  create_table "credential_cores_tasks", :id => false, :force => true do |t|
    t.integer "core_id"
    t.integer "task_id"
  end

  create_table "credential_logins_tasks", :id => false, :force => true do |t|
    t.integer "login_id"
    t.integer "task_id"
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

  create_table "delayed_jobs", :force => true do |t|
    t.integer  "priority",   :default => 0
    t.integer  "attempts",   :default => 0
    t.text     "handler"
    t.text     "last_error"
    t.datetime "run_at"
    t.datetime "locked_at"
    t.datetime "failed_at"
    t.string   "locked_by"
    t.string   "queue"
    t.datetime "created_at",                :null => false
    t.datetime "updated_at",                :null => false
  end

  add_index "delayed_jobs", ["priority", "run_at"], :name => "delayed_jobs_priority"

  create_table "egadz_result_ranges", :force => true do |t|
    t.integer  "task_id"
    t.string   "target_host"
    t.integer  "start_port"
    t.integer  "end_port"
    t.datetime "created_at",  :null => false
    t.datetime "updated_at",  :null => false
    t.string   "state"
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
    t.text     "module_rhost"
    t.text     "module_name"
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

  create_table "exports", :force => true do |t|
    t.integer  "workspace_id",                                          :null => false
    t.string   "created_by"
    t.string   "export_type"
    t.string   "name"
    t.string   "state"
    t.datetime "created_at",                                            :null => false
    t.datetime "updated_at",                                            :null => false
    t.string   "file_path",          :limit => 1024
    t.boolean  "mask_credentials",                   :default => false
    t.datetime "completed_at"
    t.text     "included_addresses"
    t.text     "excluded_addresses"
    t.datetime "started_at"
  end

  create_table "generated_payloads", :force => true do |t|
    t.string   "state"
    t.string   "file"
    t.text     "options"
    t.integer  "workspace_id"
    t.datetime "created_at",      :null => false
    t.datetime "updated_at",      :null => false
    t.string   "generator_error"
    t.string   "payload_class"
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
    t.integer  "nexpose_data_asset_id"
    t.integer  "history_count",                          :default => 0
    t.string   "detected_arch"
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

  create_table "known_ports", :force => true do |t|
    t.integer "port",                     :null => false
    t.string  "proto", :default => "tcp", :null => false
    t.string  "name",                     :null => false
    t.text    "info"
  end

  add_index "known_ports", ["port"], :name => "index_known_ports_on_port"

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

  create_table "metasploit_credential_core_tags", :force => true do |t|
    t.integer "core_id", :null => false
    t.integer "tag_id",  :null => false
  end

  add_index "metasploit_credential_core_tags", ["core_id", "tag_id"], :name => "index_metasploit_credential_core_tags_on_core_id_and_tag_id", :unique => true

  create_table "metasploit_credential_cores", :force => true do |t|
    t.integer  "origin_id",                   :null => false
    t.string   "origin_type",                 :null => false
    t.integer  "private_id"
    t.integer  "public_id"
    t.integer  "realm_id"
    t.integer  "workspace_id",                :null => false
    t.datetime "created_at",                  :null => false
    t.datetime "updated_at",                  :null => false
    t.integer  "logins_count", :default => 0
  end

  add_index "metasploit_credential_cores", ["origin_type", "origin_id"], :name => "index_metasploit_credential_cores_on_origin_type_and_origin_id"
  add_index "metasploit_credential_cores", ["private_id"], :name => "index_metasploit_credential_cores_on_private_id"
  add_index "metasploit_credential_cores", ["public_id"], :name => "index_metasploit_credential_cores_on_public_id"
  add_index "metasploit_credential_cores", ["realm_id"], :name => "index_metasploit_credential_cores_on_realm_id"
  add_index "metasploit_credential_cores", ["workspace_id", "private_id"], :name => "unique_private_metasploit_credential_cores", :unique => true
  add_index "metasploit_credential_cores", ["workspace_id", "public_id", "private_id"], :name => "unique_realmless_metasploit_credential_cores", :unique => true
  add_index "metasploit_credential_cores", ["workspace_id", "public_id"], :name => "unique_public_metasploit_credential_cores", :unique => true
  add_index "metasploit_credential_cores", ["workspace_id", "realm_id", "private_id"], :name => "unique_publicless_metasploit_credential_cores", :unique => true
  add_index "metasploit_credential_cores", ["workspace_id", "realm_id", "public_id", "private_id"], :name => "unique_complete_metasploit_credential_cores", :unique => true
  add_index "metasploit_credential_cores", ["workspace_id", "realm_id", "public_id"], :name => "unique_privateless_metasploit_credential_cores", :unique => true
  add_index "metasploit_credential_cores", ["workspace_id"], :name => "index_metasploit_credential_cores_on_workspace_id"

  create_table "metasploit_credential_login_tags", :force => true do |t|
    t.integer "login_id", :null => false
    t.integer "tag_id",   :null => false
  end

  add_index "metasploit_credential_login_tags", ["login_id", "tag_id"], :name => "index_metasploit_credential_login_tags_on_login_id_and_tag_id", :unique => true

  create_table "metasploit_credential_logins", :force => true do |t|
    t.integer  "core_id",           :null => false
    t.integer  "service_id",        :null => false
    t.string   "access_level"
    t.string   "status",            :null => false
    t.datetime "last_attempted_at"
    t.datetime "created_at",        :null => false
    t.datetime "updated_at",        :null => false
  end

  add_index "metasploit_credential_logins", ["core_id", "service_id"], :name => "index_metasploit_credential_logins_on_core_id_and_service_id", :unique => true
  add_index "metasploit_credential_logins", ["service_id", "core_id"], :name => "index_metasploit_credential_logins_on_service_id_and_core_id", :unique => true

  create_table "metasploit_credential_origin_cracked_passwords", :force => true do |t|
    t.integer  "metasploit_credential_core_id", :null => false
    t.datetime "created_at",                    :null => false
    t.datetime "updated_at",                    :null => false
  end

  add_index "metasploit_credential_origin_cracked_passwords", ["metasploit_credential_core_id"], :name => "originating_credential_cores"

  create_table "metasploit_credential_origin_imports", :force => true do |t|
    t.text     "filename",   :null => false
    t.integer  "task_id"
    t.datetime "created_at", :null => false
    t.datetime "updated_at", :null => false
  end

  add_index "metasploit_credential_origin_imports", ["task_id"], :name => "index_metasploit_credential_origin_imports_on_task_id"

  create_table "metasploit_credential_origin_manuals", :force => true do |t|
    t.integer  "user_id",    :null => false
    t.datetime "created_at", :null => false
    t.datetime "updated_at", :null => false
  end

  add_index "metasploit_credential_origin_manuals", ["user_id"], :name => "index_metasploit_credential_origin_manuals_on_user_id"

  create_table "metasploit_credential_origin_services", :force => true do |t|
    t.integer  "service_id",       :null => false
    t.text     "module_full_name", :null => false
    t.datetime "created_at",       :null => false
    t.datetime "updated_at",       :null => false
  end

  add_index "metasploit_credential_origin_services", ["service_id", "module_full_name"], :name => "unique_metasploit_credential_origin_services", :unique => true

  create_table "metasploit_credential_origin_sessions", :force => true do |t|
    t.text     "post_reference_name", :null => false
    t.integer  "session_id",          :null => false
    t.datetime "created_at",          :null => false
    t.datetime "updated_at",          :null => false
  end

  add_index "metasploit_credential_origin_sessions", ["session_id", "post_reference_name"], :name => "unique_metasploit_credential_origin_sessions", :unique => true

  create_table "metasploit_credential_privates", :force => true do |t|
    t.string   "type",       :null => false
    t.text     "data",       :null => false
    t.datetime "created_at", :null => false
    t.datetime "updated_at", :null => false
    t.string   "jtr_format"
  end

  add_index "metasploit_credential_privates", ["type", "data"], :name => "index_metasploit_credential_privates_on_type_and_data", :unique => true

  create_table "metasploit_credential_publics", :force => true do |t|
    t.string   "username",   :null => false
    t.datetime "created_at", :null => false
    t.datetime "updated_at", :null => false
    t.string   "type",       :null => false
  end

  add_index "metasploit_credential_publics", ["username"], :name => "index_metasploit_credential_publics_on_username", :unique => true

  create_table "metasploit_credential_realms", :force => true do |t|
    t.string   "key",        :null => false
    t.string   "value",      :null => false
    t.datetime "created_at", :null => false
    t.datetime "updated_at", :null => false
  end

  add_index "metasploit_credential_realms", ["key", "value"], :name => "index_metasploit_credential_realms_on_key_and_value", :unique => true

  create_table "mm_domino_edges", :force => true do |t|
    t.integer  "dest_node_id",   :null => false
    t.integer  "login_id",       :null => false
    t.integer  "run_id",         :null => false
    t.integer  "source_node_id", :null => false
    t.datetime "created_at",     :null => false
    t.datetime "updated_at",     :null => false
  end

  add_index "mm_domino_edges", ["dest_node_id", "run_id"], :name => "index_mm_domino_edges_on_dest_node_id_and_run_id", :unique => true
  add_index "mm_domino_edges", ["login_id", "run_id"], :name => "index_mm_domino_edges_on_login_id_and_run_id", :unique => true
  add_index "mm_domino_edges", ["run_id"], :name => "index_mm_domino_edges_on_run_id"

  create_table "mm_domino_nodes", :force => true do |t|
    t.integer  "run_id",                                  :null => false
    t.integer  "host_id",                                 :null => false
    t.datetime "created_at",                              :null => false
    t.datetime "updated_at",                              :null => false
    t.boolean  "high_value",           :default => false
    t.integer  "captured_creds_count", :default => 0
    t.integer  "depth",                :default => 0
  end

  add_index "mm_domino_nodes", ["host_id", "run_id"], :name => "index_mm_domino_nodes_on_host_id_and_run_id", :unique => true
  add_index "mm_domino_nodes", ["host_id"], :name => "index_mm_domino_nodes_on_host_id"
  add_index "mm_domino_nodes", ["run_id"], :name => "index_mm_domino_nodes_on_run_id"

  create_table "mm_domino_nodes_cores", :force => true do |t|
    t.integer "node_id", :null => false
    t.integer "core_id", :null => false
  end

  add_index "mm_domino_nodes_cores", ["node_id", "core_id"], :name => "index_mm_domino_nodes_cores_on_node_id_and_core_id", :unique => true

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

  create_table "nexpose_data_assets", :force => true do |t|
    t.integer  "nexpose_data_site_id", :null => false
    t.string   "asset_id",             :null => false
    t.string   "url"
    t.text     "host_names"
    t.string   "os_name"
    t.text     "mac_addresses"
    t.datetime "last_scan_date"
    t.datetime "next_scan_date"
    t.string   "last_scan_id"
    t.datetime "created_at",           :null => false
    t.datetime "updated_at",           :null => false
  end

  add_index "nexpose_data_assets", ["asset_id"], :name => "index_nexpose_data_assets_on_asset_id"
  add_index "nexpose_data_assets", ["nexpose_data_site_id"], :name => "index_nexpose_data_assets_on_nexpose_data_site_id"

  create_table "nexpose_data_exploits", :force => true do |t|
    t.integer  "module_detail_id"
    t.string   "nexpose_exploit_id"
    t.string   "skill_level"
    t.text     "description"
    t.string   "source_key"
    t.string   "source"
    t.datetime "created_at",         :null => false
    t.datetime "updated_at",         :null => false
  end

  add_index "nexpose_data_exploits", ["nexpose_exploit_id"], :name => "index_nexpose_data_exploits_on_nexpose_exploit_id", :unique => true
  add_index "nexpose_data_exploits", ["source", "source_key"], :name => "index_nexpose_data_exploits_on_source_and_source_key"

  create_table "nexpose_data_exploits_vulnerability_definitions", :id => false, :force => true do |t|
    t.integer "exploit_id"
    t.integer "vulnerability_definition_id"
  end

  add_index "nexpose_data_exploits_vulnerability_definitions", ["exploit_id", "vulnerability_definition_id"], :name => "index_nx_data_exploits_vuln_defs_on_exploit_id_and_vuln_def_id"
  add_index "nexpose_data_exploits_vulnerability_definitions", ["vulnerability_definition_id", "exploit_id"], :name => "index_nx_data_exploits_vuln_defs_on_vuln_def_id_and_exploit_id"

  create_table "nexpose_data_import_runs", :force => true do |t|
    t.integer  "user_id"
    t.integer  "workspace_id"
    t.string   "state"
    t.integer  "nx_console_id"
    t.boolean  "metasploitable_only", :default => true
    t.datetime "created_at",                            :null => false
    t.datetime "updated_at",                            :null => false
    t.string   "import_state"
  end

  add_index "nexpose_data_import_runs", ["nx_console_id"], :name => "index_nexpose_data_import_runs_on_nx_console_id"

  create_table "nexpose_data_ip_addresses", :force => true do |t|
    t.integer  "nexpose_data_asset_id"
    t.datetime "created_at",                           :null => false
    t.datetime "updated_at",                           :null => false
    t.string   "address",               :limit => nil
  end

  add_index "nexpose_data_ip_addresses", ["nexpose_data_asset_id"], :name => "index_nexpose_data_ip_addresses_on_nexpose_data_asset_id"

  create_table "nexpose_data_scan_templates", :force => true do |t|
    t.integer  "nx_console_id",    :null => false
    t.string   "scan_template_id", :null => false
    t.string   "name"
    t.datetime "created_at",       :null => false
    t.datetime "updated_at",       :null => false
  end

  add_index "nexpose_data_scan_templates", ["nx_console_id"], :name => "index_nexpose_data_scan_templates_on_nx_console_id"
  add_index "nexpose_data_scan_templates", ["scan_template_id"], :name => "index_nexpose_data_scan_templates_on_scan_template_id"

  create_table "nexpose_data_sites", :force => true do |t|
    t.integer  "nexpose_data_import_run_id", :null => false
    t.string   "site_id",                    :null => false
    t.string   "name"
    t.text     "description"
    t.string   "importance"
    t.string   "type"
    t.datetime "last_scan_date"
    t.datetime "next_scan_date"
    t.string   "last_scan_id"
    t.text     "summary"
    t.datetime "created_at",                 :null => false
    t.datetime "updated_at",                 :null => false
  end

  add_index "nexpose_data_sites", ["nexpose_data_import_run_id"], :name => "index_nexpose_data_sites_on_nexpose_data_import_run_id"
  add_index "nexpose_data_sites", ["site_id"], :name => "index_nexpose_data_sites_on_site_id"

  create_table "nexpose_data_vulnerabilities", :force => true do |t|
    t.integer  "nexpose_data_vulnerability_definition_id", :null => false
    t.string   "vulnerability_id",                         :null => false
    t.string   "title"
    t.datetime "created_at",                               :null => false
    t.datetime "updated_at",                               :null => false
  end

  add_index "nexpose_data_vulnerabilities", ["nexpose_data_vulnerability_definition_id"], :name => "index_nx_data_vuln_on_nexpose_data_vuln_def_id"
  add_index "nexpose_data_vulnerabilities", ["vulnerability_id"], :name => "index_nexpose_data_vulnerabilities_on_vulnerability_id", :unique => true

  create_table "nexpose_data_vulnerability_definitions", :force => true do |t|
    t.string   "vulnerability_definition_id"
    t.string   "title"
    t.text     "description"
    t.date     "date_published"
    t.integer  "severity_score"
    t.string   "serverity"
    t.string   "pci_severity_score"
    t.string   "pci_status"
    t.decimal  "riskscore"
    t.string   "cvss_vector"
    t.string   "cvss_access_vector_id"
    t.string   "cvss_access_complexity_id"
    t.string   "cvss_authentication_id"
    t.string   "cvss_confidentiality_impact_id"
    t.string   "cvss_integrity_impact_id"
    t.string   "cvss_availability_impact_id"
    t.decimal  "cvss_score"
    t.decimal  "cvss_exploit_score"
    t.decimal  "cvss_impact_score"
    t.boolean  "denial_of_service"
    t.datetime "created_at",                     :null => false
    t.datetime "updated_at",                     :null => false
  end

  add_index "nexpose_data_vulnerability_definitions", ["vulnerability_definition_id"], :name => "index_nx_data_vuln_def_on_vulnerability_definition_id", :unique => true

  create_table "nexpose_data_vulnerability_instances", :force => true do |t|
    t.string   "vulnerability_id"
    t.string   "asset_id"
    t.integer  "nexpose_data_vulnerability_id"
    t.integer  "nexpose_data_asset_id"
    t.string   "scan_id"
    t.date     "date"
    t.string   "status"
    t.text     "proof"
    t.string   "key"
    t.string   "service"
    t.integer  "port"
    t.string   "protocol"
    t.datetime "created_at",                                   :null => false
    t.datetime "updated_at",                                   :null => false
    t.string   "asset_ip_address",              :limit => nil
  end

  add_index "nexpose_data_vulnerability_instances", ["asset_id", "vulnerability_id"], :name => "index_nx_data_vuln_inst_on_asset_id_and_vulnerability_id"
  add_index "nexpose_data_vulnerability_instances", ["nexpose_data_asset_id"], :name => "index_nx_data_vuln_inst_on_nexpose_data_asset_id"
  add_index "nexpose_data_vulnerability_instances", ["nexpose_data_vulnerability_id"], :name => "index_nx_data_vuln_inst_on_nexpose_data_vulnerability_id"
  add_index "nexpose_data_vulnerability_instances", ["vulnerability_id", "asset_id"], :name => "index_nx_data_vuln_inst_on_vulnerability_id_and_asset_id"

  create_table "nexpose_data_vulnerability_references", :force => true do |t|
    t.integer  "nexpose_data_vulnerability_definition_id"
    t.string   "vulnerability_reference_id"
    t.string   "source"
    t.string   "reference"
    t.datetime "created_at",                               :null => false
    t.datetime "updated_at",                               :null => false
  end

  create_table "nexpose_result_exceptions", :force => true do |t|
    t.integer  "user_id"
    t.string   "nx_scope_type"
    t.integer  "nx_scope_id"
    t.datetime "created_at",                             :null => false
    t.datetime "updated_at",                             :null => false
    t.integer  "automatic_exploitation_match_result_id"
    t.integer  "nexpose_result_export_run_id"
    t.datetime "expiration_date"
    t.string   "reason"
    t.text     "comments"
    t.boolean  "approve"
    t.boolean  "sent_to_nexpose"
    t.datetime "sent_at"
  end

  add_index "nexpose_result_exceptions", ["nexpose_result_export_run_id"], :name => "index_nexpose_result_exceptions_on_nexpose_result_export_run_id"
  add_index "nexpose_result_exceptions", ["nx_scope_type", "nx_scope_id"], :name => "index_nx_r_exceptions_on_nx_scope_type_and_nx_scope_id"
  add_index "nexpose_result_exceptions", ["user_id"], :name => "index_nexpose_result_exceptions_on_user_id"

  create_table "nexpose_result_export_runs", :force => true do |t|
    t.string   "state"
    t.integer  "nx_console_id"
    t.integer  "user_id"
    t.integer  "workspace_id"
    t.datetime "created_at",    :null => false
    t.datetime "updated_at",    :null => false
  end

  create_table "nexpose_result_validations", :force => true do |t|
    t.integer  "user_id"
    t.integer  "nexpose_data_asset_id"
    t.datetime "verified_at"
    t.datetime "created_at",                             :null => false
    t.datetime "updated_at",                             :null => false
    t.integer  "automatic_exploitation_match_result_id"
    t.integer  "nexpose_result_export_run_id"
    t.boolean  "sent_to_nexpose"
    t.datetime "sent_at"
  end

  add_index "nexpose_result_validations", ["nexpose_result_export_run_id"], :name => "index_nx_result_validations_on_nx_result_export_run_id"

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

  create_table "notification_messages", :force => true do |t|
    t.integer  "workspace_id"
    t.integer  "task_id"
    t.string   "title"
    t.text     "content"
    t.string   "url"
    t.string   "kind"
    t.datetime "created_at"
  end

  create_table "notification_messages_users", :force => true do |t|
    t.integer  "user_id"
    t.integer  "message_id"
    t.boolean  "read",       :default => false
    t.datetime "created_at",                    :null => false
    t.datetime "updated_at",                    :null => false
  end

  create_table "pnd_pcap_files", :force => true do |t|
    t.integer  "task_id"
    t.integer  "loot_id"
    t.string   "status"
    t.datetime "created_at", :null => false
    t.datetime "updated_at", :null => false
  end

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

  create_table "report_artifacts", :force => true do |t|
    t.integer  "report_id",                   :null => false
    t.string   "file_path",   :limit => 1024, :null => false
    t.datetime "created_at",                  :null => false
    t.datetime "updated_at",                  :null => false
    t.datetime "accessed_at"
  end

  create_table "report_custom_resources", :force => true do |t|
    t.integer  "workspace_id",  :null => false
    t.string   "created_by"
    t.string   "resource_type"
    t.string   "name"
    t.string   "file_path"
    t.datetime "created_at",    :null => false
    t.datetime "updated_at",    :null => false
  end

  create_table "reports", :force => true do |t|
    t.integer  "workspace_id",                          :null => false
    t.string   "created_by"
    t.string   "report_type"
    t.string   "name"
    t.datetime "created_at",                            :null => false
    t.datetime "updated_at",                            :null => false
    t.string   "file_formats"
    t.text     "options"
    t.string   "sections"
    t.string   "report_template"
    t.text     "included_addresses"
    t.string   "state"
    t.datetime "started_at"
    t.datetime "completed_at"
    t.text     "excluded_addresses"
    t.integer  "se_campaign_id"
    t.integer  "app_run_id"
    t.string   "order_vulns_by"
    t.text     "usernames_reported"
    t.boolean  "skip_data_check",    :default => false
    t.text     "email_recipients"
    t.text     "logo_path"
  end

  create_table "routes", :force => true do |t|
    t.integer "session_id"
    t.string  "subnet"
    t.string  "netmask"
  end

  create_table "run_stats", :force => true do |t|
    t.string   "name"
    t.float    "data"
    t.integer  "task_id"
    t.datetime "created_at", :null => false
    t.datetime "updated_at", :null => false
  end

  create_table "scheduled_tasks", :force => true do |t|
    t.string   "kind"
    t.datetime "last_run_at"
    t.string   "state"
    t.string   "last_run_status"
    t.integer  "task_chain_id"
    t.integer  "position"
    t.text     "config_hash"
    t.datetime "created_at",                         :null => false
    t.datetime "updated_at",                         :null => false
    t.text     "form_hash"
    t.text     "report_hash"
    t.string   "file_upload"
    t.boolean  "legacy",          :default => false
  end

  create_table "se_campaign_files", :force => true do |t|
    t.integer  "attachable_id"
    t.string   "attachable_type"
    t.string   "attachment"
    t.datetime "created_at",          :null => false
    t.datetime "updated_at",          :null => false
    t.string   "content_disposition"
    t.string   "type"
    t.integer  "workspace_id"
    t.integer  "user_id"
    t.string   "name"
    t.integer  "file_size"
  end

  create_table "se_campaigns", :force => true do |t|
    t.integer  "user_id"
    t.integer  "workspace_id"
    t.string   "name"
    t.datetime "created_at",                                             :null => false
    t.datetime "updated_at",                                             :null => false
    t.string   "state",                      :default => "unconfigured"
    t.text     "prefs"
    t.integer  "port"
    t.datetime "started_at"
    t.string   "config_type"
    t.integer  "started_by_user_id"
    t.boolean  "notification_enabled"
    t.string   "notification_email_address"
    t.text     "notification_email_message"
    t.string   "notification_email_subject"
    t.datetime "last_target_interaction_at"
  end

  create_table "se_email_openings", :force => true do |t|
    t.integer  "email_id"
    t.integer  "human_target_id"
    t.datetime "created_at",                     :null => false
    t.datetime "updated_at",                     :null => false
    t.string   "address",         :limit => nil
  end

  create_table "se_email_sends", :force => true do |t|
    t.integer  "email_id"
    t.integer  "human_target_id"
    t.datetime "created_at",      :null => false
    t.datetime "updated_at",      :null => false
    t.boolean  "sent"
    t.string   "status_message"
  end

  create_table "se_email_templates", :force => true do |t|
    t.integer  "user_id"
    t.text     "content"
    t.string   "name"
    t.integer  "workspace_id"
    t.datetime "created_at",   :null => false
    t.datetime "updated_at",   :null => false
  end

  create_table "se_emails", :force => true do |t|
    t.integer  "user_id"
    t.text     "content"
    t.string   "name"
    t.string   "subject"
    t.integer  "campaign_id"
    t.integer  "template_id"
    t.datetime "created_at",        :null => false
    t.datetime "updated_at",        :null => false
    t.string   "from_address"
    t.string   "from_name"
    t.integer  "target_list_id"
    t.integer  "email_template_id"
    t.text     "prefs"
    t.string   "attack_type"
    t.string   "status"
    t.datetime "sent_at"
    t.string   "origin_type"
    t.string   "editor_type"
  end

  create_table "se_human_targets", :force => true do |t|
    t.string   "first_name"
    t.string   "last_name"
    t.string   "email_address"
    t.integer  "workspace_id"
    t.integer  "user_id"
    t.datetime "created_at",    :null => false
    t.datetime "updated_at",    :null => false
  end

  create_table "se_phishing_results", :force => true do |t|
    t.integer  "human_target_id"
    t.integer  "web_page_id"
    t.text     "data"
    t.datetime "created_at",                     :null => false
    t.datetime "updated_at",                     :null => false
    t.string   "address",         :limit => nil
    t.text     "raw_data"
    t.string   "browser_name"
    t.string   "browser_version"
    t.string   "os_name"
    t.string   "os_version"
  end

  create_table "se_portable_files", :force => true do |t|
    t.integer  "campaign_id"
    t.string   "name"
    t.datetime "created_at",                             :null => false
    t.datetime "updated_at",                             :null => false
    t.text     "prefs"
    t.string   "file_name"
    t.string   "exploit_module_path"
    t.boolean  "dynamic_stagers",     :default => false
  end

  create_table "se_target_list_human_targets", :force => true do |t|
    t.integer  "target_list_id"
    t.integer  "human_target_id"
    t.datetime "created_at",      :null => false
    t.datetime "updated_at",      :null => false
  end

  create_table "se_target_lists", :force => true do |t|
    t.string   "name"
    t.string   "file_name"
    t.integer  "user_id"
    t.integer  "workspace_id"
    t.datetime "created_at",   :null => false
    t.datetime "updated_at",   :null => false
  end

  create_table "se_tracking_links", :force => true do |t|
    t.string   "external_destination_url"
    t.integer  "email_id"
    t.integer  "web_page_id"
    t.datetime "created_at",               :null => false
    t.datetime "updated_at",               :null => false
  end

  create_table "se_visits", :force => true do |t|
    t.integer  "human_target_id"
    t.integer  "web_page_id"
    t.datetime "created_at",                     :null => false
    t.datetime "updated_at",                     :null => false
    t.integer  "email_id"
    t.string   "address",         :limit => nil
  end

  create_table "se_web_pages", :force => true do |t|
    t.integer  "campaign_id"
    t.string   "path"
    t.text     "content"
    t.string   "clone_url"
    t.boolean  "online"
    t.datetime "created_at",               :null => false
    t.datetime "updated_at",               :null => false
    t.string   "name"
    t.text     "prefs"
    t.integer  "template_id"
    t.string   "attack_type"
    t.string   "origin_type"
    t.string   "phishing_redirect_origin"
  end

  create_table "se_web_templates", :force => true do |t|
    t.string   "name"
    t.integer  "workspace_id"
    t.integer  "user_id"
    t.datetime "created_at",   :null => false
    t.datetime "updated_at",   :null => false
    t.text     "content"
    t.string   "clone_url"
    t.string   "origin_type"
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
    t.integer  "campaign_id"
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

  create_table "task_chains", :force => true do |t|
    t.text     "schedule"
    t.string   "name"
    t.datetime "last_run_at"
    t.datetime "next_run_at"
    t.integer  "user_id"
    t.integer  "workspace_id"
    t.datetime "created_at",                                      :null => false
    t.datetime "updated_at",                                      :null => false
    t.string   "state",                      :default => "ready"
    t.boolean  "clear_workspace_before_run"
    t.boolean  "legacy",                     :default => true
    t.integer  "active_task_id"
    t.text     "schedule_hash"
    t.integer  "active_scheduled_task_id"
    t.integer  "active_report_id"
    t.integer  "last_run_task_id"
    t.integer  "last_run_report_id"
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
    t.integer  "workspace_id",                 :default => 1,           :null => false
    t.string   "created_by"
    t.string   "module"
    t.datetime "completed_at"
    t.string   "path",         :limit => 1024
    t.string   "info"
    t.string   "description"
    t.integer  "progress"
    t.text     "options"
    t.text     "error"
    t.datetime "created_at",                                            :null => false
    t.datetime "updated_at",                                            :null => false
    t.text     "result"
    t.string   "module_uuid",  :limit => 8
    t.binary   "settings"
    t.integer  "app_run_id"
    t.string   "presenter"
    t.string   "state",                        :default => "unstarted"
  end

  create_table "users", :force => true do |t|
    t.string   "username"
    t.string   "crypted_password"
    t.string   "password_salt"
    t.string   "persistence_token"
    t.datetime "created_at",                                                    :null => false
    t.datetime "updated_at",                                                    :null => false
    t.string   "fullname"
    t.string   "email"
    t.string   "phone"
    t.string   "company"
    t.string   "prefs",                     :limit => 524288
    t.boolean  "admin",                                       :default => true, :null => false
    t.integer  "notification_center_count",                   :default => 0
    t.datetime "last_request_at"
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
    t.string   "info",                     :limit => 65536
    t.datetime "exploited_at"
    t.integer  "vuln_detail_count",                         :default => 0
    t.integer  "vuln_attempt_count",                        :default => 0
    t.integer  "nexpose_data_vuln_def_id"
  end

  add_index "vulns", ["name"], :name => "index_vulns_on_name"
  add_index "vulns", ["nexpose_data_vuln_def_id"], :name => "index_vulns_on_nexpose_data_vuln_def_id"

  create_table "vulns_refs", :force => true do |t|
    t.integer "ref_id"
    t.integer "vuln_id"
  end

  create_table "web_attack_cross_site_scriptings", :force => true do |t|
    t.string   "encloser_type", :null => false
    t.string   "escaper_type",  :null => false
    t.string   "evader_type",   :null => false
    t.string   "executor_type", :null => false
    t.datetime "created_at",    :null => false
    t.datetime "updated_at",    :null => false
  end

  create_table "web_cookies", :force => true do |t|
    t.string   "name",                                :null => false
    t.string   "value",                               :null => false
    t.integer  "request_group_id",                    :null => false
    t.string   "domain",                              :null => false
    t.string   "path"
    t.boolean  "secure",           :default => false, :null => false
    t.boolean  "http_only",        :default => false, :null => false
    t.integer  "version"
    t.string   "commnet"
    t.string   "comment_url"
    t.boolean  "discard",          :default => false, :null => false
    t.text     "ports"
    t.integer  "max_age"
    t.datetime "expires_at"
    t.datetime "created_at"
    t.datetime "updated_at"
  end

  add_index "web_cookies", ["request_group_id", "name"], :name => "index_web_cookies_on_request_group_id_and_name"

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

  create_table "web_headers", :force => true do |t|
    t.boolean "attack_vector",    :null => false
    t.string  "name",             :null => false
    t.string  "value",            :null => false
    t.integer "position",         :null => false
    t.integer "request_group_id", :null => false
  end

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

  create_table "web_parameters", :force => true do |t|
    t.boolean "attack_vector", :null => false
    t.string  "name",          :null => false
    t.string  "value",         :null => false
    t.integer "request_id",    :null => false
    t.integer "position",      :null => false
  end

  create_table "web_proofs", :force => true do |t|
    t.string  "image"
    t.text    "text"
    t.integer "vuln_id", :null => false
  end

  create_table "web_request_groups", :force => true do |t|
    t.datetime "created_at",   :null => false
    t.datetime "updated_at",   :null => false
    t.integer  "user_id",      :null => false
    t.integer  "workspace_id", :null => false
  end

  create_table "web_requests", :force => true do |t|
    t.string  "method",                                    :null => false
    t.integer "virtual_host_id",                           :null => false
    t.string  "path",                                      :null => false
    t.boolean "attack",                  :default => true
    t.boolean "requested"
    t.boolean "attack_vector"
    t.integer "request_group_id"
    t.integer "cross_site_scripting_id"
  end

  add_index "web_requests", ["cross_site_scripting_id"], :name => "index_web_requests_on_cross_site_scripting_id"
  add_index "web_requests", ["request_group_id"], :name => "index_web_requests_on_request_group_id"

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

  create_table "web_transmitted_cookies", :force => true do |t|
    t.boolean  "transmitted"
    t.integer  "request_id"
    t.integer  "cookie_id"
    t.datetime "created_at",  :null => false
    t.datetime "updated_at",  :null => false
  end

  create_table "web_transmitted_headers", :force => true do |t|
    t.boolean  "transmitted"
    t.integer  "request_id"
    t.integer  "header_id"
    t.datetime "created_at",  :null => false
    t.datetime "updated_at",  :null => false
  end

  create_table "web_virtual_hosts", :force => true do |t|
    t.string  "name",       :null => false
    t.integer "service_id", :null => false
  end

  add_index "web_virtual_hosts", ["service_id", "name"], :name => "index_web_virtual_hosts_on_service_id_and_name", :unique => true

  create_table "web_vuln_category_metasploits", :force => true do |t|
    t.string "name",    :null => false
    t.string "summary", :null => false
  end

  add_index "web_vuln_category_metasploits", ["name"], :name => "index_web_vuln_category_metasploits_on_name", :unique => true

  create_table "web_vuln_category_owasps", :force => true do |t|
    t.string  "detectability",  :null => false
    t.string  "exploitability", :null => false
    t.string  "impact",         :null => false
    t.string  "name",           :null => false
    t.string  "prevalence",     :null => false
    t.integer "rank",           :null => false
    t.string  "summary",        :null => false
    t.string  "target",         :null => false
    t.string  "version",        :null => false
  end

  add_index "web_vuln_category_owasps", ["target", "version", "rank"], :name => "index_web_vuln_category_owasps_on_target_and_version_and_rank", :unique => true

  create_table "web_vuln_category_projection_metasploit_owasps", :force => true do |t|
    t.integer "metasploit_id", :null => false
    t.integer "owasp_id",      :null => false
  end

  add_index "web_vuln_category_projection_metasploit_owasps", ["metasploit_id", "owasp_id"], :name => "index_web_vuln_category_project_metasploit_id_and_owasp_id", :unique => true

  create_table "web_vulns", :force => true do |t|
    t.integer  "web_site_id"
    t.datetime "created_at",                      :null => false
    t.datetime "updated_at",                      :null => false
    t.text     "path",                            :null => false
    t.string   "method",          :limit => 1024, :null => false
    t.text     "params",                          :null => false
    t.text     "pname"
    t.integer  "risk",                            :null => false
    t.string   "name",            :limit => 1024, :null => false
    t.text     "query"
    t.text     "legacy_category"
    t.integer  "confidence",                      :null => false
    t.text     "description"
    t.text     "blame"
    t.binary   "request"
    t.string   "owner"
    t.text     "payload"
    t.integer  "request_id"
    t.integer  "category_id"
  end

  add_index "web_vulns", ["method"], :name => "index_web_vulns_on_method"
  add_index "web_vulns", ["name"], :name => "index_web_vulns_on_name"
  add_index "web_vulns", ["path"], :name => "index_web_vulns_on_path"

  create_table "wizard_procedures", :force => true do |t|
    t.text    "config_hash"
    t.string  "state"
    t.integer "task_chain_id"
    t.string  "type"
    t.integer "workspace_id"
    t.integer "user_id"
  end

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
